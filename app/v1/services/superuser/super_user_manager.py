import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status
from pymongo import ASCENDING, DESCENDING

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    booking_collection,
    category_collection,
    plan_collection,
    services_collection,
    subscription_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.permission import *
from app.v1.models.slots import *
from app.v1.schemas.superuser.superuser_auth import *
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


def serialize_mongo_document(document):
    """Helper function to serialize MongoDB documents."""
    if "_id" in document:
        document["_id"] = str(document["_id"])
    return document


VALID_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def validate_time_format(time_str: str):
    try:
        datetime.strptime(time_str, "%H:%M")
    except ValueError:
        return False
    return True


class SuperUserManager:

    async def super_user_sign_in(self, email: str, password: str = None, is_login_with_otp: bool = False) -> dict:
        """Sign in a user by email and password."""
        try:
            result = await user_collection.find_one({"email": email})
            if not result:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            # Check if the entered password matches the stored hashed password
            if is_login_with_otp:
                otp = generate_otp()
                otp_expires = datetime.utcnow() + timedelta(minutes=5)
                await user_collection.update_one({"email": email}, {"$set": {"otp": otp, "otp_expires": otp_expires}})
                source = "Login With Otp"
                context = {"otp": otp}
                to_email = email
                await send_email(to_email, source, context)
                # return success({"message": "OTP sent successfully", "data": None})
                return {"message": "OTP sent successfully"}
            stored_password_hash = result.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                )
            if not bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if "admin" not in user.roles and user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized as an admin")
            user_data = user.dict()
            user_data.pop("password", None)
            user_data.pop("otp", None)
            user_data.pop("otp_expires", None)
            user_data["id"] = str(user.id)
            # Generate access and refresh tokens
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            # token = generate_jwt_token(user_id)

            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_forget_password(self, email: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
            # Generate OTP
            otp = generate_otp()
            user.otp = otp
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            user.otp_expires = otp_expiration_time
            await user.save()
            source = "Forgot Password"
            context = {"otp": otp}
            to_email = email
            await send_email(to_email, source, context)
            return {"message": "OTP sent to email"}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_otp_verify(self, email: str, otp: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
            if user.otp != otp:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
            if datetime.utcnow() > user.otp_expires:
                raise HTTPException(status_code=400, detail="OTP has expired.")
            user.is_active = True
            await user.save()
            user_data = user.dict()
            user_data.pop("password", None)
            user_data.pop("otp", None)
            # Generate access and refresh tokens
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            print(ex)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_reset_password(self, email: str, password: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            user.password = hashed_password
            await user.save()
            return {"message": "Password reset successfully"}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_resend_otp(self, email: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
            otp = generate_otp()
            user.otp = otp
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            user.otp_expires = otp_expiration_time
            await user.save()
            await send_email(email, otp)
            return {"message": "OTP resent successfully"}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_super_user_profile(self, email: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
            user_data = user.dict()
            user_data.pop("password", None)
            user_data.pop("otp", None)
            return {"user_data": user_data}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_super_user_profile(self, email: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not superuser")
            user_data = user.dict()
            return {"user_data": user_data}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def change_super_user_password(self, email: str, old_password: str, new_password: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            if user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not superuser")
            if old_password is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Old Password required")
            if not bcrypt.checkpw(old_password.encode("utf-8"), user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Old password does not match",
                )

            # Ensure the new password is different
            if bcrypt.checkpw(new_password.encode("utf-8"), user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password cannot be the same as the old password",
                )

            # Hash the new password and save it
            hashed_new_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
            user.password = hashed_new_password.decode("utf-8")  # Store as a string
            await user.save()
            return {"email": user.email}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def create_super_user(
        self, request: Request, token: str, super_user_create_request: SuperUserCreateRequest
    ) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Check if the user already exists
            user = await User.find_one(User.email == super_user_create_request.email)
            if user is not None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
            # Hash the password
            hashed_password = bcrypt.hashpw(super_user_create_request.password.encode("utf-8"), bcrypt.gensalt())
            # Create the user object
            user = User(
                first_name=super_user_create_request.first_name,
                last_name=super_user_create_request.last_name,
                email=super_user_create_request.email,
                roles=super_user_create_request.roles,
                phone=super_user_create_request.phone,
                status=super_user_create_request.status,
                password=hashed_password,
                menu=DEFAULT_MENU_STRUCTURE,
            )
            await user.save()

            # Prepare the response
            user_data = {
                "id": str(user.id),  # Convert ObjectId to string
                "first_name": user.first_name.capitalize(),
                "last_name": user.last_name.capitalize(),
                "email": user.email.lower(),
                "roles": user.roles,
                "phone": user.phone,
                "status": user.status,
                "menu": user.menu,
            }

            return user_data

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_list(
        self, request: Request, token: str, page: int, limit: int, search: str = None, role: str = "admin"
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            skip = max((page - 1) * limit, 0)
            query = {"roles": {"$regex": "^admin$", "$options": "i"}}

            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"first_name": search_regex},
                    {"last_name": search_regex},
                    {"email": search_regex},
                    {"phone": search_regex},
                ]

            # Fields to include in the result
            projection = {"_id": 1, "first_name": 1, "last_name": 1, "email": 1, "phone": 1, "status": 1}

            # Fetch paginated results
            result = await user_collection.find(query, projection).skip(skip).limit(limit).to_list(length=limit)

            # Format costumer data
            admin_data = []
            for admin in result:
                admin["id"] = str(admin.pop("_id"))  # Convert ObjectId to string
                admin["first_name"] = admin["first_name"].capitalize()
                admin["last_name"] = admin["last_name"].capitalize()
                admin["email"] = admin["email"].lower()
                admin["status"] = admin.get("status", "unknown")
                admin_data.append(admin)

            # Fetch total count for the query
            total_admin = await user_collection.count_documents(query)

            # Calculate total pages
            total_pages = (total_admin + limit - 1) // limit

            return {"data": admin_data, "total_items": total_admin, "total_pages": total_pages}
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_super_user(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            query = {"_id": ObjectId(id), "roles": {"$in": ["admin"]}}
            admin = await user_collection.find_one(query)
            if admin is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
            admin["id"] = str(admin.pop("_id"))  # Convert ObjectId to string
            admin["first_name"] = admin["first_name"].capitalize()
            admin["last_name"] = admin["last_name"].capitalize()
            admin["email"] = admin["email"].lower()
            admin["status"] = admin.get("status", "unknown")
            return admin
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_super_user(
        self, request: Request, token: str, id: str, update_super_user_request: SuperUserUpdateRequest
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Validate costumer ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid admin ID: '{id}'")

            # Check if the costumer exists
            costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="adnin not found")

            # Prepare update data
            update_data = {}
            if update_super_user_request.first_name is not None:
                update_data["first_name"] = update_super_user_request.first_name
            if update_super_user_request.last_name is not None:
                update_data["last_name"] = update_super_user_request.last_name
            if update_super_user_request.email is not None:
                update_data["email"] = update_super_user_request.email
            if update_super_user_request.phone is not None:
                update_data["phone"] = update_super_user_request.phone
            if update_super_user_request.status is not None:
                update_data["status"] = update_super_user_request.status
            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            await user_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            # Fetch updated costumer data
            updated_costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not updated_costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="admin not found")

            # Convert _id to string and format other fields
            updated_costumer["id"] = str(updated_costumer.pop("_id"))
            updated_costumer["first_name"] = updated_costumer["first_name"].capitalize()
            updated_costumer["last_name"] = updated_costumer["last_name"].capitalize()
            updated_costumer["email"] = updated_costumer["email"].lower()
            updated_costumer["phone"] = updated_costumer["phone"]
            updated_costumer["status"] = updated_costumer["status"]

            return updated_costumer
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def delete_super_user(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_dashboard_data(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            total_users = await user_collection.count_documents({"roles": {"$in": ["user"]}, "user_role": {"$ne": 2}})
            total_bookings = await booking_collection.count_documents({"booking_confirm": True})

            # Bookings that are canceled
            canceled_bookings = await booking_collection.count_documents({"booking_status": "cancelled"})

            # Bookings that are resulting
            reschedule_bookings = await booking_collection.count_documents({"booking_status": "rescheduled"})

            return {
                "total_users": total_users,
                "total_bookings": total_bookings,
                "canceled_bookings": canceled_bookings,
                "reschedule_bookings": reschedule_bookings,
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_dashboard_booking_data(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Fetch latest 10 bookings sorted by 'created_at' (or another timestamp field)
            bookings_cursor = (
                booking_collection.find({"booking_status": "panding", "booking_confirm": True})
                .sort("created_at", DESCENDING)
                .limit(10)
            )

            bookings = await bookings_cursor.to_list(length=10)  # Convert cursor to list

            if not bookings:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No bookings found")

            booking_data = []
            for booking in bookings:
                # Fetch related data
                user = await user_collection.find_one({"_id": ObjectId(booking["user_id"])}, {"first_name": 1})
                vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
                vendor_user_name = await user_collection.find_one(
                    {"_id": ObjectId(vendor["user_id"])}, {"first_name": 1}
                )
                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])}, {"name": 1})
                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])}, {"name": 1})

                booking_data.append(
                    {
                        "booking_id": str(booking["_id"]),
                        "user_name": user["first_name"] if user else None,
                        "vendor_name": vendor_user_name["first_name"] if vendor_user_name else None,
                        "category_name": category["name"] if category else None,
                        "service_name": service["name"] if service else None,
                        "booking_status": booking["booking_status"],
                        "booking_confirm": booking["booking_confirm"],
                        "booking_date": booking["booking_date"],
                        "time_slot": booking["time_slot"],
                        "payment_status": booking["payment_status"],
                        "payment_method": booking["payment_method"],
                        "amount": booking["amount"],
                        "booking_cancel_reason": (
                            booking["booking_cancel_reason"] if "booking_cancel_reason" in booking else None
                        ),
                        "booking_order_id": booking["booking_order_id"],
                        "payment_id": booking["payment_id"],
                        "created_at": booking.get("created_at"),  # Include timestamp if needed
                    }
                )

            return {
                "total_bookings": len(booking_data),
                "bookings": booking_data,
            }

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_total_subscribers(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Aggregate count of vendors for each plan
            pipeline = [
                {
                    "$group": {
                        "_id": "$razorpay_plan_id",
                        "vendor_count": {"$sum": 1},
                        "vendor_ids": {"$push": "$vendor_id"},
                    }
                },
                {"$sort": {"vendor_count": ASCENDING}},
            ]

            plan_counts = await subscription_collection.aggregate(pipeline).to_list(None)

            # Fetch plan details and vendor details
            result = []
            for plan in plan_counts:
                plan_details = await plan_collection.find_one(
                    {"razorpay_plan_id": plan["_id"]}, {"name": 1, "description": 1}
                )

                vendors = await vendor_collection.find(
                    {"_id": {"$in": [ObjectId(v_id) for v_id in plan["vendor_ids"]]}},
                    {"business_name": 1, "category_name": 1, "services": 1},
                ).to_list(None)

                vendor_data = [
                    {
                        "vendor_id": str(v["_id"]),
                        "business_name": v["business_name"],
                        "category_name": v.get("category_name", "Unknown"),
                        "services": [s["name"] for s in v.get("services", [])],
                    }
                    for v in vendors
                ]

                result.append(
                    {
                        "plan_id": plan["_id"],
                        "plan_name": plan_details["name"] if plan_details else "Unknown",
                        "description": plan_details["description"] if plan_details else "No description",
                        "vendor_count": plan["vendor_count"],
                        "vendors": vendor_data,
                    }
                )

            return {
                "total_plans": len(result),
                "plans": result,
            }

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
