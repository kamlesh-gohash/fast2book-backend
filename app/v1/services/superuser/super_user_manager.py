import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import pytz

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
    email_monitor_collection,
    plan_collection,
    services_collection,
    subscription_collection,
    ticket_collection,
    user_collection,
    vendor_collection,
    vendor_query_collection,
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

    # async def super_user_sign_in(self, email: str, password: str = None, is_login_with_otp: bool = False) -> dict:
    #     """Sign in a user by email and password."""
    #     try:
    #         result = await user_collection.find_one({"email": email})
    #         if not result:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    #         # Check if the entered password matches the stored hashed password
    #         if is_login_with_otp:
    #             otp = generate_otp()
    #             otp_expires = datetime.utcnow() + timedelta(minutes=5)
    #             await user_collection.update_one({"email": email}, {"$set": {"login_otp": otp, "login_otp_expires": datetime.utcnow() + timedelta(minutes=10)}})
    #             source = "Login With Otp"
    #             context = {"otp": otp}
    #             to_email = email
    #             await send_email(to_email, source, context)
    #             # return success({"message": "OTP sent successfully", "data": None})
    #             return {"message": "OTP sent successfully"}
    #         stored_password_hash = result.get("password")
    #         if not stored_password_hash:
    #             raise HTTPException(
    #                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
    #             )
    #         if not bcrypt.checkpw(
    #             password.encode("utf-8"),
    #             stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
    #         ):
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
    #         user = await User.find_one(User.email == email)
    #         if user is None:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
    #         if "admin" not in user.roles and user.user_role != 2:
    #             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized as an admin")
    #         user_data = user.dict()
    #         user_data.pop("password", None)
    #         user_data.pop("otp", None)
    #         user_data.pop("otp_expires", None)
    #         user_data["id"] = str(user.id)
    #         # Generate access and refresh tokens
    #         access_token = create_access_token(data={"sub": user.email})
    #         refresh_token = create_refresh_token(data={"sub": user.email})
    #         # token = generate_jwt_token(user_id)

    #         return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
    #         )

    async def super_user_sign_in(self, email: str, password: str = None, is_login_with_otp: bool = False) -> dict:
        """Sign in a super user by email and password or OTP."""
        try:
            # Find user using user_collection
            user = await user_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Check if user is an admin or has user_role == 2
            roles = user.get("roles", [])
            user_role = user.get("user_role", 0)
            if "admin" not in roles and user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized as an admin")

            if is_login_with_otp:
                otp = generate_otp()
                otp_expires = datetime.utcnow() + timedelta(minutes=10)
                await user_collection.update_one(
                    {"email": email}, {"$set": {"login_otp": otp, "login_otp_expires": otp_expires}}
                )
                source = "Login With Otp"
                context = {"otp": otp}
                to_email = email
                await send_email(to_email, source, context)
                return {"message": "OTP sent successfully"}

            # Password-based login
            stored_password_hash = user.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found"
                )
            if not bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")

            # Prepare user data
            user_data = user.copy()
            user_data["id"] = str(user_data.pop("_id"))
            user_data.pop("password", None)
            user_data.pop("login_otp", None)
            user_data.pop("login_otp_expires", None)
            user_data.pop("forgot_password_otp", None)
            user_data.pop("forgot_password_otp_expires", None)
            user_data.pop("resend_otp", None)
            user_data.pop("resend_otp_expires", None)

            access_token = create_access_token(data={"sub": user.get("email")})
            refresh_token = create_refresh_token(data={"sub": user.get("email")})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    # async def super_user_forget_password(self, email: str) -> dict:
    #     try:
    #         user = await User.find_one(User.email == email)
    #         if user is None:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
    #         if "admin" not in user.roles and user.user_role != 2:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
    #         # Generate OTP
    #         otp = generate_otp()
    #         user.otp = otp
    #         otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
    #         user.otp_expires = otp_expiration_time
    #         await user.save()
    #         source = "Forgot Password"
    #         context = {"otp": otp}
    #         to_email = email
    #         await send_email(to_email, source, context)
    #         return {"message": "OTP sent to email"}
    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
    #         )

    async def super_user_forget_password(self, email: str) -> dict:
        try:
            # Find user using user_collection
            user = await user_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Check if user is an admin or has user_role == 2
            roles = user.get("roles", [])
            user_role = user.get("user_role", 0)
            if "admin" not in roles and user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")

            # Generate and store OTP
            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            await user_collection.update_one(
                {"email": email},
                {"$set": {"forgot_password_otp": otp, "forgot_password_otp_expires": otp_expiration_time}},
            )

            # Send OTP via email
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

    # async def super_user_otp_verify(self, email: str, otp: str) -> dict:
    #     try:
    #         user = await User.find_one(User.email == email)
    #         if user is None:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
    #         if "admin" not in user.roles and user.user_role != 2:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
    #         if user.otp != otp:
    #             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
    #         if datetime.utcnow() > user.otp_expires:
    #             raise HTTPException(status_code=400, detail="OTP has expired.")
    #         user.is_active = True
    #         user.otp = None
    #         user.otp_expires = None
    #         await user.save()
    #         user_data = user.dict()
    #         user_data.pop("password", None)
    #         user_data.pop("otp", None)
    #         # Generate access and refresh tokens
    #         access_token = create_access_token(data={"sub": user.email})
    #         refresh_token = create_refresh_token(data={"sub": user.email})
    #         return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
    #         )

    async def super_user_otp_verify(self, email: str, otp: str, otp_type: Optional[str] = None) -> dict:
        try:
            # Validate otp_type
            if not otp_type:
                raise HTTPException(status_code=400, detail="OTP type must be provided")
            if otp_type not in ["login", "forgot_password", "resend_otp"]:
                raise HTTPException(
                    status_code=400, detail="Invalid OTP type. Must be 'login', 'forgot_password', or 'resend_otp'"
                )

            # Find user using user_collection
            user = await user_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Check if user is an admin or has user_role == 2
            roles = user.get("roles", [])
            user_role = user.get("user_role", 0)
            if "admin" not in roles and user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")

            # Determine the OTP field and expiration field based on otp_type
            otp_field = f"{otp_type}_otp"
            otp_expires_field = f"{otp_type}_otp_expires"

            # Check the OTP
            stored_otp = user.get(otp_field)
            expires_at = user.get(otp_expires_field)
            if stored_otp != otp:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid OTP for {otp_type}")
            if expires_at and datetime.utcnow() > expires_at:
                raise HTTPException(status_code=400, detail=f"OTP for {otp_type} has expired")

            # Clear the OTP fields after successful validation (effectively expires the OTP)
            update_data = {"$unset": {otp_field: 1, otp_expires_field: 1}}
            # Update is_active if applicable
            if otp_type in ["login", "resend_otp"]:
                update_data["$set"] = {"is_active": True}
            await user_collection.update_one({"email": email}, update_data)

            # Prepare user data
            user_data = user.copy()
            user_data["id"] = str(user_data.pop("_id"))
            user_data.pop("password", None)
            user_data.pop("login_otp", None)
            user_data.pop("login_otp_expires", None)
            user_data.pop("forgot_password_otp", None)
            user_data.pop("forgot_password_otp_expires", None)
            user_data.pop("resend_otp", None)
            user_data.pop("resend_otp_expires", None)

            access_token = create_access_token(data={"sub": user.get("email")})
            refresh_token = create_refresh_token(data={"sub": user.get("email")})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def super_user_reset_password(self, email: str, password: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if "admin" not in user.roles and user.user_role != 2:
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

    # async def super_user_resend_otp(self, email: str) -> dict:
    #     try:
    #         user = await User.find_one(User.email == email)
    #         if user is None:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
    #         if "admin" not in user.roles and user.user_role != 2:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")
    #         otp = generate_otp()
    #         user.otp = otp
    #         otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
    #         user.otp_expires = otp_expiration_time
    #         await user.save()
    #         source = "Resend OTP"
    #         to_email = email
    #         context = {"otp": otp}
    #         await send_email(to_email, source, context)
    #         return {"message": "OTP resent successfully"}
    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
    #         )

    async def super_user_resend_otp(self, email: str, otp_type: str) -> dict:
        try:
            # Find user using user_collection
            user = await user_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Check if user is an admin or has user_role == 2
            roles = user.get("roles", [])
            user_role = user.get("user_role", 0)
            if "admin" not in roles and user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not a super user")

            # Generate and store OTP
            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            otp_field = f"{otp_type}_otp"
            otp_expires_field = f"{otp_type}_otp_expires"

            # Store OTP in the appropriate field
            await user_collection.update_one(
                {"email": email}, {"$set": {otp_field: otp, otp_expires_field: otp_expiration_time}}
            )

            # Send OTP via email
            source = "Resend OTP"
            to_email = email
            context = {"otp": otp}
            await send_email(to_email, source, context)
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
            if "admin" not in user.roles and user.user_role != 2:
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
            if "admin" not in user.roles and user.user_role != 2:
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
            if "admin" not in user.roles and user.user_role != 2:
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

    async def create_super_user(self, current_user: User, super_user_create_request: SuperUserCreateRequest) -> dict:
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # if current_user.user_role != 2:
            #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")

            email = super_user_create_request.email.lower()
            super_user_create_request.email = email
            # Check if the user already exists
            user = await User.find_one(User.email == super_user_create_request.email)
            if user is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this email"
                )
            user = await User.find_one(User.phone == super_user_create_request.phone)
            if user is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this phone"
                )
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
        self,
        request: Request,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
        role: str = "admin",
    ):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
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

            if statuss:
                statuss = statuss.strip()
                if not statuss:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status cannot be empty")
                query["status"] = statuss
            # Fields to include in the result
            projection = {"_id": 1, "first_name": 1, "last_name": 1, "email": 1, "phone": 1, "status": 1}

            # Fetch paginated results
            result = await user_collection.find(query, projection).skip(skip).limit(limit).to_list(length=limit)

            # Format costumer data
            admin_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")

            for admin in result:
                # created_at = admin.get("created_at")
                # if isinstance(created_at, datetime):
                #     created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                #     created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                #     admin["created_at"] = created_at_ist.isoformat()
                admin["id"] = str(admin.pop("_id"))  # Convert ObjectId to string
                admin["first_name"] = admin["first_name"].capitalize()
                admin["last_name"] = admin["last_name"].capitalize()
                admin["email"] = admin["email"]
                admin["status"] = admin.get("status", "unknown")
                # admin["created_at"] = admin["created_at"]
                admin_data.append(admin)

            # Fetch total count for the query
            total_admin = await user_collection.count_documents(query)

            # Calculate total pages
            total_pages = (total_admin + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": admin_data,
                "paginator": {
                    "itemCount": total_admin,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_super_user(self, current_user: User, id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            query = {"_id": ObjectId(id), "roles": {"$in": ["admin"]}}
            admin = await user_collection.find_one(query)
            if admin is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            admin["id"] = str(admin.pop("_id"))  # Convert ObjectId to string
            admin["first_name"] = admin["first_name"].capitalize()
            admin["last_name"] = admin["last_name"].capitalize()
            admin["email"] = admin["email"]
            admin["status"] = admin.get("status", "unknown")
            return admin
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_super_user(self, current_user: User, id: str, update_super_user_request: SuperUserUpdateRequest):
        try:
            if "admin" not in current_user.roles and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not superuser")
            # Validate costumer ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid admin ID: '{id}'")

            # Check if the costumer
            costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Adnin not found")
            # Prepare update data
            update_data = {}
            if update_super_user_request.first_name is not None:
                update_data["first_name"] = update_super_user_request.first_name
            if update_super_user_request.last_name is not None:
                update_data["last_name"] = update_super_user_request.last_name
            if update_super_user_request.email is not None:
                # Check if the new email already exists (only if the email is being updated)
                email = update_super_user_request.email.lower()
                user_with_email = await User.find_one(User.email == email)
                if user_with_email and str(user_with_email.id) != id:  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this email"
                    )
                update_data["email"] = email
            if update_super_user_request.phone is not None:
                # Check if the new phone already exists (only if the phone is being updated)
                user_with_phone = await User.find_one(User.phone == update_super_user_request.phone)
                if user_with_phone and str(user_with_phone.id) != id:  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this phone"
                    )
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
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

            # Convert _id to string and format other fields
            updated_costumer["id"] = str(updated_costumer.pop("_id"))
            updated_costumer["first_name"] = updated_costumer["first_name"].capitalize()
            updated_costumer["last_name"] = updated_costumer["last_name"].capitalize()
            updated_costumer["email"] = updated_costumer["email"]
            updated_costumer["phone"] = updated_costumer["phone"]
            updated_costumer["status"] = updated_costumer["status"]

            return updated_costumer
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def delete_super_user(self, current_user: User, id: str):
        try:
            if current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_dashboard_data(self, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            total_users = await user_collection.count_documents({"roles": {"$in": ["user"]}, "user_role": {"$ne": 2}})
            total_bookings = await booking_collection.count_documents({"payment_status": "paid"})

            canceled_bookings = await booking_collection.count_documents({"booking_status": "cancelled"})

            reschedule_bookings = await booking_collection.count_documents({"booking_status": "rescheduled"})

            return {
                "total_users": total_users,
                "total_bookings": total_bookings,
                "canceled_bookings": canceled_bookings,
                "reschedule_bookings": reschedule_bookings,
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_dashboard_booking_data(self, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Fetch latest 10 bookings sorted by 'created_at'
            bookings_cursor = (
                booking_collection.find({"booking_status": "panding", "payment_status": "paid"})
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
                vendor_user_name = None
                if vendor:  # Check if vendor exists
                    vendor_user_name = await user_collection.find_one(
                        {"vendor_id": ObjectId(vendor["_id"])}, {"first_name": 1}
                    )
                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])}, {"name": 1})
                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])}, {"name": 1})

                booking_data.append(
                    {
                        "booking_id": str(booking["_id"]),
                        "user_name": user.get("first_name") if user else None,  # Safely access 'first_name'
                        "vendor_name": (
                            vendor_user_name.get("first_name") if vendor_user_name else None
                        ),  # Safely access 'first_name'
                        "category_name": category.get("name") if category else None,  # Safely access 'name'
                        "service_name": service.get("name") if service else None,  # Safely access 'name'
                        "booking_status": booking["booking_status"],
                        "booking_confirm": booking.get("booking_confirm"),  # Safely access optional field
                        "booking_date": booking["booking_date"],
                        "time_slot": booking["time_slot"],
                        "payment_status": booking["payment_status"],
                        "payment_method": booking.get("payment_method"),  # Safely access optional field
                        "amount": booking["amount"],
                        "booking_cancel_reason": booking.get("booking_cancel_reason"),  # Safely access optional field
                        "booking_order_id": booking.get("booking_order_id"),  # Safely access optional field
                        "payment_id": booking.get("payment_id"),  # Safely access optional field
                        "created_at": booking.get("created_at"),  # Safely access optional field
                    }
                )

            return {
                "total_bookings": len(booking_data),
                "bookings": booking_data,
            }
        except HTTPException as e:
            raise e

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_total_subscribers(self, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Aggregate count of vendors for each plan
            pipeline = [
                {"$match": {"is_subscription": True}},  # Only consider vendors with active subscriptions
                {
                    "$group": {
                        "_id": "$manage_plan",  # Group by the plan ID
                        "vendor_count": {"$sum": 1},  # Count the number of vendors in each group
                    }
                },
                {
                    "$lookup": {
                        "from": "plans",
                        "localField": "_id",
                        "foreignField": "razorpay_plan_id",
                        "as": "plan_details",
                    }
                },
                {"$unwind": "$plan_details"},  # Unwind the plan details array
                {
                    "$project": {
                        "plan_id": "$_id",
                        "plan_name": "$plan_details.name",
                        "description": "$plan_details.description",
                        "vendor_count": 1,
                    }
                },
            ]

            plan_counts = await vendor_collection.aggregate(pipeline).to_list(None)

            # Fetch vendor details for each plan
            result = []
            for plan in plan_counts:
                vendors = await vendor_collection.find(
                    {"manage_plan": plan["plan_id"], "is_subscription": True},
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
                        "plan_id": plan["plan_id"],
                        "plan_name": plan["plan_name"],
                        "description": plan["description"],
                        "vendor_count": plan["vendor_count"],
                    }
                )

            return {
                "total_plans": len(result),
                "plans": result,
            }

        except HTTPException as e:
            raise e

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_total_booking_for_year(self, current_user: User, year: int):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            if year < 2000 or year > 2100:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid year")

            start_date = f"{year}-01-01"
            end_date = f"{year + 1}-01-01"
            pipeline = [
                {
                    "$match": {
                        "payment_status": "paid",
                        "booking_date": {"$gte": start_date, "$lt": end_date},
                    }
                },
                {
                    "$group": {
                        "_id": {"$month": {"$dateFromString": {"dateString": "$booking_date"}}},  # Parse string to date
                        "booking_count": {"$sum": 1},  # Count bookings per month
                    }
                },
                {"$sort": {"_id": 1}},  # Sort by month for consistency
            ]

            # Execute the aggregation pipeline
            monthly_counts = await booking_collection.aggregate(pipeline).to_list(None)
            month_data = {month: 0 for month in range(1, 13)}
            for entry in monthly_counts:
                month_data[entry["_id"]] = entry["booking_count"]

            # Format the result
            result = [
                {"name": "Jan", "booking": month_data[1]},
                {"name": "Feb", "booking": month_data[2]},
                {"name": "Mar", "booking": month_data[3]},
                {"name": "Apr", "booking": month_data[4]},
                {"name": "May", "booking": month_data[5]},
                {"name": "Jun", "booking": month_data[6]},
                {"name": "Jul", "booking": month_data[7]},
                {"name": "Aug", "booking": month_data[8]},
                {"name": "Sep", "booking": month_data[9]},
                {"name": "Oct", "booking": month_data[10]},
                {"name": "Nov", "booking": month_data[11]},
                {"name": "Dec", "booking": month_data[12]},
            ]
            return result

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_all_tickets(
        self,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
    ):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            skip = max((page - 1) * limit, 0)
            query = {}

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

            if statuss:
                statuss = statuss.strip()
                if not statuss:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status cannot be empty")
                query["status"] = statuss

            # Fetch all tickets

            tickets = (
                await ticket_collection.find(query)
                .sort("created_at", DESCENDING)
                .skip(skip)
                .limit(limit)
                .to_list(length=limit)
            )
            if not tickets:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No tickets found")

            for ticket in tickets:
                ticket["id"] = str(ticket["_id"])
                ticket.pop("_id")

            total_tickets = await ticket_collection.count_documents(query)
            total_pages = (total_tickets + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": tickets,
                "paginator": {
                    "itemCount": total_tickets,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_ticket_details(self, current_user: User, ticket_id: str):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            # Fetch the ticket details
            ticket = await ticket_collection.find_one({"_id": ObjectId(ticket_id)})
            if not ticket:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

            ticket["id"] = str(ticket["_id"])
            ticket.pop("_id")

            return ticket

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def reply_to_ticket(self, current_user: User, ticket_id: str, reply: str):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Fetch the ticket to get the user's email
            ticket = await ticket_collection.find_one({"_id": ObjectId(ticket_id)})
            if not ticket:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

            user_email = ticket.get("email")
            if not user_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email not found in ticket")

            # Update the ticket with the reply
            update_data = await ticket_collection.update_one({"_id": ObjectId(ticket_id)}, {"$set": {"reply": reply}})

            # Send email to the user with the reply
            source = "Ticket Reply"
            to_email = user_email
            context = {"reply": reply}
            await send_email(to_email, source, context)

            return {reply}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_all_vendor_query(
        self,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
    ):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            skip = max((page - 1) * limit, 0)
            query = {}

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

            if statuss:
                statuss = statuss.strip()
                if not statuss:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status cannot be empty")
                query["status"] = statuss

            # Fetch all tickets

            vendor_query = (
                await vendor_query_collection.find(query)
                .sort("created_at", DESCENDING)
                .skip(skip)
                .limit(limit)
                .to_list(length=limit)
            )
            if not vendor_query:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor query found")

            for vendor in vendor_query:

                vendor["id"] = str(vendor["_id"])
                vendor.pop("_id")

            total_vendor_query = await vendor_query_collection.count_documents(query)
            total_pages = (total_vendor_query + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": vendor_query,
                "paginator": {
                    "itemCount": total_vendor_query,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_query_details(self, current_user: User, vendor_query_id: str):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            # Fetch the ticket details
            vendor_query = await vendor_query_collection.find_one({"_id": ObjectId(vendor_query_id)})
            if not vendor_query:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor query not found")

            vendor_query["id"] = str(vendor_query["_id"])
            vendor_query.pop("_id")

            return vendor_query

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def reply_to_vendor_query(self, current_user: User, vendor_query_id: str, reply: str):
        try:
            # Check if the user has the required permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Fetch the ticket to get the user's email
            vendor_query = await vendor_query_collection.find_one({"_id": ObjectId(vendor_query_id)})
            if not vendor_query:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

            user_email = vendor_query.get("email")
            if not user_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email not found in ticket")

            # Update the ticket with the reply
            await vendor_query_collection.update_one({"_id": ObjectId(vendor_query_id)}, {"$set": {"reply": reply}})

            # Send email to the user with the reply
            source = "Vendor Query Reply"
            to_email = user_email
            context = {"reply": reply}
            await send_email(to_email, source, context)

            return {reply}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_all_email(
        self,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
    ):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            skip = max((page - 1) * limit, 0)
            query = {}

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

            if statuss:
                statuss = statuss.strip()
                if not statuss:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status cannot be empty")
                query["status"] = statuss
            email_list = await email_monitor_collection.find(query).skip(skip).limit(limit).to_list(length=limit)

            for email in email_list:
                email["id"] = str(email["_id"])
                email.pop("_id", None)

            total_email_query = await email_monitor_collection.count_documents(query)
            total_pages = (total_email_query + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": email_list,
                "paginator": {
                    "itemCount": total_email_query,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
