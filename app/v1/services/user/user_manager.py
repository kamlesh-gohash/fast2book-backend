# app/v1/middleware/user_manager.py

import logging
import random

from datetime import datetime, timedelta
from typing import List, Optional

import bcrypt

from bcrypt import gensalt, hashpw
from beanie import Link
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection  # Ensure this import for Motor

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    booking_collection,
    category_collection,
    services_collection,
    support_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.support import Support
from app.v1.models.user import Role
from app.v1.models.vendor import Vendor
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


logger = logging.getLogger(__name__)


class UserManager:

    async def create_user(self, user: User) -> dict:
        """Create a new user in the database."""
        existing_user = await user_collection.find_one(
            {
                "$or": [
                    {"email": {"$eq": user.email, "$nin": [None, ""]}},
                    {"phone": {"$eq": user.phone, "$nin": [None, ""]}},
                ]
            }
        )

        if existing_user:
            raise HTTPException(status_code=404, detail="User with this email or phone already exists in the database.")

        otp = generate_otp()

        if user.email:
            to_email = user.email
            await send_email(to_email, otp)
        if user.phone:
            to_phone = user.phone
            # await send_sms(to_phone, otp)  # Uncomment this line when implementing SMS functionality
        otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
        user.otp = otp
        user.otp_expires = otp_expiration_time
        user.password = hashpw(user.password.encode("utf-8"), gensalt()).decode("utf-8")
        if not user.roles:
            user.roles = [Role.user]
        # user.otp_expires = otp_expiration_time
        user_dict = user.dict()
        result = await user_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)
        return user_dict

    async def get_profile(self, user_id: str) -> dict:
        """Retrieve user details by ID."""
        # Validate and convert the ID to ObjectId
        if not ObjectId.is_valid(user_id):
            raise ValueError(f"Invalid user ID: '{user_id}'")

        user = await user_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise ValueError(f"User with ID '{user_id}' does not exist")

        # Convert MongoDB's ObjectId to string
        user["_id"] = str(user["_id"])

        # Optionally remove sensitive fields
        user.pop("password", None)  # Remove hashed password from response
        user.pop("otp", None)  # Remove OTP from response

        return user

    async def list_users(self) -> list:
        """List all users."""
        users = []
        async for user in user_collection.find():
            user["_id"] = str(user["_id"])  # Convert ObjectId to string
            users.append(user)
        return users

    async def update_user(self, email: str, update_data: dict) -> dict:
        """Update user details."""
        result = await user_collection.find_one_and_update(
            {"email": email}, {"$set": update_data}, return_document=True
        )
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
        return result

    async def delete_user(self, email: str) -> dict:
        """Delete a user by email."""
        result = await user_collection.find_one_and_delete({"email": email})
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["id"] = str(result["_id"])  # Convert ObjectId to string
        return result

    async def sign_in(self, email: str, password: str = None, is_login_with_otp: bool = False) -> dict:
        """Sign in a user by email and password."""
        try:
            result = await user_collection.find_one({"email": email})
            if not result:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            if is_login_with_otp:
                otp = generate_otp()
                await user_collection.update_one(
                    {"email": email}, {"$set": {"otp": otp, "otp_expires": datetime.utcnow() + timedelta(minutes=10)}}
                )
                await send_email(email, otp)
                return {"message": "OTP sent to your email address"}
            stored_password_hash = result.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                )
            # Check if the entered password matches the stored hashed password
            if not bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Please verify your email or phone to activate your account",
                )
            user_data = user.dict()
            user_data["id"] = str(user.id)  # Add the id explicitly

            user_data.pop("password", None)
            user_data.pop("otp", None)

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

    async def resend_otp(self, email: Optional[str] = None, phone: Optional[str] = None) -> str:
        """Send OTP to the user's email or phone."""
        otp = generate_otp()  # Generate OTP

        if email:
            try:
                # Check if email exists in the database
                user = await User.find_one(User.email == email)

                if user is None:
                    raise HTTPException(status_code=404, detail="User not found")

                # Send OTP to email
                await send_email(email, otp)
                user.otp = otp  # Update the OTP in the database

                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                user.otp_expires = otp_expiration_time
                await user.save()
                return otp

            except Exception as ex:
                raise HTTPException(status_code=500, detail="Internal Server Error")

        if phone:
            try:
                # Check if phone exists in the database
                user = await User.find_one(User.phone == phone)

                if user is None:
                    raise HTTPException(status_code=404, detail="User not found")

                # Send OTP to phone (SMS)
                # await send_sms(phone, otp)  # Uncomment when implementing SMS
                user.otp = otp  # Update the OTP in the database

                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                user.otp_expires = otp_expiration_time
                await user.save()
                return otp

            except Exception as ex:
                raise HTTPException(status_code=500, detail="Internal Server Error")

        raise ValueError("Either email or phone must be provided to send OTP.")

    async def forgot_password(self, email: Optional[str] = None, phone: Optional[str] = None) -> dict:
        """Verify user by email or phone and send OTP."""
        try:
            otp = generate_otp()  # Generate OTP

            if email:
                # Check if the user exists with the provided email
                user = await User.find_one(User.email == email)
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided email.")

                # Send OTP to the user's email
                await send_email(email, otp)
                user.otp = otp

                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                user.otp_expires = otp_expiration_time
                await user.save()
                return {"message": "OTP sent to email", "otp": otp}  # Include OTP in response for testing

            if phone:
                user = await User.find_one(User.phone == phone)
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided phone.")
                user.otp = otp

                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                user.otp_expires = otp_expiration_time
                await user.save()
                return {"message": "OTP sent to phone", "otp": otp}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def validate_otp(self, email: Optional[str] = None, phone: Optional[str] = None, otp: str = None) -> dict:
        if email:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided email.")
            if user.otp != otp:
                raise HTTPException(status_code=400, detail="Invalid OTP.")
            if datetime.utcnow() > user.otp_expires:
                raise HTTPException(status_code=400, detail="OTP has expired.")
            user.is_active = True
            await user.save()
            user_data = user.dict(by_alias=True)
            user_data["id"] = str(user_data.pop("_id"))
            user_data.pop("password", None)
            user_data.pop("otp", None)
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

        if phone:
            user = await User.find_one(User.phone == phone)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided phone.")
            if user.otp != otp:
                raise HTTPException(status_code=400, detail="Invalid OTP.")
            if datetime.utcnow() > user.otp_expires:
                raise HTTPException(status_code=400, detail="OTP has expired.")
            user.is_active = True
            await user.save()
            user_data = user.dict(by_alias=True)
            user_data["id"] = str(user_data.pop("_id"))
            user_data.pop("password", None)
            user_data.pop("otp", None)
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")

    async def reset_password(
        self, email: Optional[str] = None, phone: Optional[str] = None, password: str = None
    ) -> dict:
        if not password:
            raise HTTPException(status_code=400, detail="Password is required.")

        if email:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided email.")

            user.password = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")
            await user.save()
            return {"message": "Password reset successful."}

        if phone:
            user = await User.find_one(User.phone == phone)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided phone.")

            user.password = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")
            await user.save()
            return {"message": "Password reset successful."}

        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")

    async def update_profile(self, user_id: str, profile_update_request: User):

        try:
            if not ObjectId.is_valid(user_id):
                raise HTTPException(status_code=400, detail="Invalid user ID.")
            user = await User.find_one(User.id == ObjectId(user_id))
            if user is None:
                raise HTTPException(status_code=404, detail="User not found.")
            update_data = {}
            if profile_update_request.first_name is not None:
                update_data["first_name"] = profile_update_request.first_name
            if profile_update_request.last_name is not None:
                update_data["last_name"] = profile_update_request.last_name
            if profile_update_request.email is not None:
                update_data["email"] = profile_update_request.email
            if profile_update_request.phone is not None:
                update_data["phone"] = profile_update_request.phone
            if profile_update_request.gender is not None:
                update_data["gender"] = profile_update_request.gender
            if profile_update_request.dob is not None:
                update_data["dob"] = profile_update_request.dob
                if datetime.strptime(update_data["dob"], "%Y-%m-%d").date() > datetime.now().date():
                    raise HTTPException(status_code=400, detail="Date of birth cannot be in the future.")
            if profile_update_request.user_profile is not None:
                update_data["user_profile"] = profile_update_request.user_profile
            if profile_update_request.blood_group is not None:
                update_data["blood_group"] = profile_update_request.blood_group

            if not update_data:
                raise HTTPException(status_code=400, detail="No data provided to update.")

            await user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
            result = await user_collection.find_one({"_id": ObjectId(user_id)})

            return {"message": "Profile updated successfully.", "user": result}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_category_list_for_users(self) -> List[Category]:
        try:

            active_categories = await category_collection.find({"status": "active"}).to_list(length=None)
            category_data = [
                {
                    "id": str(category["_id"]),
                    "name": category["name"],
                    "slug": category["slug"],
                    "status": category["status"],
                }
                for category in active_categories
            ]

            return category_data
        except HTTPException:
            raise
        except Exception as ex:
            print(ex)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_service_list_for_category(self, category_slug: str) -> List[Service]:
        try:
            if not category_slug:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid category slug")

            category = await category_collection.find_one({"slug": category_slug})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            active_services = await services_collection.find(
                {"category_id": category["_id"], "status": "active"}
            ).to_list(length=None)
            service_data = [
                {"id": str(service["_id"]), "name": service["name"], "status": service["status"]}
                for service in active_services
            ]

            return service_data
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    # async def get_vendor_list_for_category(self, category_slug: str) -> List[dict]:
    #     try:
    #         if not category_slug:
    #             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid category slug")

    #         category = await category_collection.find_one({"slug": category_slug})
    #         if not category:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
    #         category_id = str(category["_id"])
    #         active_vendors = await vendor_collection.find({"category_id": category_id, "status": "active"}).to_list(length=None)
    #         if not active_vendors:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active vendors found for the given category")
    async def get_vendor_list_for_category(self, category_slug: str, service_id: Optional[str] = None) -> List[dict]:
        try:
            if not category_slug:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid category slug")

            category = await category_collection.find_one({"slug": category_slug})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            category_id = str(category["_id"])

            # Base filter
            vendor_filter = {"category_id": category_id, "status": "active"}

            # If service_id is provided, add it to the filter
            if service_id:
                if not ObjectId.is_valid(service_id):
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid service ID")

                service = await services_collection.find_one({"_id": ObjectId(service_id), "status": "active"})
                if not service:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

                vendor_filter["services.id"] = service_id

            # Fetch vendors based on the constructed filter
            active_vendors = await vendor_collection.find(vendor_filter).to_list(length=None)
            if not active_vendors:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No active vendors found for the given category" + (f" and service" if service_id else ""),
                )
            vendor_data = []
            for vendor in active_vendors:
                try:
                    user = await user_collection.find_one(
                        {"$or": [{"_id": vendor["user_id"]}, {"_id": ObjectId(vendor["user_id"])}]}
                    )

                    if user:
                        if vendor["business_type"] == "business":
                            created_users = await user_collection.find(
                                {
                                    "$or": [
                                        {"created_by": str(vendor["user_id"])},
                                        {"created_by": vendor["user_id"]},
                                    ]
                                }
                            ).to_list(length=None)

                            # If created users exist, append each user as a separate vendor entry
                            if created_users:
                                for u in created_users:
                                    user_details = {
                                        "first_name": u.get("first_name"),
                                        "last_name": u.get("last_name"),
                                        "email": u.get("email"),
                                        "phone": u.get("phone"),
                                        "status": u.get("status"),
                                        "roles": u.get("roles"),
                                        "availability_slots": [],
                                    }
                                    availability_slots = vendor.get("availability_slots", [])
                                for slot in availability_slots:
                                    slot_day = slot["day"]
                                    current_date = datetime.now().date()
                                    days = {
                                        "Monday": 0,
                                        "Tuesday": 1,
                                        "Wednesday": 2,
                                        "Thursday": 3,
                                        "Friday": 4,
                                        "Saturday": 5,
                                        "Sunday": 6,
                                    }
                                    current_weekday = current_date.weekday()
                                    target_weekday = days[slot_day]
                                    days_ahead = (target_weekday - current_weekday) % 7
                                    target_date = current_date + timedelta(days=days_ahead)

                                    day_slot = {
                                        "day": slot_day,
                                        "date": target_date.strftime("%Y-%m-%d"),
                                        "time_slots": [],
                                    }
                                    daily_booking_count = await self.get_daily_booking_count(
                                        str(vendor["_id"]), slot_day
                                    )
                                    day_slot["daily_booking_count"] = daily_booking_count
                                    total_seat_count = await self.get_max_seat_count(str(vendor["_id"]), slot_day)
                                    day_slot["max_seat_count"] = total_seat_count
                                    for time_slot in slot.get("time_slots", []):
                                        booking_count = await self.get_booking_count_for_slot(
                                            str(vendor["_id"]), slot_day, time_slot["start_time"]
                                        )

                                        day_slot["time_slots"].append(
                                            {
                                                "start_time": time_slot["start_time"],
                                                "end_time": time_slot["end_time"],
                                                "max_seat": time_slot["max_seat"],
                                                "booking_count": booking_count,
                                            }
                                        )

                                    user_details["availability_slots"].append(day_slot)
                                    vendor_data.append(
                                        {
                                            "vendor_id": str(vendor["_id"]),
                                            "business_name": vendor.get("business_name"),
                                            "business_type": vendor.get("business_type"),
                                            "business_address": vendor.get("business_address"),
                                            "business_details": vendor.get("business_details"),
                                            "category_id": str(vendor["category_id"]),
                                            "services": vendor.get("services", []),
                                            "fees": vendor.get("fees", 0),
                                            "user_details": user_details,
                                        }
                                    )
                        else:
                            user_details = {
                                "first_name": user.get("first_name"),
                                "last_name": user.get("last_name"),
                                "email": user.get("email"),
                                "phone": user.get("phone"),
                                "status": user.get("status"),
                                "roles": user.get("roles"),
                                "availability_slots": [],
                            }

                            availability_slots = vendor.get("availability_slots", [])
                            for slot in availability_slots:
                                slot_day = slot["day"]
                                current_date = datetime.now().date()
                                days = {
                                    "Monday": 0,
                                    "Tuesday": 1,
                                    "Wednesday": 2,
                                    "Thursday": 3,
                                    "Friday": 4,
                                    "Saturday": 5,
                                    "Sunday": 6,
                                }
                                current_weekday = current_date.weekday()
                                target_weekday = days[slot_day]
                                days_ahead = (target_weekday - current_weekday) % 7
                                target_date = current_date + timedelta(days=days_ahead)

                                day_slot = {"day": slot_day, "date": target_date.strftime("%Y-%m-%d"), "time_slots": []}
                                daily_booking_count = await self.get_daily_booking_count(str(vendor["_id"]), slot_day)
                                day_slot["daily_booking_count"] = daily_booking_count
                                total_seat_count = await self.get_max_seat_count(str(vendor["_id"]), slot_day)
                                day_slot["max_seat_count"] = total_seat_count
                                for time_slot in slot.get("time_slots", []):
                                    booking_count = await self.get_booking_count_for_slot(
                                        str(vendor["_id"]), slot_day, time_slot["start_time"]
                                    )

                                    day_slot["time_slots"].append(
                                        {
                                            "start_time": time_slot["start_time"],
                                            "end_time": time_slot["end_time"],
                                            "max_seat": time_slot["max_seat"],
                                            "booking_count": booking_count,
                                        }
                                    )

                                user_details["availability_slots"].append(day_slot)

                            vendor_data.append(
                                {
                                    "vendor_id": str(vendor["_id"]),
                                    "business_name": vendor.get("business_name"),
                                    "business_type": vendor.get("business_type"),
                                    "business_address": vendor.get("business_address"),
                                    "business_details": vendor.get("business_details"),
                                    "category_id": str(vendor["category_id"]),
                                    "services": vendor.get("services", []),
                                    "fees": vendor.get("fees", 0),
                                    "user_details": user_details,
                                }
                            )

                    else:
                        vendor_data.append(
                            {
                                "vendor_id": str(vendor["_id"]),
                                "business_name": vendor.get("business_name"),
                                "business_type": vendor.get("business_type"),
                                "user_details": [] if vendor["business_type"] == "business" else {},
                                "availability_slots": vendor.get("availability_slots", []),
                            }
                        )
                except Exception as e:
                    vendor_data.append(
                        {
                            "vendor_id": str(vendor["_id"]),
                            "business_name": vendor.get("business_name"),
                            "business_type": vendor.get("business_type"),
                            "user_details": [] if vendor["business_type"] == "business" else {},
                            "availability_slots": vendor.get("availability_slots", []),
                        }
                    )

            return vendor_data
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_booking_count_for_slot(self, vendor_id: str, day: str, time_slot: str) -> int:
        try:
            current_date = datetime.now().date()

            days = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}
            current_weekday = current_date.weekday()
            target_weekday = days[day]
            days_ahead = (target_weekday - current_weekday) % 7
            target_date = current_date + timedelta(days=days_ahead)
            # Combine date and time
            # slot_datetime = datetime.combine(
            #     target_date,
            #     datetime.strptime(start_time, "%H:%M").time()
            # )
            # Count bookings for this specific slot
            booking_count = await booking_collection.count_documents(
                {
                    "vendor_id": vendor_id,
                    "booking_date": target_date.strftime("%Y-%m-%d"),
                    "time_slot": {"$regex": f"^{time_slot}"},
                }
            )
            return booking_count
        except Exception as e:
            return 0

    async def get_daily_booking_count(self, vendor_id: str, day: str) -> int:
        try:
            current_date = datetime.now().date()

            days = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}
            current_weekday = current_date.weekday()
            target_weekday = days[day]
            days_ahead = (target_weekday - current_weekday) % 7
            target_date = current_date + timedelta(days=days_ahead)

            # Get bookings for the entire day
            daily_booking_count = await booking_collection.count_documents(
                {
                    "vendor_id": vendor_id,
                    "booking_date": target_date.strftime("%Y-%m-%d"),
                }
            )

            return daily_booking_count
        except Exception as e:
            return 0

    async def get_max_seat_count(self, vendor_id: str, day: str) -> int:
        try:
            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                return 0
            availability_slots = vendor.get("availability_slots", [])
            max_seat_count = 0

            for slot in availability_slots:
                if slot["day"] == day:
                    for time_slot in slot.get("time_slots", []):
                        max_seat_count += time_slot.get("max_seat", 0)

            return max_seat_count
        except Exception as e:
            return 0

    async def get_vendor_list_for_services(self, service_id: str) -> List[dict]:
        try:
            if not ObjectId.is_valid(service_id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid service ID")

            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            active_vendors = await vendor_collection.find(
                {
                    "services.id": service_id,
                    "status": "active",
                }
            ).to_list(length=None)

            if not active_vendors:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No active vendors found for the given service",
                )

            vendor_data = []

            for vendor in active_vendors:
                try:
                    user = await user_collection.find_one({"_id": ObjectId(vendor["user_id"])})
                    if not user:
                        continue

                    if vendor["business_type"] == "business":
                        created_users = await user_collection.find({"created_by": str(vendor["user_id"])}).to_list(
                            length=None
                        )
                        user_details = [
                            {
                                "first_name": u.get("first_name"),
                                "last_name": u.get("last_name"),
                                "email": u.get("email"),
                                "phone": u.get("phone"),
                                "status": u.get("status"),
                                "roles": u.get("roles"),
                                "availability_slots": u.get("availability_slots", []),
                            }
                            for u in created_users
                        ]
                    else:
                        user_details = {
                            "first_name": user.get("first_name"),
                            "last_name": user.get("last_name"),
                            "email": user.get("email"),
                            "phone": user.get("phone"),
                            "status": user.get("status"),
                            "roles": user.get("roles"),
                            "availability_slots": vendor.get("availability_slots", []),
                        }

                    # Prepare vendor data
                    vendor_info = {
                        "id": str(vendor["_id"]),
                        "status": vendor["status"],
                        "business_name": vendor.get("business_name"),
                        "business_type": vendor.get("business_type"),
                        "business_address": vendor.get("business_address"),
                        "business_details": vendor.get("business_details"),
                        "services": vendor.get("services", []),
                        "is_payment_verified": vendor.get("is_payment_verified"),
                        "created_at": vendor.get("created_at"),
                        "user_details": user_details,
                    }
                    vendor_data.append(vendor_info)

                except Exception as e:
                    continue

            return vendor_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred",
            )

    async def create_support_request(self, support_request: Support):
        try:

            result = await support_collection.insert_one(support_request.dict())
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Support request not found")
            result_data = {
                "id": str(result.inserted_id),
                "name": support_request.name,
                "email": support_request.email,
                "phone": support_request.phone,
                "message": support_request.message,
                "created_at": support_request.created_at,
            }

            return result_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def service_search(self, id: str):
        try:
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid service ID")

            result = await services_collection.find_one({"_id": ObjectId(id)})
            if not result:
                logger.error(f"Service with ID {id} not found.")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            updated_service = await services_collection.find_one_and_update(
                {"_id": ObjectId(id)}, {"$inc": {"number_of_views": 1}}, return_document=True
            )

            if not updated_service:
                logger.error(f"Service with ID {id} was not updated correctly.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update service"
                )

            result_data = {
                "service_name": updated_service.get("name"),
                "number_of_views": updated_service.get("number_of_views"),
            }
            return result_data

        except HTTPException as ex:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def category_search(self, id: str):
        try:
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid category ID")

            result = await category_collection.find_one({"_id": ObjectId(id)})
            if not result:
                logger.error(f"Category with ID {id} not found.")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            updated_category = await category_collection.find_one_and_update(
                {"_id": ObjectId(id)}, {"$inc": {"number_of_views": 1}}, return_document=True
            )

            if not updated_category:
                logger.error(f"Category with ID {id} was not updated correctly.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update category"
                )

            result_data = {
                "category_name": updated_category.get("name"),
                "number_of_views": updated_category.get("number_of_views"),
            }
            return result_data

        except HTTPException as ex:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_top_services(self):
        try:
            cursor = services_collection.aggregate(
                [
                    {"$sort": {"number_of_views": -1}},
                    {
                        "$group": {
                            "_id": "$category_name",
                            "services": {
                                "$push": {
                                    "service_id": "$_id",
                                    "name": "$name",
                                    "number_of_views": "$number_of_views",
                                    "category_name": "$category_name",
                                    "service_image": "$service_image",
                                    "service_image_url": "$service_image_url",
                                }
                            },
                        }
                    },
                    {"$project": {"_id": 0, "category": "$_id", "services": {"$slice": ["$services", 2]}}},
                    {"$unwind": "$services"},
                    {
                        "$project": {
                            "id": {"$toString": "$services.service_id"},
                            "name": "$services.name",
                            "service_image": "$services.service_image",
                            "service_image_url": "$services.service_image_url",
                            "number_of_views": "$services.number_of_views",
                            "category": "$category",
                        }
                    },
                ]
            )

            result = await cursor.to_list(length=100)
            for item in result:
                item["id"] = str(item["id"])
                item["category"] = str(item["category"])

            return result

        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_category_top_service(self):
        try:
            cursor = services_collection.aggregate(
                [
                    {"$sort": {"number_of_views": -1}},
                    {
                        "$group": {
                            "_id": "$category_name",
                            "services": {
                                "$push": {
                                    "service_id": "$_id",
                                    "name": "$name",
                                    "service_image": "$service_image",
                                    "service_image_url": "$service_image_url",
                                    "category_name": "$category_name",
                                }
                            },
                        }
                    },
                    {"$project": {"_id": 0, "category": "$_id", "services": 1}},
                ]
            )

            result = await cursor.to_list(length=100)

            data = {}
            for item in result:
                category = item["category"]
                services = item["services"]

                if category == "Doctor":
                    data[category] = {"services": services[:6]}
                else:
                    data[category] = {"services": services[:5]}
                for service in data[category]["services"]:
                    service["service_id"] = str(service["service_id"])

            return data

        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def change_password(self, request: Request, token: str, old_password: str, new_password: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if old_password is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Old Password required")
            if not bcrypt.checkpw(old_password.encode("utf-8"), current_user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Old password does not match",
                )

            # Ensure the new password is different
            if bcrypt.checkpw(new_password.encode("utf-8"), current_user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password cannot be the same as the old password",
                )

            # Hash the new password and save it
            hashed_new_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            # Update user in the database
            await user_collection.update_one(
                {"_id": ObjectId(current_user.id)}, {"$set": {"password": hashed_new_password}}
            )
            return {None}

        except HTTPException as ex:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
