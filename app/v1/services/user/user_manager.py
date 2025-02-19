# app/v1/middleware/user_manager.py

import logging
import random
import re

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
    blog_collection,
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
from app.v1.models.user import *
from app.v1.models.vendor import Vendor
from app.v1.schemas.user.auth import *
from app.v1.utils.email import generate_otp, send_email, send_sms_on_phone
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


logger = logging.getLogger(__name__)


class UserManager:

    async def create_user(self, user: User) -> dict:
        """Create a new user in the database."""
        try:
            existing_user = await user_collection.find_one(
                {
                    "$or": [
                        {"email": {"$eq": user.email, "$nin": [None, ""]}},
                        {"phone": {"$eq": user.phone, "$nin": [None, ""]}},
                    ]
                }
            )

            if existing_user:
                raise HTTPException(
                    status_code=404, detail="User with this email or phone already exists in the database."
                )

            otp = generate_otp()
            expiry_time = datetime.utcnow() + timedelta(minutes=10)
            expiry_time = datetime.utcnow() + timedelta(minutes=10)
            expiry_minutes = 10
            if user.email:
                source = "Activation_code"
                context = {"otp": otp, "to_email": user.email}
                to_email = user.email
                await send_email(to_email, source, context)
            if user.phone:
                to_phone = user.phone

                await send_sms_on_phone(
                    to_phone, otp, expiry_minutes
                )  # Uncomment this line when implementing SMS functionality

            user.otp = otp
            user.otp_expires = expiry_time

            user.password = hashpw(user.password.encode("utf-8"), gensalt()).decode("utf-8")
            if not user.roles:
                user.roles = [Role.user]
            # user.otp_expires = otp_expiration_time
            user.notification_settings = DEFAULT_NOTIFICATION_PREFERENCES
            user_dict = user.dict()
            result = await user_collection.insert_one(user_dict)
            user_dict["_id"] = str(result.inserted_id)
            return user_dict
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_profile(self, request: Request, token: str) -> dict:
        """Retrieve user details by ID."""
        # Validate and convert the ID to ObjectId
        current_user = await get_current_user(request=request, token=token)
        if not current_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

        user = await user_collection.find_one({"_id": ObjectId(current_user.id)})
        if not user:
            raise ValueError(f"User with ID '{current_user.id}' does not exist")

        # Convert MongoDB's ObjectId to string
        user["_id"] = str(user["_id"])
        user["id"] = str(user["_id"])

        # Optionally remove sensitive fields
        user.pop("password", None)  # Remove hashed password from response
        user.pop("otp", None)  # Remove OTP from response
        user.pop("otp_expires", None)
        user.pop("_id", None)

        return user

    async def list_users(self) -> list:
        """List all users."""
        users = []
        async for user in user_collection.find():
            user["_id"] = str(user["_id"])
            users.append(user)
        return users

    async def update_user(self, email: str, update_data: dict) -> dict:
        """Update user details."""
        result = await user_collection.find_one_and_update(
            {"email": email}, {"$set": update_data}, return_document=True
        )
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["_id"] = str(result["_id"])
        return result

    async def delete_user(self, email: str) -> dict:
        """Delete a user by email."""
        result = await user_collection.find_one_and_delete({"email": email})
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["id"] = str(result["_id"])
        return result

    async def sign_in(
        self, email: str = None, phone: int = None, password: str = None, is_login_with_otp: bool = False
    ) -> dict:
        """Sign in a user by email and password."""
        try:
            if email:
                users = await user_collection.find({}).to_list(length=None)
                result = await user_collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})
                if not result:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail="user does not exist with this email"
                    )
                if is_login_with_otp:
                    otp = generate_otp()
                    await user_collection.update_one(
                        {"email": email},
                        {"$set": {"otp": otp, "otp_expires": datetime.utcnow() + timedelta(minutes=10)}},
                    )
                    source = "Login With Otp"
                    context = {"otp": otp}
                    to_email = email
                    await send_email(to_email, source, context)
                    return {"message": "OTP sent to your email address"}
                stored_password_hash = result.get("password")
                if not stored_password_hash:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                    )
                if not bcrypt.checkpw(
                    password.encode("utf-8"),
                    (
                        stored_password_hash.encode("utf-8")
                        if isinstance(stored_password_hash, str)
                        else stored_password_hash
                    ),
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
                if user.status == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Your account is inactive, please contact admin",
                    )
                user_data = user.dict()
                user_data["id"] = str(user.id)  # Add the id explicitly

                user_data.pop("password", None)
                user_data.pop("otp", None)

                # Generate access and refresh tokens
                access_token = create_access_token(data={"sub": user.email})
                refresh_token = create_refresh_token(data={"sub": user.email})
                # token = generate_jwt_token(user_id)
            if phone:
                result = await user_collection.find_one({"phone": phone})
                if not result:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid phone number")
                if is_login_with_otp:
                    otp = generate_otp()
                    await user_collection.update_one(
                        {"phone": phone},
                        {"$set": {"otp": otp, "otp_expires": datetime.utcnow() + timedelta(minutes=10)}},
                    )
                    to_phone = phone
                    expiry_minutes = 10
                    await send_sms_on_phone(to_phone, otp, expiry_minutes)

                    return {"message": "OTP sent to your email address"}
                stored_password_hash = result.get("password")
                if not stored_password_hash:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                    )
                # Check if the entered password matches the stored hashed password
                if not bcrypt.checkpw(
                    password.encode("utf-8"),
                    (
                        stored_password_hash.encode("utf-8")
                        if isinstance(stored_password_hash, str)
                        else stored_password_hash
                    ),
                ):
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
                user = await User.find_one(User.phone == phone)
                if user is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
                if not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Please verify your email or phone to activate your account",
                    )
                if user.status == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Your account is inactive, please contact admin",
                    )
                user_data = user.dict()
                user_data["id"] = str(user.id)  # Add the id explicitly

                user_data.pop("password", None)
                user_data.pop("otp", None)

                # Generate access and refresh tokens
                access_token = create_access_token(data={"sub": user.phone})
                refresh_token = create_refresh_token(data={"sub": user.phone})
                # token = generate_jwt_token(user_id)

            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def resend_otp(self, email: Optional[str] = None, phone: Optional[int] = None) -> str:
        """Send OTP to the user's email or phone."""
        otp = generate_otp()  # Generate OTP

        if email:
            try:
                # Check if email exists in the database
                user = await user_collection.find_one({"email": email})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found")

                # Send OTP to email
                source = "Resend OTP"
                context = {"otp": otp}
                await send_email(email, source, context)
                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                update_data = {"otp": otp, "otp_expires": otp_expiration_time}
                await user_collection.update_one({"email": email}, {"$set": update_data})
                return otp

            except Exception as ex:
                raise HTTPException(status_code=500, detail="Internal Server Error")

        if phone:
            try:
                # Check if phone exists in the database
                user = await user_collection.find_one({"phone": phone})
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                to_phone = phone
                expiry_minutes = 10
                # Send OTP to phone (SMS)
                await send_sms_on_phone(to_phone, otp, expiry_minutes)
                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                update_data = {"otp": otp, "otp_expires": otp_expiration_time}

                await user_collection.update_one({"phone": phone}, {"$set": update_data})

                return otp

            except Exception as ex:
                raise HTTPException(status_code=500, detail="Internal Server Error")

        raise ValueError("Either email or phone must be provided to send OTP.")

    async def forgot_password(self, email: Optional[str] = None, phone: Optional[int] = None) -> dict:
        """Verify user by email or phone and send OTP."""
        try:
            otp = generate_otp()  # Generate OTP

            if email:
                # Check if the user exists with the provided email
                user = await User.find_one(User.email == email)
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided email.")

                # if user.notification_settings and not user.notification_settings.get("forgot_password", False):
                #     print("kkkkkkkkkkkkkkkkk")
                #     raise HTTPException(status_code=403, detail="Forgot password notifications are disabled for this user.")

                source = "Forgot Password"
                context = {"otp": otp}
                # Send OTP to the user's email
                await send_email(email, source, context)
                user.otp = otp

                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                user.otp_expires = otp_expiration_time
                await user.save()
                return {"message": "OTP sent to email", "otp": otp}  # Include OTP in response for testing

            if phone:
                # Check if the user exists with the provided phone
                user = await user_collection.find_one({"phone": phone})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided phone.")

                # Send OTP to the user's phone
                to_phone = phone
                expiry_minutes = 10
                await send_sms_on_phone(to_phone, otp, expiry_minutes)
                otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
                update_data = {"otp": otp, "otp_expires": otp_expiration_time}

                await user_collection.update_one({"phone": phone}, {"$set": update_data})

                return {"otp": otp}

            raise ValueError("Either email or phone must be provided to send OTP.")
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def validate_otp(self, email: Optional[str] = None, phone: Optional[int] = None, otp: str = None) -> dict:
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
            vendor = await vendor_collection.find_one({"user_id": str(user_data["id"])})
            if vendor:
                vendor_data = await vendor_collection.find_one({"user_id": str(user_data["id"])})
                vendor_data["id"] = str(vendor_data.pop("_id"))
                user_data["is_subscription"] = vendor_data["is_subscription"]
                user_data["business_type"] = vendor_data["business_type"]

            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

        if phone:
            user = await user_collection.find_one({"phone": phone})
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided phone.")

            if user.get("otp") != otp:
                raise HTTPException(status_code=400, detail="Invalid OTP.")
            if datetime.utcnow() > user.get("otp_expires"):
                raise HTTPException(status_code=400, detail="OTP has expired.")
            user.get("is_active") == True
            await user_collection.update_one({"phone": phone}, {"$set": {"is_active": True}})
            user_data = user.copy()  # Since `user` is a dictionary, use `copy()`
            user_data["id"] = str(user_data.pop("_id"))
            user_data.pop("password", None)
            user_data.pop("otp", None)
            vendor = await vendor_collection.find_one({"user_id": str(user_data["id"])})
            if vendor:
                vendor_data = await vendor_collection.find_one({"user_id": str(user_data["id"])})
                vendor_data["id"] = str(vendor_data.pop("_id"))
                user_data["is_subscription"] = vendor_data["is_subscription"]
                user_data["business_type"] = vendor_data["business_type"]
            # access_token = create_access_token(data={"sub": user.email})
            # refresh_token = create_refresh_token(data={"sub": user.email})

            access_token = create_access_token(data={"sub": user.get("phone")})
            refresh_token = create_refresh_token(data={"sub": user.get("phone")})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")

    async def reset_password(
        self, email: Optional[str] = None, phone: Optional[int] = None, password: str = None
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

    async def update_profile(self, request: Request, token: str, profile_update_request: UpdateProfileRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            user = await user_collection.find_one({"_id": ObjectId(current_user.id)})
            if user is None:
                raise HTTPException(status_code=404, detail="User not found.")
            update_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            if profile_update_request.phone is not None and profile_update_request.secondary_phone_number is not None:
                if profile_update_request.phone == profile_update_request.secondary_phone_number:
                    raise HTTPException(status_code=400, detail="Phone and secondary phone cannot be the same.")
            if profile_update_request.first_name is not None:
                update_data["first_name"] = profile_update_request.first_name
            if profile_update_request.last_name is not None:
                update_data["last_name"] = profile_update_request.last_name
            if profile_update_request.email is not None:
                existing_email = await user_collection.find_one({"email": profile_update_request.email})
                if existing_email and str(existing_email["_id"]) != str(user["_id"]):
                    raise HTTPException(status_code=400, detail="Email is already in use by another user.")
                update_data["email"] = profile_update_request.email
            if profile_update_request.user_image:
                image_name = profile_update_request.user_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                update_data["user_image"] = image_name
                update_data["user_image_url"] = file_url
            else:
                file_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{user.get('user_image')}"
                )
            # Check if phone number already exists in the database (excluding the current user)
            if profile_update_request.phone is not None:
                existing_phone = await user_collection.find_one({"phone": profile_update_request.phone})
                if existing_phone and str(existing_phone["_id"]) != str(user["_id"]):
                    raise HTTPException(status_code=400, detail="Phone number is already in use by another user.")
                update_data["phone"] = profile_update_request.phone
            if profile_update_request.gender is not None:
                update_data["gender"] = profile_update_request.gender
            if profile_update_request.dob is not None:
                update_data["dob"] = profile_update_request.dob
                if datetime.strptime(update_data["dob"], "%Y-%m-%d").date() > datetime.now().date():
                    raise HTTPException(status_code=400, detail="Date of birth cannot be in the future.")
            if profile_update_request.blood_group is not None:
                update_data["blood_group"] = profile_update_request.blood_group
            if profile_update_request.address is not None:
                update_data["address"] = profile_update_request.address.dict()
            if profile_update_request.secondary_phone_number is not None:
                existing_secondary_phone = await user_collection.find_one(
                    {"secondary_phone_number": profile_update_request.secondary_phone_number}
                )
                if existing_secondary_phone and str(existing_secondary_phone["_id"]) != str(user["_id"]):
                    raise HTTPException(
                        status_code=400, detail="Secondary phone number is already in use by another user."
                    )
                update_data["secondary_phone_number"] = profile_update_request.secondary_phone_number

            if not update_data:
                raise HTTPException(status_code=400, detail="No data provided to update.")

            await user_collection.update_one({"_id": ObjectId(user["_id"])}, {"$set": update_data})

            result = await user_collection.find_one({"_id": ObjectId(user["_id"])})
            if result and "_id" in result:
                result["_id"] = str(result["_id"])

            return result

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

    async def get_vendor_list_for_category(
        self,
        category_slug: str,
        service_id: Optional[str] = None,
        address: Optional[str] = None,
        page: int = 1,
        limit: int = 10,
    ) -> List[dict]:
        try:
            skip = (page - 1) * limit
            if not category_slug:
                raise HTTPException(status_code=400, detail="Invalid category slug")
            # Fetch the category
            category = await category_collection.find_one({"slug": category_slug})
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            category_id = str(category["_id"])
            # Base filter for vendors
            vendor_filter = {"category_id": category_id, "status": "active", "is_subscription": True}

            if service_id:
                if not ObjectId.is_valid(service_id):
                    raise HTTPException(status_code=400, detail="Invalid service ID")
                service = await services_collection.find_one({"_id": ObjectId(service_id), "status": "active"})
                if not service:
                    raise HTTPException(status_code=404, detail="Service not found")
                vendor_filter["services.id"] = service_id

            # Generate dates for the next 7 days
            current_date = datetime.now().date()
            date_range = [current_date + timedelta(days=i) for i in range(7)]
            date_strings = [d.strftime("%Y-%m-%d") for d in date_range]
            day_names = [d.strftime("%A") for d in date_range]

            # Aggregation pipeline
            pipeline = [
                {"$match": vendor_filter},
                {
                    "$lookup": {
                        "from": "users",
                        "let": {"user_id": {"$toString": "$user_id"}},  # Vendor ID as string
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {
                                        "$and": [
                                            {"$eq": ["$created_by", "$$user_id"]},
                                        ]
                                    }
                                }
                            },
                            {
                                "$project": {
                                    "_id": {"$toString": "$_id"},
                                    "first_name": 1,
                                    "last_name": 1,
                                    "email": 1,
                                    "phone": 1,
                                    "roles": 1,
                                    "availability_slots": 1,
                                }
                            },
                        ],
                        "as": "created_users",
                    }
                },
                {
                    "$lookup": {
                        "from": "users",
                        "let": {"userId": {"$toObjectId": "$user_id"}},  # Vendor's user_id
                        "pipeline": [
                            {"$match": {"$expr": {"$eq": ["$_id", "$$userId"]}}},
                            {
                                "$project": {
                                    "_id": 0,
                                    "first_name": 1,
                                    "last_name": 1,
                                    "email": 1,
                                    "phone": 1,
                                    "status": 1,
                                    "roles": 1,
                                    "availability_slots": 1,
                                }
                            },
                        ],
                        "as": "vendor_user",
                    }
                },
                {
                    "$lookup": {
                        "from": "bookings",
                        "let": {"vendor_id": {"$toObjectId": "$_id"}},  # Convert vendor _id to ObjectId
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$eq": [{"$toObjectId": "$vendor_id"}, "$$vendor_id"]
                                            },  # Convert vendor_id to ObjectId
                                            {"$eq": ["$payment_status", "paid"]},
                                            {"$in": ["$booking_date", date_strings]},
                                        ]
                                    }
                                }
                            }
                        ],
                        "as": "bookings",
                    }
                },
                {
                    "$project": {
                        "_id": 1,
                        "vendor_id": {"$toString": "$_id"},
                        "business_name": 1,
                        "business_type": 1,
                        "business_address": 1,
                        "business_details": 1,
                        "is_payment_required": 1,
                        "category_id": {"$toString": "$category_id"},
                        "services": 1,
                        "fees": 1,
                        "location": 1,
                        "specialization": 1,
                        "created_users": 1,  # Users created by the vendor (for business type)
                        "vendor_user": {"$arrayElemAt": ["$vendor_user", 0]},  # Vendor's own user details
                        "booking_count": {"$size": "$bookings"},
                        "bookings": {
                            "$map": {
                                "input": "$bookings",
                                "as": "booking",
                                "in": {
                                    "date": "$$booking.booking_date",
                                    "seat_count": {"$ifNull": ["$$booking.seat_count", 1]},
                                },
                            }
                        },
                    }
                },
                {
                    "$addFields": {
                        "user_details": {
                            "$cond": {
                                "if": {"$eq": ["$business_type", "business"]},
                                "then": {
                                    "$mergeObjects": [
                                        {"$arrayElemAt": ["$created_users", 0]},  # Include the created user details
                                        {"created_user_id": {"$toString": {"$arrayElemAt": ["$created_users._id", 0]}}},
                                    ]
                                },
                                "else": "$vendor_user",  # Use vendor's own user details for individual type
                            }
                        },
                    }
                },
                {
                    "$addFields": {
                        "user_details.availability_slots": {
                            "$reduce": {
                                "input": date_strings,
                                "initialValue": [],
                                "in": {
                                    "$concatArrays": [
                                        "$$value",
                                        {
                                            "$map": {
                                                "input": {
                                                    "$filter": {
                                                        "input": "$user_details.availability_slots",
                                                        "as": "slot",
                                                        "cond": {
                                                            "$eq": [
                                                                "$$slot.day",
                                                                {
                                                                    "$arrayElemAt": [
                                                                        day_names,
                                                                        {"$indexOfArray": [date_strings, "$$this"]},
                                                                    ]
                                                                },
                                                            ]
                                                        },
                                                    }
                                                },
                                                "as": "slot",
                                                "in": {
                                                    "$mergeObjects": [
                                                        "$$slot",
                                                        {
                                                            "date": "$$this",
                                                            "daily_booking_count": {
                                                                "$reduce": {
                                                                    "input": {
                                                                        "$filter": {
                                                                            "input": "$bookings",
                                                                            "as": "booking",
                                                                            "cond": {
                                                                                "$eq": ["$$booking.date", "$$this"]
                                                                            },
                                                                        }
                                                                    },
                                                                    "initialValue": 0,
                                                                    "in": {"$add": ["$$value", "$$this.seat_count"]},
                                                                }
                                                            },
                                                            "max_seat_count": {
                                                                "$reduce": {
                                                                    "input": "$$slot.time_slots",
                                                                    "initialValue": 0,
                                                                    "in": {"$add": ["$$value", "$$this.max_seat"]},
                                                                }
                                                            },
                                                        },
                                                    ]
                                                },
                                            }
                                        },
                                    ]
                                },
                            }
                        }
                    }
                },
                # Filter out vendors with null or empty availability_slots
                {
                    "$match": {
                        "$and": [
                            {"user_details.availability_slots": {"$ne": None}},  # Exclude null
                            {"user_details.availability_slots": {"$ne": []}},  # Exclude empty array
                        ]
                    }
                },
                {
                    "$project": {
                        "id": {"$toString": "$_id"},
                        "_id": 0,
                        "vendor_id": 1,
                        "business_name": 1,
                        "business_type": 1,
                        "business_address": 1,
                        "business_details": 1,
                        "category_id": 1,
                        "services": 1,
                        "fees": 1,
                        "location": 1,
                        "specialization": 1,
                        "user_details": 1,
                        "booking_count": 1,
                    }
                },
            ]

            if address:
                address = address.strip()
                print(address, "address in get_vendor_list_for_category")
                if address:
                    escaped_address = re.escape(address)  # Escape special characters
                    print(escaped_address, "escaped_address")
                    pipeline.append(
                        {
                            "$match": {
                                "location.formatted_address": {"$regex": f".*{escaped_address}.*", "$options": "i"}
                            }
                        }
                    )

            active_vendors = await vendor_collection.aggregate(pipeline).to_list(length=None)
            if not active_vendors:
                raise HTTPException(
                    status_code=404,
                    detail="No active vendors found for the given category" + (f" and service" if service_id else ""),
                )
            total_vendors = await vendor_collection.count_documents({})
            total_pages = (total_vendors + limit - 1) // limit
            return active_vendors

            # return {"data": active_vendors, "total_pages": total_pages, "total_items": total_vendors}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def get_booking_count_for_slot(self, vendor_id: str, day: str, time_slot: str) -> int:
        try:
            current_date = datetime.now().date()

            days = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}
            current_weekday = current_date.weekday()
            target_weekday = days[day]
            days_ahead = (target_weekday - current_weekday) % 7
            target_date = current_date + timedelta(days=days_ahead)
            vendor_obj = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor_obj:
                return 0
            vendor_id_str = str(vendor_obj["_id"])

            formatted_date = target_date.strftime("%Y-%m-%d")

            all_bookings = await booking_collection.find({"vendor_id": vendor_id_str}).to_list(length=None)
            # print(target_date,'target_date in get_booking_count_for_slot')
            # Combine date and time
            # slot_datetime = datetime.combine(
            #     target_date,
            #     datetime.strptime(start_time, "%H:%M").time()
            # )
            # Count bookings for this specific slot
            date_bookings = await booking_collection.find(
                {"vendor_id": vendor_id_str, "booking_date": formatted_date}
            ).to_list(length=None)
            booking_count = await booking_collection.count_documents(
                {
                    "vendor_id": vendor_id_str,
                    "booking_date": formatted_date,
                    "time_slot": {"$regex": f"^{time_slot}"},
                    "payment_status": "paid",
                }
            )
            return booking_count
        except Exception as e:
            return 0

    async def get_daily_booking_count(self, vendor_id: str, target_date: str) -> int:
        try:
            current_date = datetime.now().date()

            # days = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}
            # current_weekday = current_date.weekday()
            # target_weekday = days[day]
            # days_ahead = (target_weekday - current_weekday) % 7
            # target_date = current_date + timedelta(days=days_ahead)
            vendor_obj = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor_obj:
                return 0
            vendor_id_str = str(vendor_obj["_id"])
            # Get bookings for the entire day
            daily_booking_count = await booking_collection.count_documents(
                {"vendor_id": vendor_id_str, "payment_status": "paid", "booking_date": target_date}
            )

            return daily_booking_count
        except Exception as e:
            return 0

    async def get_max_seat_count(self, vendor_id: str, day: str) -> int:
        try:
            user = await user_collection.find_one({"_id": ObjectId(vendor_id)})  # Fetch from user collection
            if not user:
                return 0
            availability_slots = user.get("availability_slots", [])  # Fetch from user table
            max_seat_count = 0

            for slot in availability_slots:
                if slot["day"] == day:
                    for time_slot in slot.get("time_slots", []):
                        max_seat_count += time_slot.get("max_seat", 0)
            return max_seat_count
        except Exception as e:
            return 0

    async def get_availability_slots(self, vendor: dict) -> List[dict]:
        """
        Helper function to get availability slots for a vendor (now from user table).
        """
        availability_slots = []

        user = await user_collection.find_one({"_id": ObjectId(vendor["_id"])})  # Fetch from user collection
        if not user:
            return availability_slots  # Return empty if user not found

        for slot in user.get("availability_slots", []):  # Fetch slots from user table
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
            daily_booking_count = await self.get_daily_booking_count(str(user["_id"]), target_date)
            day_slot["daily_booking_count"] = daily_booking_count
            total_seat_count = await self.get_max_seat_count(str(user["_id"]), slot_day)
            day_slot["max_seat_count"] = total_seat_count

            for time_slot in slot.get("time_slots", []):
                booking_count = await self.get_booking_count_for_slot(
                    str(user["_id"]), slot_day, time_slot["start_time"]
                )

                day_slot["time_slots"].append(
                    {
                        "start_time": time_slot["start_time"],
                        "end_time": time_slot["end_time"],
                        "max_seat": time_slot["max_seat"],
                        "booking_count": booking_count,
                    }
                )

            availability_slots.append(day_slot)

        return availability_slots

    def _addresses_match(self, vendor_address: str, search_address: str) -> bool:
        """
        Helper method to determine if two addresses match.
        You can customize this method based on your matching requirements.
        """
        if not vendor_address or not search_address:
            return False

        # Convert both addresses to lowercase for case-insensitive comparison
        vendor_address = vendor_address.lower()
        search_address = search_address.lower()

        # Split addresses into components
        vendor_components = set(vendor_address.split(","))
        search_components = set(search_address.split(","))

        # Check if there's any overlap in the address components
        # You can adjust the matching threshold based on your needs
        common_components = vendor_components.intersection(search_components)
        return len(common_components) >= 2

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
                    {"$match": {"status": "active"}},  # Filter out inactive services
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
                                    "category_slug": {"$ifNull": ["$category_slug", ""]},
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
                            "category_slug": "$services.category_slug",
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
                    {"$match": {"status": "active"}},
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
                                    "category_slug": {"$ifNull": ["$category_slug", ""]},
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
                    data[category] = services[:6]
                else:
                    data[category] = services[:5]

                for service in data[category]:
                    service["service_id"] = str(service["service_id"])
                    if "category_slug" not in service:
                        service["category_slug"] = ""

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

            hashed_new_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

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

    async def google_login(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            return current_user

        except HTTPException as ex:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def blog_list(self, page: int = 1, limit: int = 10, search: str = None) -> dict:
        """
        Get list of all active categories.
        """
        try:
            # Fetch all active categories
            skip = (page - 1) * limit
            query = {}  # Start with an empty query

            # If there's a search term, modify the query to search by name or category_name
            if search:
                search_regex = {"$regex": search, "$options": "i"}  # Case-insensitive search
                query["$or"] = [
                    {"title": search_regex},  # Search by category name (if the category is loaded)
                ]
            active_blogs = await blog_collection.find(query).skip(skip).limit(limit).to_list(length=100)

            # Format the response with category name, status, and created_at
            blog_data = [
                {
                    "id": str(blog["_id"]),
                    "title": blog["title"],
                    "content": blog["content"],
                    "blog_url": blog["blog_url"],
                    "blog_image": blog["blog_image"],
                    "blog_image_url": blog["blog_image_url"],
                    "author_name": blog["author_name"],
                    "category": blog["category"],
                    "tags": blog["tags"],
                    "status": blog["status"],
                    "created_at": blog["created_at"],
                    "updated_at": blog["updated_at"],
                }
                for blog in active_blogs
            ]
            total_blogs = await blog_collection.count_documents({})
            total_pages = (total_blogs + limit - 1) // limit
            # Return the formatted response
            return {"data": blog_data, "total_pages": total_pages, "total_items": total_blogs}
        except Exception as e:
            raise e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to fetch list of blogs: {str(e)}"
            )

    async def get_blog_by_id(self, id: str) -> dict:
        try:
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid blog ID: '{id}'")

            # Check if the blog exists
            existing_blog = await blog_collection.find_one({"_id": ObjectId(id)})
            if not existing_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            # Format the result
            blog_data = {
                "id": str(existing_blog["_id"]),
                "title": existing_blog["title"],
                "content": existing_blog["content"],
                "blog_url": existing_blog["blog_url"],
                "blog_image": existing_blog["blog_image"],
                "blog_image_url": existing_blog["blog_image_url"],
                "author_name": existing_blog["author_name"],
                "category": existing_blog["category"],
                "tags": existing_blog["tags"],
                "status": existing_blog["status"],
                "created_at": existing_blog["created_at"],
                "updated_at": existing_blog["updated_at"],
            }
            recent_blogs = (
                await blog_collection.find({"_id": {"$ne": ObjectId(id)}})
                .sort("created_at", -1)
                .limit(3)
                .to_list(length=3)
            )
            recent_blog_list = []
            for blog in recent_blogs:
                recent_blog_list.append(
                    {
                        "id": str(blog["_id"]),
                        "title": blog["title"],
                        "blog_url": blog["blog_url"],
                        "blog_image_url": blog["blog_image_url"],
                        "author_name": blog["author_name"],
                        "created_at": blog["created_at"],
                    }
                )

            return {
                "blog": blog_data,
                "recent_blogs": recent_blog_list,
            }
            return blog_data
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )
