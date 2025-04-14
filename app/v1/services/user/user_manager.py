# app/v1/middleware/user_manager.py

import logging
import random
import re

from datetime import date, datetime, timedelta
from typing import List, Optional

import aiohttp
import bcrypt
import geocoder
import httpx

from bcrypt import gensalt, hashpw
from beanie import Link
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import BackgroundTasks, Body, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection  # Ensure this import for Motor

from app.v1.middleware.auth import get_current_user, get_current_user_by_google
from app.v1.models import (
    User,
    blog_collection,
    booking_collection,
    category_collection,
    search_query_collection,
    services_collection,
    support_collection,
    ticket_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.category import Category
from app.v1.models.search_query import SearchQuery
from app.v1.models.services import Service
from app.v1.models.support import Support
from app.v1.models.ticket import Ticket
from app.v1.models.user import *
from app.v1.models.vendor import Vendor
from app.v1.schemas.user.auth import *
from app.v1.utils.email import generate_otp, send_email, send_sms_on_phone
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


# from app.v1.utils.notification import send_push_notification

logger = logging.getLogger(__name__)


class UserManager:

    async def create_user(self, user: User, background_tasks: BackgroundTasks) -> dict:
        """Create a new user in the database."""
        try:
            # Check if a user with the same email or phone already exists
            existing_user = await user_collection.find_one(
                {
                    "$or": [
                        {"email": {"$eq": user.email, "$nin": [None, ""]}},
                        {"phone": {"$eq": user.phone, "$nin": [None, ""]}},
                    ]
                }
            )

            if existing_user:
                # If the user exists and is already active, raise an error
                if existing_user.get("is_active", False):
                    raise HTTPException(
                        status_code=400, detail="User with this email or phone already exists and is active."
                    )

                # If the user exists but is not active, update their data and send a new OTP
                if user.email:  # Check if email is provided
                    email = user.email.lower()
                    user.email = email
                otp = generate_otp()
                expiry_time = datetime.utcnow() + timedelta(minutes=10)
                expiry_minutes = 10

                if user.email:
                    source = "Activation_code"
                    context = {"otp": otp, "to_email": user.email, "user_name": user.first_name}
                    to_email = user.email
                    background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

                if user.phone:
                    to_phone = user.phone
                    await send_sms_on_phone(to_phone, otp, expiry_minutes)

                # Update the existing user with new data
                update_data = {
                    "sign_up_otp": otp,
                    "signup_otp_expires": expiry_time,
                    "password": hashpw(user.password.encode("utf-8"), gensalt()).decode("utf-8"),
                    "roles": user.roles if user.roles else [Role.user],
                    "notification_settings": DEFAULT_NOTIFICATION_PREFERENCES,
                }

                # Update the user in the database
                await user_collection.update_one({"_id": ObjectId(existing_user["_id"])}, {"$set": update_data})

                # Return the updated user data
                updated_user = await user_collection.find_one({"_id": ObjectId(existing_user["_id"])})
                updated_user["_id"] = str(updated_user["_id"])
                return updated_user

            # If the user does not exist, create a new user
            if user.email:  # Check if email is provided
                email = user.email.lower()
                user.email = email
            otp = generate_otp()
            expiry_time = datetime.utcnow() + timedelta(minutes=10)
            expiry_minutes = 10

            # Send OTP to email if provided
            if user.email:
                source = "Activation_code"
                context = {"otp": otp, "to_email": user.email, "name": user.first_name + " " + user.last_name}
                to_email = user.email
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)
            # Send OTP to phone if provided
            if user.phone:
                to_phone = user.phone
                await send_sms_on_phone(to_phone, otp, expiry_minutes)

            # Set user fields in dictionary
            user_dict = user.dict()
            user_dict["sign_up_otp"] = otp
            user_dict["signup_otp_expires"] = expiry_time
            user_dict["password"] = hashpw(user.password.encode("utf-8"), gensalt()).decode("utf-8")
            if not user.roles:
                user_dict["roles"] = [Role.user]
            user_dict["notification_settings"] = DEFAULT_NOTIFICATION_PREFERENCES
            user_dict["is_active"] = False
            result = await user_collection.insert_one(user_dict)
            user_dict["_id"] = str(result.inserted_id)
            return user_dict

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_profile(self, current_user: User) -> dict:
        """Retrieve user details by ID."""
        # Validate and convert the ID to ObjectId
        try:
            user = await user_collection.find_one({"_id": ObjectId(current_user.id)})
            if not user:
                raise ValueError(f"User with ID '{current_user.id}' does not exist")

            user["_id"] = str(user["_id"])
            user["id"] = str(user["_id"])

            user.pop("password", None)  # Remove hashed password from response
            user.pop("otp", None)  # Remove OTP from response
            user.pop("otp_expires", None)
            user.pop("_id", None)
            if user.get("user_image") is not None:
                user["user_image_url"] = user["user_image_url"]
            else:
                user["user_image_url"] = None

            return user
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def sign_in(
        self, email: str = None, phone: int = None, password: str = None, is_login_with_otp: bool = False
    ) -> dict:
        """Sign in a user by email or password."""
        try:
            if email:
                result = await user_collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})
                if not result:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail="User does not exist with this email"
                    )
                if is_login_with_otp:
                    if not result.get("is_active", False):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Please verify your email to activate your account",
                        )
                    if result.get("status") == "inactive":
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Your account is inactive, please contact admin",
                        )

                    otp = generate_otp()
                    await user_collection.update_one(
                        {"email": email},
                        {"$set": {"login_otp": otp, "login_otp_expires": datetime.utcnow() + timedelta(minutes=10)}},
                    )
                    # device_token = result.get("device_token")
                    # if device_token:
                    #     try:
                    #         await send_push_notification(
                    #             device_token=device_token,
                    #             title="Your OTP Code",
                    #             body=f"Your OTP is {otp}. It expires in 10 minutes.",
                    #             data={"otp": otp, "type": "login"}
                    #         )
                    #     except Exception as e:
                    #         print(f"Push notification failed: {str(e)}")
                    source = "Login With Otp"
                    context = {"otp": otp, "first_name": result.get("first_name")}
                    await send_email(email, source, context)
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
                        detail="Please verify your email to activate your account",
                    )
                if user.status == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="Your account is inactive, please contact admin"
                    )

                user_data = user.dict()
                user_data["id"] = str(user.id)
                user_data.pop("password", None)
                user_data.pop("otp", None)
                access_token = create_access_token(data={"sub": user.email})
                refresh_token = create_refresh_token(data={"sub": user.email})

            if phone:
                result = await user_collection.find_one({"phone": phone})
                if not result:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid phone number")
                if is_login_with_otp:
                    if not result.get("is_active", False):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Please verify your phone to activate your account",
                        )
                    if result.get("status") == "inactive":
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Your account is inactive, please contact admin",
                        )

                    otp = generate_otp()
                    await user_collection.update_one(
                        {"phone": phone},
                        {"$set": {"login_otp": otp, "login_otp_expires": datetime.utcnow() + timedelta(minutes=10)}},
                    )
                    # device_token = result.get("device_token")
                    # if device_token:
                    #     try:
                    #         await send_push_notification(
                    #             device_token=device_token,
                    #             title="Your OTP Code",
                    #             body=f"Your OTP is {otp}. It expires in 10 minutes.",
                    #             data={"otp": otp, "type": "login"}
                    #         )
                    #     except Exception as e:
                    #         print(f"Push notification failed: {str(e)}")
                    await send_sms_on_phone(phone, otp, expiry_minutes=10)
                    return {"message": "OTP sent to your phone"}

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
                user = await User.find_one(User.phone == phone)
                if user is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User data not found")
                if not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Please verify your phone to activate your account",
                    )
                if user.status == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="Your account is inactive, please contact admin"
                    )

                user_data = user.dict()
                user_data["id"] = str(user.id)
                user_data.pop("password", None)
                user_data.pop("otp", None)
                access_token = create_access_token(data={"sub": str(user.phone)})
                refresh_token = create_refresh_token(data={"sub": str(user.phone)})

            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def resend_otp(
        self, email: Optional[str] = None, phone: Optional[int] = None, otp_type: Optional[str] = None
    ) -> str:
        """Send OTP to the user's email or phone based on the specified otp_type."""
        try:
            if otp_type not in ["login", "forgot_password", "sign_up"]:
                raise HTTPException(status_code=400, detail="Invalid OTP type. Must be 'login' or 'forgot_password'")

            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            otp_field = f"{otp_type}_otp"
            otp_expires_field = f"{otp_type}_otp_expires"

            if email:
                user = await user_collection.find_one({"email": email})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found")

                source = "Resend OTP"
                context = {"otp": otp, "user_name": user.get("first_name")}
                to_email = email
                await send_email(to_email, source, context)

                await user_collection.update_one(
                    {"email": email}, {"$set": {otp_field: otp, otp_expires_field: otp_expiration_time}}
                )
                return otp

            if phone:
                user = await user_collection.find_one({"phone": phone})
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")

                await send_sms_on_phone(phone, otp, expiry_minutes=10)

                await user_collection.update_one(
                    {"phone": phone}, {"$set": {otp_field: otp, otp_expires_field: otp_expiration_time}}
                )
                return otp

            raise ValueError("Either email or phone must be provided to send OTP.")
        except HTTPException as e:
            raise e
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def forgot_password(self, email: Optional[str] = None, phone: Optional[int] = None) -> dict:
        """Verify user by email or phone and send OTP."""
        try:
            otp = generate_otp()
            if email:
                # Find user using user_collection by email
                user = await user_collection.find_one({"email": email})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided email")
                if not user.get("is_active", False):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Please verify your email to activate your account",
                    )
                if user.get("status") == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="Your account is inactive, please contact admin"
                    )

                source = "Forgot Password"
                context = {"otp": otp}
                await send_email(email, source, context)

                await user_collection.update_one(
                    {"email": email},
                    {
                        "$set": {
                            "forgot_password_otp": otp,
                            "forgot_password_otp_expires": datetime.utcnow() + timedelta(minutes=10),
                        }
                    },
                )
                return {"message": "OTP sent to email", "otp": otp}  # Remove otp from response in production

            if phone:
                # Find user using user_collection by phone
                user = await user_collection.find_one({"phone": phone})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided phone")
                if not user.get("is_active", False):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Please verify your phone to activate your account",
                    )
                if user.get("status") == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="Your account is inactive, please contact admin"
                    )

                # Send OTP via SMS
                await send_sms_on_phone(phone, otp, expiry_minutes=10)

                # Store OTP in user_collection
                await user_collection.update_one(
                    {"phone": phone},
                    {
                        "$set": {
                            "forgot_password_otp": otp,
                            "forgot_password_otp_expires": datetime.utcnow() + timedelta(minutes=10),
                        }
                    },
                )
                return {"message": "OTP sent to phone", "otp": otp}  # Remove otp from response in production

            raise ValueError("Either email or phone must be provided to send OTP.")
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def validate_otp(
        self,
        email: Optional[str] = None,
        phone: Optional[int] = None,
        otp: str = None,
        otp_type: Optional[str] = None,
        device_token: Optional[str] = None,
    ) -> dict:
        """
        Validates an OTP for the specified type ('login', 'forgot_password', 'resend_otp').
        """
        try:
            if otp_type not in ["login", "forgot_password", "resend_otp", "sign_up"]:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid OTP type. Must be 'login', 'forgot_password', 'resend_otp', or 'sign_up'",
                )

            # Determine the OTP field and expiration field based on otp_type
            otp_field = f"{otp_type}_otp"
            otp_expires_field = f"{otp_type}_otp_expires"

            device_token_update = {}
            if device_token:
                device_token_update["device_token"] = device_token
            if email:
                user = await user_collection.find_one({"email": email})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided email")

                # Check the OTP
                stored_otp = user.get(otp_field)
                expires_at = user.get(otp_expires_field)
                if stored_otp != otp:
                    raise HTTPException(status_code=400, detail=f"Invalid OTP for {otp_type}")
                if expires_at and datetime.utcnow() > expires_at:
                    raise HTTPException(status_code=400, detail=f"OTP for {otp_type} has expired")
                if not user.get("device_token"):
                    await user_collection.update_one(
                        {"email": email},
                        {
                            "$set": {
                                "device_token": device_token,
                            }
                        },
                    )
                # Clear the OTP fields after successful validation
                await user_collection.update_one(
                    {"email": email},
                    {
                        "$unset": {otp_field: 1, otp_expires_field: 1},
                        "$set": {
                            "is_active": True if otp_type == "sign_up" else user.get("is_active"),
                            **device_token_update,
                        },
                    },
                )

                user_data = user.copy()
                user_data.pop("password", None)
                user_data.pop("forgot_password_otp", None)
                user_data.pop("forgot_password_otp_expires", None)
                user_data.pop("login_otp", None)
                user_data.pop("login_otp_expires", None)
                user_data.pop("resend_otp", None)
                user_data.pop("resend_otp_expires", None)
                user_data.pop("otp_expires", None)
                user_data.pop("sign_up_otp", None)
                user_data.pop("sign_up_otp_expires", None)
                user_data["id"] = str(user_data.pop("_id"))
                if "vendor_id" in user_data and user_data["vendor_id"]:
                    user_data["vendor_id"] = str(user_data["vendor_id"])  # Convert ObjectId to string

                # Add vendor data if applicable
                if "vendor_id" in user_data and user_data["vendor_id"]:
                    vendor = await vendor_collection.find_one({"_id": ObjectId(user_data["vendor_id"])})
                    if vendor:
                        vendor_data = vendor.copy()
                        vendor_data["id"] = str(vendor_data.pop("_id"))
                        # Convert nested ObjectId fields to strings
                        vendor_data["category_id"] = (
                            str(vendor_data.get("category_id")) if vendor_data.get("category_id") else None
                        )
                        if "services" in vendor_data:
                            for service in vendor_data["services"]:
                                service["id"] = str(service["id"]) if "id" in service else None
                        user_data["is_subscription"] = vendor_data.get("is_subscription", False)
                        user_data["business_type"] = vendor_data.get("business_type", None)
                        user_data["vendor_details"] = vendor_data  # Optionally include vendor details

                access_token = create_access_token(data={"sub": str(user.get("email"))})
                refresh_token = create_refresh_token(data={"sub": str(user.get("email"))})
                return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

            if phone:
                user = await user_collection.find_one({"phone": phone})
                if user is None:
                    raise HTTPException(status_code=404, detail="User not found with the provided phone")

                # Check the OTP
                stored_otp = user.get(otp_field)
                expires_at = user.get(otp_expires_field)
                if stored_otp != otp:
                    raise HTTPException(status_code=400, detail=f"Invalid OTP for {otp_type}")
                if expires_at and datetime.utcnow() > expires_at:
                    raise HTTPException(status_code=400, detail=f"OTP for {otp_type} has expired")
                if not user.get("device_token"):
                    await user_collection.update_one(
                        {"phone": phone},
                        {
                            "$set": {
                                "device_token": device_token,
                            }
                        },
                    )

                await user_collection.update_one(
                    {"phone": phone},
                    {
                        "$set": {
                            otp_field: None,
                            otp_expires_field: None,
                            "is_active": True if otp_type == "sign_up" else user.get("is_active"),
                            **device_token_update,
                        }
                    },
                )

                user_data = user.copy()
                user_data["id"] = str(user_data.pop("_id"))
                user_data.pop("password", None)
                user_data.pop("forgot_password_otp", None)
                user_data.pop("forgot_password_otp_expires", None)
                user_data.pop("login_otp", None)
                user_data.pop("login_otp_expires", None)
                user_data.pop("resend_otp", None)
                user_data.pop("resend_otp_expires", None)
                user_data.pop("otp_expires", None)
                user_data.pop("sign_up_otp", None)
                user_data.pop("sign_up_otp_expires", None)
                if "vendor_id" in user_data and user_data["vendor_id"]:
                    user_data["vendor_id"] = str(user_data["vendor_id"])  # Convert ObjectId to string

                # Add vendor data if applicable
                if "vendor_id" in user_data and user_data["vendor_id"]:
                    vendor = await vendor_collection.find_one({"_id": ObjectId(user_data["vendor_id"])})
                    if vendor:
                        vendor_data = vendor.copy()
                        vendor_data["id"] = str(vendor_data.pop("_id"))
                        # Convert nested ObjectId fields to strings
                        vendor_data["category_id"] = (
                            str(vendor_data.get("category_id")) if vendor_data.get("category_id") else None
                        )
                        if "services" in vendor_data:
                            for service in vendor_data["services"]:
                                service["id"] = str(service["id"]) if "id" in service else None
                        user_data["is_subscription"] = vendor_data.get("is_subscription", False)
                        user_data["business_type"] = vendor_data.get("business_type", None)
                        user_data["vendor_details"] = vendor_data  # Optionally include vendor details

                access_token = create_access_token(data={"sub": str(user.get("phone"))})
                refresh_token = create_refresh_token(data={"sub": str(user.get("phone"))})
                return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

            raise HTTPException(status_code=400, detail="Either email or phone must be provided")
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def reset_password(
        self, email: Optional[str] = None, phone: Optional[int] = None, password: str = None
    ) -> dict:
        try:
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
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_profile(self, current_user: User, profile_update_request: UpdateProfileRequest):
        try:
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
            if profile_update_request.costumer_details is not None:
                update_data["costumer_details"] = profile_update_request.costumer_details
            if profile_update_request.blood_group is not None:
                update_data["blood_group"] = profile_update_request.blood_group
            if profile_update_request.address is not None:
                update_data["address"] = profile_update_request.address.dict()
            if profile_update_request.costumer_address is not None:
                update_data["costumer_address"] = profile_update_request.costumer_address
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
                    "icon": category["icon"] if "icon" in category else None,
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

    async def get_service_list_for_category(self, category_slug: str) -> dict:
        try:
            if not category_slug:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid category slug")

            # Fetch category
            category = await category_collection.find_one({"slug": category_slug})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
            category_id = str(category["_id"])

            # Pipeline to get search counts for all services in the category
            search_count_pipeline = [
                {"$match": {"category_id": PydanticObjectId(category_id)}},
                {"$group": {"_id": "$service_id", "search_count": {"$sum": 1}}},
                {
                    "$lookup": {
                        "from": "services",
                        "let": {"service_id": "$_id"},
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {"$eq": ["$_id", "$$service_id"]},
                                    "category_id": PydanticObjectId(category_id),
                                    "status": "active",
                                }
                            },
                            {
                                "$project": {
                                    "_id": {"$toString": "$_id"},
                                    "name": 1,
                                    "status": 1,
                                }
                            },
                        ],
                        "as": "service_info",
                    }
                },
                {"$unwind": "$service_info"},
                {
                    "$project": {
                        "id": {"$toString": "$_id"},
                        "name": "$service_info.name",
                        "status": "$service_info.status",
                        "search_count": 1,
                    }
                },
            ]

            # Fetch all services with their search counts
            search_results = await search_query_collection.aggregate(search_count_pipeline).to_list(length=None)
            service_counts = {service["id"]: service["search_count"] for service in search_results}

            # Fetch all active services for the category
            active_services = await services_collection.find(
                {"category_id": category["_id"], "status": "active"}
            ).to_list(length=None)
            service_data = [
                {
                    "id": str(service["_id"]),
                    "name": service["name"],
                    "status": service["status"],
                    "search_count": service_counts.get(str(service["_id"]), 0),  # Default to 0 if not searched
                }
                for service in active_services
            ]

            # Sort services by search_count descending and take top 3 for top_services
            top_services_data = sorted(service_data, key=lambda x: (-x["search_count"], x["id"]))[:3]
            top_services_data = [
                {"id": service["id"], "name": service["name"], "search_count": service["search_count"]}
                for service in top_services_data
            ]

            return {"services": service_data, "top_services": top_services_data}
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_vendor_list_for_category(
        self,
        request: Request,
        category_slug: str,
        current_user: Optional[User] = None,
        service_id: Optional[str] = None,
        address: Optional[str] = None,
        date: Optional[date] = None,
        page: int = 1,
        limit: int = 10,
    ) -> dict:
        try:
            skip = (page - 1) * limit
            if not category_slug:
                raise HTTPException(status_code=400, detail="Invalid category slug")

            category = await category_collection.find_one({"slug": category_slug})
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            category_id = str(category["_id"])

            vendor_filter = {"category_id": category_id, "status": "active", "is_subscription": True}

            if service_id:
                if not ObjectId.is_valid(service_id):
                    raise HTTPException(status_code=400, detail="Invalid service ID")
                service = await services_collection.find_one({"_id": ObjectId(service_id), "status": "active"})
                if not service:
                    raise HTTPException(status_code=404, detail="Service not found")
                vendor_filter["services.id"] = service_id

            current_date = date if date else datetime.now().date()
            date_range = [current_date + timedelta(days=i) for i in range(7)]
            date_strings = [d.strftime("%Y-%m-%d") for d in date_range]
            day_names = [d.strftime("%A") for d in date_range]

            current_user_id = str(current_user.id) if current_user else None
            user_location = None

            if current_user:
                user = await user_collection.find_one({"_id": current_user.id})
                if user and "user_location" in user and user["user_location"]["type"] == "Point":
                    user_location = user["user_location"]
            if address and address.strip():
                address_terms = [term.strip() for term in address.split(",") if term.strip()]
                matching_vendor_query = {
                    "$and": [
                        {"location.formatted_address": {"$regex": re.escape(term), "$options": "i"}}
                        for term in address_terms
                    ]
                }

                matching_vendor = await vendor_collection.find_one(matching_vendor_query)

                address_location = {
                    "type": "Point",
                    "coordinates": [
                        matching_vendor["location"]["geometry"]["location"]["lng"],
                        matching_vendor["location"]["geometry"]["location"]["lat"],
                    ],
                }
                radius_km = 20
                radius_radians = radius_km / 6378.1

                pipeline = [
                    {"$match": vendor_filter},
                    {
                        "$addFields": {
                            "geo_point": {
                                "type": "Point",
                                "coordinates": ["$location.geometry.location.lng", "$location.geometry.location.lat"],
                            }
                        }
                    },
                    {
                        "$match": {
                            "geo_point": {
                                "$geoWithin": {"$centerSphere": [address_location["coordinates"], radius_radians]}
                            }
                        }
                    },
                ]

            elif user_location:
                radius_km = 20
                radius_radians = radius_km / 6378.1
                pipeline = [
                    {"$match": vendor_filter},
                    {
                        "$addFields": {
                            "geo_point": {
                                "type": "Point",
                                "coordinates": [
                                    "$location.geometry.location.lng",
                                    "$location.geometry.location.lat",
                                ],
                            }
                        }
                    },
                    {
                        "$match": {
                            "geo_point": {
                                "$geoWithin": {"$centerSphere": [user_location["coordinates"], radius_radians]}
                            }
                        }
                    },
                ]
            else:

                ip_address = request.query_params.get("ipAddress")
                if ip_address:
                    geo = geocoder.ip(ip_address)
                    if geo.ok and geo.latlng:
                        ip_location = {
                            "type": "Point",
                            "coordinates": [geo.lng, geo.lat],
                        }
                        radius_km = 20
                        radius_radians = radius_km / 6378.1
                        pipeline = [
                            {"$match": vendor_filter},
                            {
                                "$addFields": {
                                    "geo_point": {
                                        "type": "Point",
                                        "coordinates": [
                                            "$location.geometry.location.lng",
                                            "$location.geometry.location.lat",
                                        ],
                                    }
                                }
                            },
                            {
                                "$match": {
                                    "geo_point": {
                                        "$geoWithin": {"$centerSphere": [ip_location["coordinates"], radius_radians]}
                                    }
                                }
                            },
                        ]
                    else:
                        raise HTTPException(status_code=500, detail="Failed to geolocate IP address")
                else:
                    pipeline = [{"$match": vendor_filter}]

            if service_id or address:
                search_query = {
                    "user_id": ObjectId(current_user_id) if current_user_id else None,
                    "category_id": ObjectId(category_id),
                    "service_id": ObjectId(service_id) if service_id else None,
                    "location": address if address else None,
                }
                await search_query_collection.insert_one(search_query)

            pipeline.extend(
                [
                    {
                        "$lookup": {
                            "from": "users",
                            "let": {"vendor_id": {"$toObjectId": "$_id"}},
                            "pipeline": [
                                {"$match": {"$expr": {"$eq": ["$vendor_id", "$$vendor_id"]}}},
                                {
                                    "$project": {
                                        "_id": 0,
                                        "id": {"$toString": "$_id"},
                                        "first_name": 1,
                                        "last_name": 1,
                                        "email": 1,
                                        "phone": 1,
                                        "user_image": 1,
                                        "user_image_url": 1,
                                        "specialization": 1,
                                        "fees": 1,
                                        "roles": 1,
                                        "availability_slots": 1,
                                    }
                                },
                                {"$match": {"availability_slots": {"$exists": True, "$ne": []}}},
                            ],
                            "as": "vendor_user",
                        }
                    },
                    {
                        "$lookup": {
                            "from": "users",
                            "let": {"vendor_id": {"$toObjectId": "$_id"}},
                            "pipeline": [
                                {"$match": {"$expr": {"$eq": ["$vendor_id", "$$vendor_id"]}}},
                                {
                                    "$project": {
                                        "_id": 0,
                                        "id": {"$toString": "$_id"},
                                        "first_name": 1,
                                        "last_name": 1,
                                        "email": 1,
                                        "phone": 1,
                                        "roles": 1,
                                        "user_image": 1,
                                        "user_image_url": 1,
                                        "specialization": 1,
                                        "fees": 1,
                                        "availability_slots": 1,
                                    }
                                },
                                {"$match": {"availability_slots": {"$exists": True, "$ne": []}}},
                            ],
                            "as": "created_users",
                        }
                    },
                    {"$unwind": {"path": "$created_users", "preserveNullAndEmptyArrays": True}},
                    {
                        "$lookup": {
                            "from": "vendor_services",
                            "let": {
                                "vendor_id": {"$toObjectId": "$_id"},
                                "vendor_user_id": {"$toObjectId": "$created_users.id"},
                            },
                            "pipeline": [
                                {
                                    "$match": {
                                        "$expr": {
                                            "$and": [
                                                {"$eq": ["$vendor_id", "$$vendor_id"]},
                                                {"$eq": ["$vendor_user_id", "$$vendor_user_id"]},
                                            ]
                                        }
                                    }
                                },
                                {
                                    "$project": {
                                        "_id": {"$toString": "$_id"},
                                        "services": {
                                            "$map": {
                                                "input": "$services",
                                                "as": "service",
                                                "in": {
                                                    "id": {
                                                        "$ifNull": [
                                                            {"$toString": "$$service.service_id"},
                                                            "$$service.id",
                                                        ]
                                                    },
                                                    "name": {"$ifNull": ["$$service.service_name", "$$service.name"]},
                                                    "service_image": "$$service.service_image",
                                                    "service_image_url": "$$service.service_image_url",
                                                },
                                            }
                                        },
                                    }
                                },
                            ],
                            "as": "vendor_service",
                        }
                    },
                    {"$unwind": {"path": "$vendor_service", "preserveNullAndEmptyArrays": True}},
                    {
                        "$lookup": {
                            "from": "bookings",
                            "let": {
                                "vendor_id": {"$toObjectId": "$_id"},
                                "business_type": "$business_type",
                                "created_users_ids": {
                                    "$ifNull": [
                                        {
                                            "$cond": [
                                                {"$isArray": "$created_users.id"},
                                                "$created_users.id",
                                                ["$created_users.id"],
                                            ]
                                        },
                                        [],
                                    ]
                                },
                                "vendor_user_ids": {
                                    "$ifNull": [
                                        {
                                            "$cond": [
                                                {"$isArray": "$vendor_user.id"},
                                                "$vendor_user.id",
                                                ["$vendor_user.id"],
                                            ]
                                        },
                                        [],
                                    ]
                                },
                            },
                            "pipeline": [
                                {
                                    "$match": {
                                        "$expr": {
                                            "$and": [
                                                {"$eq": [{"$toObjectId": "$vendor_id"}, "$$vendor_id"]},
                                                {"$eq": ["$payment_status", "paid"]},
                                                {"$in": ["$booking_date", date_strings]},
                                                {
                                                    "$or": [
                                                        {
                                                            "$and": [
                                                                {"$eq": ["$$business_type", "business"]},
                                                                {"$in": ["$vendor_user_id", "$$created_users_ids"]},
                                                            ]
                                                        },
                                                        {
                                                            "$and": [
                                                                {"$ne": ["$$business_type", "business"]},
                                                                {"$in": ["$vendor_user_id", "$$vendor_user_ids"]},
                                                            ]
                                                        },
                                                    ]
                                                },
                                            ]
                                        }
                                    }
                                },
                                {
                                    "$project": {
                                        "_id": {"$toString": "$_id"},
                                        "booking_date": 1,
                                        "seat_count": 1,
                                        "vendor_user_id": {"$toString": "$vendor_user_id"},
                                        "time_slot": 1,
                                    }
                                },
                            ],
                            "as": "bookings",
                        }
                    },
                    {
                        "$project": {
                            "_id": {"$toString": "$_id"},
                            "vendor_id": {"$toString": "$_id"},
                            "business_name": 1,
                            "business_type": 1,
                            "business_address": 1,
                            "business_details": 1,
                            "is_payment_required": 1,
                            "category_id": {"$toString": "$category_id"},
                            "services": "$vendor_service.services",
                            "location": 1,
                            "created_users": 1,
                            "vendor_user": {"$arrayElemAt": ["$vendor_user", 0]},
                            "booking_count": {"$size": "$bookings"},
                            "bookings": {
                                "$map": {
                                    "input": "$bookings",
                                    "as": "booking",
                                    "in": {
                                        "date": "$$booking.booking_date",
                                        "seat_count": {"$ifNull": ["$$booking.seat_count", 1]},
                                        "vendor_user_id": "$$booking.vendor_user_id",
                                        "time_slot": "$$booking.time_slot",
                                    },
                                }
                            },
                        }
                    },
                    {"$unwind": {"path": "$created_users", "preserveNullAndEmptyArrays": True}},
                    {
                        "$addFields": {
                            "user_details": {
                                "$cond": {
                                    "if": {"$eq": ["$business_type", "business"]},
                                    "then": "$created_users",
                                    "else": "$vendor_user",
                                }
                            }
                        }
                    },
                    {
                        "$lookup": {
                            "from": "vendor_ratings",
                            "let": {"user_details_id": "$user_details.id"},
                            "pipeline": [
                                {"$match": {"$expr": {"$eq": ["$vendor_id", "$$user_details_id"]}}},
                                {
                                    "$project": {
                                        "_id": {"$toString": "$_id"},
                                        "rating": 1,
                                        "review": 1,
                                        "user_id": {"$toString": "$user_id"},
                                    }
                                },
                            ],
                            "as": "ratings",
                        }
                    },
                    {
                        "$addFields": {
                            "average_rating": {
                                "$cond": {
                                    "if": {"$gt": [{"$size": "$ratings"}, 0]},
                                    "then": {"$divide": [{"$sum": "$ratings.rating"}, {"$size": "$ratings"}]},
                                    "else": 0,
                                }
                            },
                            "current_user_rating": {
                                "$cond": [
                                    {
                                        "$or": [
                                            {"$eq": [current_user_id, None]},
                                            {
                                                "$eq": [
                                                    {
                                                        "$size": {
                                                            "$filter": {
                                                                "input": "$ratings",
                                                                "as": "rating",
                                                                "cond": {"$eq": ["$$rating.user_id", current_user_id]},
                                                            }
                                                        }
                                                    },
                                                    0,
                                                ]
                                            },
                                        ]
                                    },
                                    None,
                                    {
                                        "$arrayElemAt": [
                                            {
                                                "$filter": {
                                                    "input": "$ratings",
                                                    "as": "rating",
                                                    "cond": {"$eq": ["$$rating.user_id", current_user_id]},
                                                }
                                            },
                                            0,
                                        ]
                                    },
                                ]
                            },
                        }
                    },
                    {"$sort": {"average_rating": -1}},
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
                                                        "$let": {
                                                            "vars": {
                                                                "max_seat_count": {
                                                                    "$reduce": {
                                                                        "input": "$$slot.time_slots",
                                                                        "initialValue": 0,
                                                                        "in": {"$add": ["$$value", "$$this.max_seat"]},
                                                                    }
                                                                },
                                                                "daily_booking_count": {
                                                                    "$reduce": {
                                                                        "input": {
                                                                            "$filter": {
                                                                                "input": "$bookings",
                                                                                "as": "booking",
                                                                                "cond": {
                                                                                    "$and": [
                                                                                        {
                                                                                            "$eq": [
                                                                                                "$$booking.date",
                                                                                                "$$this",
                                                                                            ]
                                                                                        },
                                                                                        {
                                                                                            "$eq": [
                                                                                                "$$booking.vendor_user_id",
                                                                                                "$user_details.id",
                                                                                            ]
                                                                                        },
                                                                                    ]
                                                                                },
                                                                            }
                                                                        },
                                                                        "initialValue": 0,
                                                                        "in": {
                                                                            "$add": [
                                                                                "$$value",
                                                                                {"$ifNull": ["$$this.seat_count", 1]},
                                                                            ]
                                                                        },
                                                                    }
                                                                },
                                                            },
                                                            "in": {
                                                                "$mergeObjects": [
                                                                    "$$slot",
                                                                    {
                                                                        "date": "$$this",
                                                                        "daily_booking_count": "$$daily_booking_count",
                                                                        "daily_bookings_left": {
                                                                            "$subtract": [
                                                                                {"$ifNull": ["$$max_seat_count", 0]},
                                                                                {
                                                                                    "$ifNull": [
                                                                                        "$$daily_booking_count",
                                                                                        0,
                                                                                    ]
                                                                                },
                                                                            ]
                                                                        },
                                                                        "max_seat_count": "$$max_seat_count",
                                                                        "time_slots": {
                                                                            "$map": {
                                                                                "input": "$$slot.time_slots",
                                                                                "as": "time_slot",
                                                                                "in": {
                                                                                    "$let": {
                                                                                        "vars": {
                                                                                            "booking_count": {
                                                                                                "$reduce": {
                                                                                                    "input": {
                                                                                                        "$filter": {
                                                                                                            "input": "$bookings",
                                                                                                            "as": "booking",
                                                                                                            "cond": {
                                                                                                                "$and": [
                                                                                                                    {
                                                                                                                        "$eq": [
                                                                                                                            "$$booking.date",
                                                                                                                            "$$this",
                                                                                                                        ]
                                                                                                                    },
                                                                                                                    {
                                                                                                                        "$eq": [
                                                                                                                            "$$booking.vendor_user_id",
                                                                                                                            "$user_details.id",
                                                                                                                        ]
                                                                                                                    },
                                                                                                                    {
                                                                                                                        "$eq": [
                                                                                                                            {
                                                                                                                                "$arrayElemAt": [
                                                                                                                                    {
                                                                                                                                        "$split": [
                                                                                                                                            "$$booking.time_slot",
                                                                                                                                            " - ",
                                                                                                                                        ]
                                                                                                                                    },
                                                                                                                                    0,
                                                                                                                                ]
                                                                                                                            },
                                                                                                                            "$$time_slot.start_time",
                                                                                                                        ]
                                                                                                                    },
                                                                                                                ]
                                                                                                            },
                                                                                                        }
                                                                                                    },
                                                                                                    "initialValue": 0,
                                                                                                    "in": {
                                                                                                        "$add": [
                                                                                                            "$$value",
                                                                                                            {
                                                                                                                "$ifNull": [
                                                                                                                    "$$this.seat_count",
                                                                                                                    1,
                                                                                                                ]
                                                                                                            },
                                                                                                        ]
                                                                                                    },
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "in": {
                                                                                            "$mergeObjects": [
                                                                                                "$$time_slot",
                                                                                                {
                                                                                                    "booking_count": "$$booking_count",
                                                                                                    "bookings_left": {
                                                                                                        "$subtract": [
                                                                                                            "$$time_slot.max_seat",
                                                                                                            "$$booking_count",
                                                                                                        ]
                                                                                                    },
                                                                                                },
                                                                                            ]
                                                                                        },
                                                                                    }
                                                                                },
                                                                            }
                                                                        },
                                                                    },
                                                                ]
                                                            },
                                                        }
                                                    },
                                                }
                                            },
                                        ]
                                    },
                                }
                            }
                        }
                    },
                    {
                        "$match": {
                            "$and": [
                                {"user_details.availability_slots": {"$ne": None}},
                                {"user_details.availability_slots": {"$ne": []}},
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
                            "user_details": 1,
                            "booking_count": 1,
                            "average_rating": 1,
                            "current_user_rating": 1,
                        }
                    },
                    {"$skip": skip},
                    {"$limit": limit},
                ]
            )

            active_vendors = await vendor_collection.aggregate(pipeline).to_list(length=None)
            if not active_vendors:
                raise HTTPException(
                    status_code=404,
                    detail="No active vendors found for the given "
                    + ("location" if address else "category")
                    + (f" and service" if service_id else ""),
                )

            total_vendors = await vendor_collection.count_documents(
                {
                    "location.formatted_address": {"$regex": f"^{re.escape(address.strip())}$", "$options": "i"},
                    **vendor_filter,
                }
                if address and address.strip()
                else vendor_filter
            )
            total_pages = (total_vendors + limit - 1) // limit

            return {"items": active_vendors, "total_pages": total_pages, "total_items": total_vendors}

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def create_support_request(self, support_request: Support, background_tasks: BackgroundTasks):
        try:
            # Insert into MongoDB
            result = await support_collection.insert_one(support_request.dict())
            if not result.inserted_id:  # Check inserted_id instead of result directly
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Support request not found")

            # Prepare response data
            result_data = {
                "id": str(result.inserted_id),
                "name": support_request.name,
                "email": support_request.email,
                "subject": support_request.subject,
                "phone": support_request.phone,
                "message": support_request.message,
                "country": support_request.country,
                "state": support_request.state,
                "city": support_request.city,
                "zipcode": support_request.zipcode,
                "created_at": support_request.created_at,
            }

            # Offload email sending to background tasks
            customer_email_context = {
                "name": support_request.name,
                "subject": support_request.subject,
                "message": support_request.message,
                "phone": support_request.phone,
                "email": support_request.email,
                "country": support_request.country,
                "state": support_request.state,
                "city": support_request.city,
                "zipcode": support_request.zipcode,
                "created_at": support_request.created_at,
                "website": "https://fast2book.com",
            }
            support_email_context = {
                "name": support_request.name,
                "subject": support_request.subject,
                "message": support_request.message,
                "phone": support_request.phone,
                "email": support_request.email,
                "country": support_request.country,
                "state": support_request.state,
                "city": support_request.city,
                "zipcode": support_request.zipcode,
                "created_at": support_request.created_at,
            }

            # Add email sending tasks to background
            background_tasks.add_task(send_email, support_request.email, "Support Request", customer_email_context)
            background_tasks.add_task(send_email, "support@fast2book.com", "New Support Request", support_email_context)

            # Return response immediately
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

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
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

    async def change_password(self, current_user: User, old_password: str, new_password: str):
        try:
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

    async def google_login(self, request: Request, payload: dict):
        try:
            token = payload.get("access_token")
            email = payload.get("email")
            first_name = payload.get("given_name", "Unknown")
            last_name = payload.get("family_name", "Unknown")
            picture = payload.get("picture", "")

            # Validate required fields

            # Get or create the user
            current_user = await get_current_user_by_google(
                request=request,
                token=token,
                email=email,
                first_name=first_name,
                last_name=last_name,
                picture=picture,
            )

            if not current_user:
                raise HTTPException(status_code=401, detail="Unauthorized")

            return current_user

        except HTTPException as ex:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def blog_list(self, page: int = 1, limit: int = 10, search: str = None, category: str = None) -> dict:
        """
        Get list of all active blogs, optionally filtered by search term and category.
        """
        try:
            skip = (page - 1) * limit
            query = {"status": "active"}

            # Add search filter if search term is provided
            if search:
                search_regex = {"$regex": search, "$options": "i"}  # Case-insensitive search
                query["$or"] = [
                    {"title": search_regex},
                    {"content": search_regex},
                ]

            # Add category filter if category is provided
            if category:
                query["category"] = category  # Filter by exact category name

            # Fetch blogs based on the query
            active_blogs = await blog_collection.find(query).skip(skip).limit(limit).to_list(length=100)
            # Format the response
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

            # Count total blogs matching the query
            total_blogs = await blog_collection.count_documents(query)
            total_pages = (total_blogs + limit - 1) // limit

            # Return the formatted response
            return {"data": blog_data, "total_pages": total_pages, "total_items": total_blogs}
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
            existing_blog = await blog_collection.find_one({"_id": ObjectId(id), "status": "active"})
            if not existing_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog not found or is not active")

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
                await blog_collection.find({"_id": {"$ne": ObjectId(id)}, "status": "active"})
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
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_notifications_list(self, current_user: User) -> dict:
        try:
            notifications = current_user.notification_settings

            return notifications

        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def update_notification(self, request: Request, current_user: User) -> dict:
        try:
            # Get the update data from the request body
            update_data = await request.json()
            if not update_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No data provided for update")

            # Validate the update data
            valid_keys = {"booking_confirmation", "payment_confirmation"}
            if not all(key in valid_keys for key in update_data.keys()):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid notification settings provided"
                )

            # Update the notification settings in the current user object
            for key, value in update_data.items():
                if key in current_user.notification_settings:
                    current_user.notification_settings[key] = value

            # Update the notification settings in the database
            await user_collection.update_one(
                {"_id": current_user.id},  # Filter by user ID
                {
                    "$set": {"notification_settings": current_user.notification_settings}
                },  # Update the notification settings
            )

            return current_user.notification_settings

        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_vendor_list(self, request: Request, current_user: Optional[User] = None):
        try:
            user = current_user
            ipaddress = request.query_params.get("ipAddress")
            geo_filter = []
            radius_km = 20
            radius_radians = radius_km / 6378.1

            if user and user.user_location:
                user_location = user.user_location
                geo_filter = [
                    {
                        "$addFields": {
                            "geo_point": {
                                "type": "Point",
                                "coordinates": [
                                    {"$toDouble": "$location.geometry.location.lng"},
                                    {"$toDouble": "$location.geometry.location.lat"},
                                ],
                            }
                        }
                    },
                    {
                        "$match": {
                            "geo_point": {
                                "$geoWithin": {"$centerSphere": [user_location["coordinates"], radius_radians]}
                            }
                        }
                    },
                ]
            elif ipaddress:
                geo = geocoder.ip(ipaddress)
                if geo.ok and geo.latlng:
                    ip_location = {
                        "type": "Point",
                        "coordinates": [geo.lng, geo.lat],
                    }
                    geo_filter = [
                        {
                            "$addFields": {
                                "geo_point": {
                                    "type": "Point",
                                    "coordinates": [
                                        {"$toDouble": "$location.geometry.location.lng"},
                                        {"$toDouble": "$location.geometry.location.lat"},
                                    ],
                                }
                            }
                        },
                        {
                            "$match": {
                                "geo_point": {
                                    "$geoWithin": {"$centerSphere": [ip_location["coordinates"], radius_radians]}
                                }
                            }
                        },
                    ]
                else:
                    raise HTTPException(status_code=500, detail=f"Failed to geolocate IP address: {ipaddress}")

            search_pipeline = [
                {
                    "$group": {
                        "_id": {"category_id": "$category_id", "service_id": "$service_id"},
                        "search_count": {"$sum": 1},
                    }
                },
                {"$sort": {"search_count": -1}},
                {
                    "$group": {
                        "_id": "$_id.category_id",
                        "services": {
                            "$push": {"service_id": {"$toString": "$_id.service_id"}, "search_count": "$search_count"}
                        },
                    }
                },
                {
                    "$project": {
                        "_id": {"$toString": "$_id"},
                        "services": {"$slice": ["$services", 4]},  # Limit to top 4 services
                    }
                },
            ]

            # Execute search pipeline
            search_cursor = search_query_collection.aggregate(search_pipeline)
            search_results = await search_cursor.to_list(length=None)
            top_services_by_category = {
                item["_id"]: {service["service_id"]: service["search_count"] for service in item["services"]}
                for item in search_results
            }
            print("Top services by category:", top_services_by_category)

            pipeline = [
                {"$match": {"status": "active"}},
                {
                    "$lookup": {
                        "from": "services",
                        "let": {"category_id": {"$toString": "$_id"}},
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {"$eq": [{"$toString": "$category_id"}, "$$category_id"]},
                                    "status": "active",
                                }
                            },
                            {
                                "$project": {
                                    "_id": {"$toString": "$_id"},
                                    "name": 1,
                                    "service_image": 1,
                                    "service_image_url": 1,
                                    "category_name": 1,
                                    "category_slug": 1,
                                    "category_id": "$$category_id",
                                }
                            },
                        ],
                        "as": "services",
                    }
                },
                {
                    "$lookup": {
                        "from": "vendors",
                        "let": {"category_id_str": {"$toString": "$_id"}},
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {"$eq": ["$category_id", "$$category_id_str"]},
                                    "status": "active",
                                    "is_subscription": True,
                                }
                            },
                            *geo_filter,
                            {
                                "$lookup": {
                                    "from": "users",
                                    "let": {"vendor_id": {"$toString": "$_id"}},
                                    "pipeline": [
                                        {"$match": {"$expr": {"$eq": [{"$toString": "$vendor_id"}, "$$vendor_id"]}}},
                                        {"$match": {"roles": "vendor_user"}},
                                        {
                                            "$project": {
                                                "_id": {"$toString": "$_id"},
                                                "first_name": 1,
                                                "last_name": 1,
                                                "user_image": 1,
                                                "user_image_url": 1,
                                            }
                                        },
                                    ],
                                    "as": "creator_user",
                                }
                            },
                            {
                                "$lookup": {
                                    "from": "users",
                                    "let": {"vendor_id": {"$toString": "$_id"}},
                                    "pipeline": [
                                        {"$match": {"$expr": {"$eq": [{"$toString": "$vendor_id"}, "$$vendor_id"]}}},
                                        {
                                            "$project": {
                                                "_id": {"$toString": "$_id"},
                                                "first_name": 1,
                                                "last_name": 1,
                                                "user_image": 1,
                                                "user_image_url": 1,
                                            }
                                        },
                                    ],
                                    "as": "vendor_user",
                                }
                            },
                            {
                                "$facet": {
                                    "business_vendors": [
                                        {"$match": {"business_type": "business"}},
                                        {"$unwind": "$creator_user"},
                                        {"$addFields": {"user_details": "$creator_user"}},
                                    ],
                                    "non_business_vendors": [
                                        {"$match": {"business_type": {"$ne": "business"}}},
                                        {"$unwind": "$vendor_user"},
                                        {"$addFields": {"user_details": "$vendor_user"}},
                                    ],
                                }
                            },
                            {
                                "$project": {
                                    "vendors": {"$concatArrays": ["$business_vendors", "$non_business_vendors"]}
                                }
                            },
                            {"$unwind": "$vendors"},
                            {"$replaceRoot": {"newRoot": "$vendors"}},
                            {
                                "$lookup": {
                                    "from": "vendor_ratings",
                                    "let": {"vendor_user_id": "$user_details._id"},
                                    "pipeline": [
                                        {"$match": {"$expr": {"$eq": ["$vendor_id", "$$vendor_user_id"]}}},
                                        {
                                            "$project": {
                                                "_id": {"$toString": "$_id"},
                                                "rating": 1,
                                                "user_id": {"$toString": "$user_id"},
                                            }
                                        },
                                    ],
                                    "as": "ratings",
                                }
                            },
                            {
                                "$addFields": {
                                    "average_rating": {
                                        "$cond": {
                                            "if": {"$gt": [{"$size": "$ratings"}, 0]},
                                            "then": {"$divide": [{"$sum": "$ratings.rating"}, {"$size": "$ratings"}]},
                                            "else": 0,
                                        }
                                    },
                                    "vendor_id": "$user_details._id",
                                    "vendor_first_name": "$user_details.first_name",
                                    "vendor_last_name": "$user_details.last_name",
                                    "vendor_image": "$user_details.user_image",
                                    "vendor_image_url": "$user_details.user_image_url",
                                }
                            },
                            {
                                "$project": {
                                    "_id": {"$toString": "$_id"},
                                    "vendor_id": 1,
                                    "business_name": 1,
                                    "business_type": 1,
                                    "vendor_first_name": 1,
                                    "vendor_last_name": 1,
                                    "vendor_image": 1,
                                    "vendor_image_url": 1,
                                    "average_rating": 1,
                                }
                            },
                            {"$sort": {"average_rating": -1}},
                        ],
                        "as": "vendors",
                    }
                },
                {"$addFields": {"vendors": {"$slice": ["$vendors", 0, 4]}}},
                {
                    "$project": {
                        "_id": 0,
                        "category": "$name",
                        "category_slug": "$slug",
                        "services": "$services",
                        "vendors": {
                            "$map": {
                                "input": "$vendors",
                                "as": "vendor",
                                "in": {
                                    "vendor_id": "$$vendor.vendor_id",
                                    "business_name": "$$vendor.business_name",
                                    "business_type": "$$vendor.business_type",
                                    "vendor_first_name": "$$vendor.vendor_first_name",
                                    "vendor_last_name": "$$vendor.vendor_last_name",
                                    "vendor_image": "$$vendor.vendor_image",
                                    "vendor_image_url": "$$vendor.vendor_image_url",
                                    "average_rating": "$$vendor.average_rating",
                                },
                            }
                        },
                    }
                },
            ]

            cursor = category_collection.aggregate(pipeline)
            result = await cursor.to_list(length=100)
            data = {}
            for item in result:
                category = item["category"]
                services = item["services"]
                vendors = item["vendors"]
                category_id = next((s["category_id"] for s in services if "category_id" in s), None)
                if not category_id:
                    print(f"Warning: No category_id found for {category}")
                    continue

                print(f"Raw services for {category} (category_id: {category_id}):", services)
                # Add search_count to services
                for service in services:
                    search_count = top_services_by_category.get(category_id, {}).get(service["_id"], 0)
                    service["search_count"] = search_count
                    print(f"Service {service['_id']} ({service['name']}) search_count: {search_count}")

                # Sort by search_count descending, then _id ascending
                services.sort(key=lambda x: (-x["search_count"], x["_id"]))
                services = services[:4]  # Limit to top 4
                print(f"Sorted services for {category}:", services)

                # Format services for response
                services = [
                    {
                        "service_id": service["_id"],
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                        "category_name": service["category_name"],
                        "category_slug": service["category_slug"],
                        "search_count": service["search_count"],  # Include for debugging
                    }
                    for service in services
                ]
                data[category] = {"services": services, "vendors": vendors}

            return data
        except HTTPException:
            raise
        except Exception as ex:
            print(ex, "ddddddd")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_vendor_slot(self, request: Request, vendor_id: str, date: str = None):
        try:
            if not ObjectId.is_valid(vendor_id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vendor ID")

            vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            if not date:
                date = datetime.now().strftime("%Y-%m-%d")

            try:
                date_obj = datetime.strptime(date, "%Y-%m-%d").date()
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Use YYYY-MM-DD"
                )

            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_user.get("vendor_id"))})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor found")

            if vendor.get("business_type") == "business":
                user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
                if not user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            else:
                user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
                if not user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            slots = vendor_user.get("availability_slots")
            if not slots:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No slots found for the vendor")

            day_of_week = date_obj.strftime("%A")
            filtered_slots = None
            for slot in slots:
                if slot.get("day") == day_of_week:
                    filtered_slots = slot.get("time_slots")
                    break

            if not filtered_slots:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No slots found for {day_of_week}")

            for slot in filtered_slots:
                if "start_time" in slot and isinstance(slot["start_time"], datetime):
                    slot["start_time"] = slot["start_time"].isoformat()
                if "end_time" in slot and isinstance(slot["end_time"], datetime):
                    slot["end_time"] = slot["end_time"].isoformat()

            for slot in filtered_slots:
                slot_start_time = slot["start_time"]
                slot_end_time = slot["end_time"]

                total_bookings_for_slot = await booking_collection.count_documents(
                    {
                        "vendor_user_id": str(vendor_id),
                        "booking_date": date,
                        "payment_status": "paid",
                        "time_slot": {"$gte": slot_start_time, "$lt": slot_end_time},
                    }
                )
                slot["total_bookings"] = total_bookings_for_slot
                slot["max_seats"] = slot.get("max_seat", 0)

            vendor_data = {
                "vendor_user_id": str(vendor_user.get("_id")),
                "vendor_first_name": vendor_user.get("first_name"),
                "vendor_last_name": vendor_user.get("last_name"),
                "vendor_image": vendor_user.get("user_image"),
                "vendor_image_url": vendor_user.get("user_image_url"),
                "business_name": vendor.get("business_name"),
                "business_type": vendor.get("business_type"),
                "vendor_id": str(vendor.get("_id")),
                "services": vendor_user.get("services") if vendor_user.get("services") else vendor.get("services"),
                "category_id": (vendor.get("category_id")),
                "fess": vendor_user.get("fess"),
                "specialization": vendor_user.get("specialization"),
                "location": vendor.get("location"),
            }

            filtered_slots = [
                {
                    "start_time": slot["start_time"],
                    "end_time": slot["end_time"],
                    "duration": slot.get("duration", None),
                    "max_seats": slot.get("max_seats", 0),
                    "total_bookings": slot.get("total_bookings", 0),
                    "bookings_left": slot.get("max_seats", 0) - slot.get("total_bookings", 0),
                }
                for slot in filtered_slots
            ]

            return {
                "slots": filtered_slots,
                "vendor": vendor_data,
            }

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_category_service(self, category_slug: str, request: Request, page: int = 1, limit: int = 10):
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
                {
                    "id": str(service["_id"]),
                    "name": service["name"],
                    "status": service["status"],
                    "service_image": service["service_image"],
                    "service_image_url": service["service_image_url"],
                }
                for service in active_services
            ]

            total_services = await services_collection.count_documents(
                {"category_id": category["_id"], "status": "active"}
            )
            total_pages = (total_services + limit - 1) // limit

            service_data = {
                "services": service_data,
                "total_services": total_services,
                "total_pages": total_pages,
            }

            return service_data
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def create_ticket(
        self,
        request: Request,
        ticket_data: Ticket,
        current_user: Optional[User] = None,
        background_tasks: BackgroundTasks = None,
    ):
        try:
            if not ticket_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ticket data")

            if current_user:
                ticket_data.user = str(current_user.id)
            ticket_data.ticket_number = Ticket.generate_ticket_number()
            issue_image_url = None
            if ticket_data.issue_image:
                issue_image = ticket_data.issue_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                issue_image_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{issue_image}"
                ticket_data.issue_image_url = issue_image_url

            ticket = await ticket_collection.insert_one(ticket_data.dict())
            if ticket:
                source = "Ticket Created"
                to_email = ticket_data.email
                context = {
                    "ticket_number": ticket_data.ticket_number,
                    "ticket_type": ticket_data.ticket_type,
                    "description": ticket_data.description,
                    "email": ticket_data.email,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                }
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)
                source = "New Ticket Created"
                to_email = "support@fast2book.com"
                context = {
                    "ticket_number": ticket_data.ticket_number,
                    "ticket_type": ticket_data.ticket_type,
                    "description": ticket_data.description,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "email": ticket_data.email,
                }
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

            ticket_data = ticket_data.dict()
            ticket_data["id"] = str(ticket.inserted_id)

            return ticket_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_user_location(self, request: Request, current_user: User):
        try:
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            lat = request.query_params.get("lat")
            lng = request.query_params.get("lng")
            if not lat or not lng:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Latitude and longitude are required"
                )

            try:
                lat = float(lat)
                lng = float(lng)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid latitude or longitude values"
                )

            current_user_doc = await user_collection.find_one({"_id": current_user.id})
            if not current_user_doc:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            new_geo_point = {"type": "Point", "coordinates": [lng, lat], "timestamp": datetime.utcnow().isoformat()}

            current_location = current_user_doc.get("user_location", None)
            location_history = current_user_doc.get("location_history", [])

            coords_exist = False
            new_coords = [lng, lat]
            if current_location and "coordinates" in current_location:
                if current_location["coordinates"] == new_coords:
                    coords_exist = True
            if not coords_exist:
                for hist_loc in location_history:
                    if hist_loc.get("coordinates") == new_coords:
                        coords_exist = True
                        break

            update_data = {"user_location": new_geo_point}
            if not coords_exist and new_coords:
                location_history.append(new_geo_point)
                update_data["location_history"] = location_history

            update_result = await user_collection.update_one({"_id": current_user.id}, {"$set": update_data})
            if update_result.matched_count == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            user_location = await user_collection.find_one({"_id": current_user.id})
            if not user_location:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            if "_id" in user_location:
                user_location["_id"] = str(user_location["_id"])
            if "vendor_id" in user_location:
                user_location["vendor_id"] = str(user_location["vendor_id"])

            return user_location

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_user_ticket_list(
        self,
        request: Request,
        current_user: User,
    ):
        try:
            tickets = (
                await ticket_collection.find({"user": str(current_user.id)}).sort("created_at", -1).to_list(length=None)
            )
            if not tickets:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tickets not found")
            for ticket in tickets:
                ticket["id"] = str(ticket["_id"])
                ticket.pop("_id")

            return tickets

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_notification_list(self, current_user: User):
        try:
            pass
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
