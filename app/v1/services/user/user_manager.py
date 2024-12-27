# app/v1/middleware/user_manager.py

import random
from app.v1.models import User
from app.v1.models import user_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from bcrypt import hashpw, gensalt

class UserManager:

    async def create_user(self, user: User) -> dict:
        """Create a new user in the database."""
        existing_user = await user_collection.find_one({
        "$or": [
            {"email": {"$eq": user.email, "$nin": [None, ""]}},
            {"phone": {"$eq": user.phone, "$nin": [None, ""]}}
        ]
        })

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
        user.password = hashpw(user.password.encode('utf-8'), gensalt()).decode('utf-8') 
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
        user.pop("otp", None)       # Remove OTP from response

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
            {"email": email},
            {"$set": update_data},
            return_document=True
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
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
        return result
    
    async def sign_in(self, email: str, password: str) -> dict:
        """Sign in a user by email and password."""
        try:
            result = await user_collection.find_one({"email": email})
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            # Check if the entered password matches the stored hashed password
            stored_password_hash = result.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Stored password hash not found."
                )
            # Check if the entered password matches the stored hashed password
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8') if isinstance(stored_password_hash, str) else stored_password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Password"
                )
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Please verify your email or phone to activate your account"
                )
            user_data = user.dict()
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
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
            # Check if the user exists with the provided phone
            user = await User.find_one(User.phone == phone)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided phone.")
            
            # Send OTP to the user's phone (SMS logic should be implemented)
            # await send_sms(phone, otp)  # Uncomment this line when implementing SMS functionality
            user.otp = otp

            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            user.otp_expires = otp_expiration_time
            await user.save()
            return {"message": "OTP sent to phone", "otp": otp}  # Include OTP in response for testing

        # Raise an error if neither email nor phone is provided
        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")

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
            user_data["_id"] = str(user.id)
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
            user_data = user.dict(by_alias=True)  # Include `id` field
            user_data["_id"] = str(user.id)
            user_data.pop("password", None)
            user_data.pop("otp", None)
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})
            return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")
    
    async def reset_password(self, email: Optional[str] = None, phone: Optional[str] = None, password: str = None) -> dict:
        if not password:
            raise HTTPException(status_code=400, detail="Password is required.")

        if email:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided email.")
            
            # Ensure password is being hashed correctly
            user.password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8') 
            await user.save()
            return {"message": "Password reset successful."}

        if phone:
            user = await User.find_one(User.phone == phone)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found with the provided phone.")
            
            # Ensure password is being hashed correctly
            user.password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8') 
            await user.save()
            return {"message": "Password reset successful."}

        raise HTTPException(status_code=400, detail="Either email or phone must be provided.")

    async def update_profile(self, user_id: str, profile_update_request: User):
        
        try:
            # Update user profile logic
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
