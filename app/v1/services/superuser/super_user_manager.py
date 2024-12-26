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
from app.v1.schemas.superuser.superuser_auth import SuperUserCreateRequest

class SuperUserManager:
    
    async def super_user_sign_in(self, email: str, password: str) -> dict:
        """Sign in a user by email and password."""
        try:
            result = await user_collection.find_one({"email": email})
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            print(result,'result')
            # Check if the entered password matches the stored hashed password
            stored_password_hash = result.get("password")
            print(stored_password_hash,'stored_password_hash')
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Stored password hash not found."
                )
            # Check if the entered password matches the stored hashed password
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8') if isinstance(stored_password_hash, str) else stored_password_hash):
                print(password,'password')
                print(bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8') if isinstance(stored_password_hash, str) else stored_password_hash))
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
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
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

    async def super_user_forget_password(self, email: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
                )
            # Generate OTP
            otp = generate_otp()
            user.otp = otp
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            user.otp_expires = otp_expiration_time
            await user.save()
            # Send email with OTP
            await send_email(email, otp)
            return {"message": "OTP sent to email"}
        except HTTPException as e:
            raise e 
        except Exception as ex:
            print(ex,'ssssssssss')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def super_user_otp_verify(self, email: str, otp: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )    
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
                )
            if user.otp != otp:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid OTP"
                )
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
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )    
        
    async def super_user_reset_password(self, email: str, password: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )    
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
                )
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password
            await user.save()
            return {"message": "Password reset successfully"}
        except HTTPException as e:
            raise e 
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )    
        
    async def super_user_resend_otp(self, email: str) -> dict:    
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )    
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
                )
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def get_super_user_profile(self, email: str) -> dict:    
        try:
            user = await User.find_one(User.email == email)
            if user is None:    
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User data not found"
                )    
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not a super user"
                )
            user_data = user.dict()
            user_data.pop("password", None)
            user_data.pop("otp", None)
            return {"user_data": user_data}
        except HTTPException as e:
            raise e 
        except Exception as ex: 
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def update_super_user_profile(self,email:str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail= "User not found"
                )    
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not superuser"
                )
            user_data = user.dict()
            return {"user_data":user_data}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def change_super_user_password(self,email:str,old_password:str,new_password:str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )  
            if user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is not superuser"
                )
            if old_password is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail= "Old Password required"
                )
            if not bcrypt.checkpw(old_password.encode('utf-8'), user.password.encode('utf-8')):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Old password does not match",
                )

            # Ensure the new password is different
            if bcrypt.checkpw(new_password.encode('utf-8'), user.password.encode('utf-8')):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password cannot be the same as the old password",
                )

            # Hash the new password and save it
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_new_password.decode('utf-8')  # Store as a string
            await user.save()
            return {"email": user.email}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
    async def create_super_user(self,super_user_create_request:SuperUserCreateRequest) -> dict:    
        try:
            user = await User.find_one(User.email == super_user_create_request.email)
            if user is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists"
                )
            hashed_password = bcrypt.hashpw(super_user_create_request.password.encode('utf-8'), bcrypt.gensalt())
            user = User(first_name=super_user_create_request.first_name, last_name=super_user_create_request.last_name, email=super_user_create_request.email,  user_role=super_user_create_request.user_role,phone=super_user_create_request.phone,password=hashed_password,)
            await user.save()
            return {"data":None}
        except HTTPException as e:
            raise e 
        except Exception as ex: 
            print(ex)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )