import zon
from pydantic import BaseModel, EmailStr
from app.v1.utils.response.response_format import validation_error
from typing import Optional
import bcrypt
from datetime import datetime



super_user_sign_in_validator = zon.record({
    "email": zon.string().email(),  
    "password": zon.string().min(6).max(20),
})

class SuperUserSignInRequest(BaseModel):
    email: str 
    password: str

    def validate(self):
        try:
            super_user_sign_in_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
super_user_forgot_password_validator = zon.record({
    "email": zon.string().email(),

})    

class SuperUserForgotPasswordRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_forgot_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None

super_user_otp_validator = zon.record({
    "email": zon.string().email(),
    "otp": zon.string().min(6).max(6),
})    

class SuperUserOtpRequest(BaseModel):
    email: str
    otp: str

    def validate(self):
        try:
            super_user_otp_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None

super_user_reset_password_validator = zon.record({
    "email": zon.string().email(),
    "password": zon.string().min(6).max(20),
})    

class SuperUserResetPasswordRequest(BaseModel):
    email: str
    password: str

    def validate(self):
        try:
            super_user_reset_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
super_user_resend_otp_validator = zon.record({
    "email": zon.string().email(),
})    

class SuperUserResendOtpRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_resend_otp_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
super_user_profile_validator = zon.record({
    "email": zon.string().email(),
})    

class SuperUserProfileRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_profile_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None

super_user_change_password_validator = zon.record({
    "email": zon.string().email(),
    "old_password": zon.string(),
    "new_password": zon.string()

})    

class SuperUserChangePassword(BaseModel):
    email: str
    old_password: str
    new_password: str

    def validate(self):
        try:
            super_user_change_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
create_super_user_validator = zon.record({
    "first_name": zon.string().min(1).max(50),
    "last_name": zon.string().min(1).max(50),
    "email": zon.string().email(),
    "user_role": zon.string(),
    "phone": zon.string().min(10).max(10),
    "password": zon.string().min(6).max(20),
})    

class SuperUserCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    user_role: str
    phone: str
    password: str

    def validate(self):
        try:
            create_super_user_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None