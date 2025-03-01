from datetime import datetime
from typing import List, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, root_validator, validator

from app.v1.models.user import *
from app.v1.utils.response.response_format import validation_error


super_user_sign_in_validator = zon.record(
    {
        "email": zon.string().email(),
        "password": zon.string().min(6).max(20).optional(),
        "is_login_with_otp": zon.boolean().optional(),
    }
)


class SuperUserSignInRequest(BaseModel):
    email: str
    password: Optional[str] = None
    is_login_with_otp: bool = False

    def validate(self):
        try:
            super_user_sign_in_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


super_user_forgot_password_validator = zon.record(
    {
        "email": zon.string().email(),
    }
)


class SuperUserForgotPasswordRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_forgot_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


super_user_otp_validator = zon.record(
    {
        "email": zon.string().email(),
        "otp": zon.string().min(6).max(6),
    }
)


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


super_user_reset_password_validator = zon.record(
    {
        "email": zon.string().email(),
        "password": zon.string().min(6).max(20),
    }
)


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


super_user_resend_otp_validator = zon.record(
    {
        "email": zon.string().email(),
    }
)


class SuperUserResendOtpRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_resend_otp_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


super_user_profile_validator = zon.record(
    {
        "email": zon.string().email(),
    }
)


class SuperUserProfileRequest(BaseModel):
    email: str

    def validate(self):
        try:
            super_user_profile_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


super_user_change_password_validator = zon.record(
    {"email": zon.string().email(), "old_password": zon.string(), "new_password": zon.string()}
)


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


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


create_super_user_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50),
        "last_name": zon.string().min(1).max(50),
        "email": zon.string().email(),
        "phone": zon.string().min(10).max(10),
        "password": zon.string().min(6).max(20),
    }
)


class SuperUserCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    gender: Gender = Field(default=Gender.male)
    roles: List[Role] = Field(default=["admin"])
    phone: str
    status: StatusEnum = StatusEnum.ACTIVE
    password: str

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "password", "email", "phone", "gender"]
        missing_fields = []

        # Check for missing required fields
        for field in required_fields:
            if field not in values or values[field] is None:
                missing_fields.append(field)

        if missing_fields:
            # Raise a custom exception with the validation error
            raise CustomValidationError(
                detail={
                    "status": "VALIDATION_ERROR",
                    "message": f"The following fields are required: {', '.join(missing_fields)}",
                    "data": None,
                }
            )

        return values

    def validate(self):
        try:
            create_super_user_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


get_super_user_list_validator = zon.record({})


class SuperUserListRequest(BaseModel):

    def validate(self):
        try:
            get_super_user_list_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_super_user_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50).optional(),
        "last_name": zon.string().min(1).max(50).optional(),
        "email": zon.string().email().optional(),
        "phone": zon.string().min(10).max(10).optional(),
    }
)


class SuperUserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[StatusEnum] = None

    def validate(self):
        try:
            update_super_user_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


delete_super_user_validator = zon.record({"id": zon.string()})


class SuperUserDeleteRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_super_user_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
