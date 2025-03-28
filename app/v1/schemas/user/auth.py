from datetime import datetime
from typing import List, Optional

import bcrypt
import zon

from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, Field, ValidationError, root_validator, validator

from app.v1.models.user import *
from app.v1.utils.response.response_format import validation_error


signup_validator = (
    zon.record(
        {
            "first_name": zon.string().min(1).max(50),
            "last_name": zon.string().min(0).max(50),
            "email": zon.string().email().optional(),  # Optional but must pass refinement
            "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional but must pass refinement
            "gender": zon.string().min(1).max(30),  # Allow values like "male", "female", or "other"
            "password": zon.string().min(6).max(20),
            "otp": zon.string().min(6).max(6).optional(),
            "otp_expires": zon.string().datetime().optional(),
        }
    )
    .refine(lambda data: data.get("email") or data.get("phone"), "Either email or phone is required and must be valid")
    .refine(
        lambda data: data.get("gender") in ["Male", "Female", "Don't want to Disclose"],  # Validate gender values
        "Gender must be one of: male, female, other",
    )
)


class SignUpRequest(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    roles: Optional[List[str]] = None  # Optional roles, can be a list of strings like ['user', 'vendor']
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    gender: str
    password: str
    otp: Optional[str] = None  # Make OTP optional
    otp_expires: Optional[datetime] = None
    is_active: bool = Field(default=False)
    notification_settings: Dict[str, bool] = Field(default_factory=dict)

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "gender", "password"]
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
        # Validate using zon schema
        try:
            data = self.dict()
            signup_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})

        return None


sign_in_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
        "password": zon.string().min(6).max(20).optional(),
        "is_login_with_otp": zon.boolean().optional(),
    }
)


class SignInRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    password: Optional[str] = None
    is_login_with_otp: Optional[bool] = False

    def validate(self):
        try:
            sign_in_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


resend_otp_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
    }
).refine(
    lambda data: data.get("email") or data.get("phone"),  # At least one required
    "Either 'email' or 'phone' must be provided.",
)


class ResendOtpRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    otp_type: Optional[str] = None

    def validate(self):
        # Ensure either email or phone is provided, but not both
        if not self.email and not self.phone:
            return validation_error({"message": "Either email or phone must be provided."})
        if self.email and self.phone:
            return validation_error({"message": "Only one of email or phone should be provided."})

        # Prepare data for Zon validation, and only include the provided value
        data = {}

        if self.email:
            data["email"] = self.email
        if self.phone:
            data["phone"] = self.phone

        # Ensure that data passed to Zon does not contain any None values
        if data:
            try:
                # Perform Zon validation with the prepared data
                resend_otp_validator.validate(data)
            except zon.error.ZonError as e:
                # Format Zon errors
                error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
                return validation_error({"message": f"Validation Error: {error_message}"})
        else:
            return validation_error({"message": "Neither email nor phone was provided."})

        return None


forgot_password_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
    }
).refine(
    lambda data: data.get("email") or data.get("phone"),  # At least one required
    "Either 'email' or 'phone' must be provided.",
)


class ForgotPasswordRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None

    def validate(self):
        # Ensure either email or phone is provided, but not both
        if not self.email and not self.phone:
            return validation_error({"message": "Either email or phone must be provided."})
        if self.email and self.phone:
            return validation_error({"message": "Only one of email or phone should be provided."})

        # Prepare data for Zon validation, and only include the provided value
        data = {}

        if self.email:
            data["email"] = self.email
        if self.phone:
            data["phone"] = self.phone

        # Ensure that data passed to Zon does not contain any None values
        if data:
            try:
                # Perform Zon validation with the prepared data
                forgot_password_validator.validate(data)
            except zon.error.ZonError as e:
                # Format Zon errors
                error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
                return validation_error({"message": f"Validation Error: {error_message}"})
        else:
            return validation_error({"message": "Neither email nor phone was provided."})

        return None


validate_otp_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
        "otp": zon.string().min(6).max(6),  # OTP validation
    }
).refine(
    lambda data: data.get("email") or data.get("phone"),  # At least one required
    "Either 'email' or 'phone' must be provided.",
)


class ValidateOtpRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    otp: str
    otp_type: str

    def validate(self):
        # Ensure either email or phone is provided, but not both
        if not self.email and not self.phone:
            return validation_error({"message": "Either email or phone must be provided."})
        if self.email and self.phone:
            return validation_error({"message": "Only one of email or phone should be provided."})

        # Prepare data for Zon validation, and only include the provided value
        data = {}

        if self.email:
            data["email"] = self.email
        if self.phone:
            data["phone"] = self.phone
        data["otp"] = self.otp

        # Ensure that data passed to Zon does not contain any None values
        if data:
            try:
                # Perform Zon validation with the prepared data
                validate_otp_validator.validate(data)
            except zon.error.ZonError as e:
                # Format Zon errors
                error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
                return validation_error({"message": f"Validation Error: {error_message}"})
        else:
            return validation_error({"message": "Neither email nor phone was provided."})

        return None


reset_password_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
        "password": zon.string().min(6).max(20),  # Password length validation
    }
)


class ResetPasswordRequest(BaseModel):
    password: str
    email: Optional[EmailStr] = None
    phone: Optional[int] = None

    def validate(self):
        if not self.password:
            return validation_error({"message": "Password is required and cannot be empty."})

        if not self.email and not self.phone:
            return validation_error({"message": "Either email or phone must be provided."})
        if self.email and self.phone:
            return validation_error({"message": "Only one of email or phone should be provided."})

        data = {}
        if self.email:
            data["email"] = self.email
        if self.phone:
            data["phone"] = self.phone
        data["password"] = self.password

        try:
            reset_password_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})

        return None


referce_token_validator = zon.record(
    {
        "refresh_token": zon.string().min(1).max(500),
    }
)


class RefreshTokenRequest(BaseModel):
    refresh_token: str

    def validate(self):
        try:
            referce_token_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


change_password_validator = zon.record(
    {
        "old_password": zon.string().min(6).max(20),
        "new_password": zon.string().min(6).max(20),
    }
)


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

    def validate(self):
        try:
            change_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_profile_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50).optional(),
        "last_name": zon.string().min(1).max(50).optional(),
        "email": zon.string().email().optional(),
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
        "gender": zon.string().min(1).max(50).optional(),
        "blood_group": zon.string().min(1).max(50).optional(),
        "address": zon.string().min(1).max(50).optional(),
        "dob": zon.string().min(1).max(50).optional(),
    }
)


class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    phone: Optional[int] = None
    gender: Optional[str] = None
    blood_group: Optional[str] = None
    dob: Optional[str] = None
    address: Optional[Location] = Field(None, description="Location details of the vendor")
    secondary_phone_number: Optional[int] = None
    costumer_details: Optional[str] = None
    costumer_address: Optional[str] = None

    # @validator("address", pre=True)
    # def validate_address(cls, value):
    #     if value == "" or value is None:
    #         return None
    #     return value

    def validate(self):
        try:
            data = self.dict(exclude_none=True)
            change_password_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


link_request_validator = zon.record(
    {
        "email": zon.string().email().optional(),
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
        "link": zon.string().min(1).max(50).optional(),
    }
)


class LinkRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    link: Optional[str] = None

    def validate(self):
        try:
            data = self.dict(exclude_none=True)
            change_password_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
