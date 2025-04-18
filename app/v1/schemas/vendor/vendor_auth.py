from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, root_validator, validator

from app.v1.models.services import Service
from app.v1.models.user import *
from app.v1.models.vendor import *
from app.v1.utils.response.response_format import validation_error


class BusinessType(str, Enum):
    individual = "individual"
    business = "business"


class Service(BaseModel):
    id: str
    name: Optional[str] = None
    service_image: Optional[str] = None
    service_image_url: Optional[str] = None


# Validator for vendor creation
vendor_create_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50),
        "last_name": zon.string().min(1).max(50),
        "email": zon.string().email(),
        "phone": zon.string().min(10).max(10),
        # "password": zon.string().min(6).max(20),
    }
)


# Request model for vendor creation
class VendorCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    gender: Gender = Field(default=Gender.Male)
    roles: list[Role] = [Role.vendor]  # Default role is 'vendor'
    business_type: BusinessType = Field(default=BusinessType.individual)
    business_name: Optional[str] = Field(None, max_length=100)
    business_address: Optional[str] = Field(None, max_length=255)
    business_details: Optional[str] = None
    category_id: Optional[str] = Field(None, description="ID of the selected category")
    category_name: Optional[str] = Field(None, description="Name of the selected category")
    services: Optional[List[Service]] = Field(None, description="List of selected services with their IDs and names")
    service_details: Optional[str] = None

    # Additional Fields
    manage_plan: Optional[str] = None
    manage_fee_and_gst: Optional[str] = None
    manage_offer: Optional[str] = None
    is_payment_verified: bool = Field(default=False)
    is_dashboard_created: bool = Field(default=False)
    status: StatusEnum = Field(default=StatusEnum.Active)
    password: str

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "gender", "password", "email", "phone"]
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

    @validator("roles", pre=True, always=True)
    def ensure_vendor_role(cls, roles):
        """
        Ensure that the 'vendor' role is always present in the roles list.
        """
        if Role.vendor not in roles:
            roles.append(Role.vendor)
        return roles

    def validate(self):
        """
        Validate the request data using Zon.
        """
        try:
            vendor_create_validator.validate(self.dict(exclude={"roles"}))  # Exclude roles from zon validation
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


vendor_list_validator = zon.record({})


class VendorListRequest(BaseModel):

    def validate(self):
        try:
            vendor_list_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


get_vendor_validator = zon.record(
    {
        "id": zon.string().min(1).max(50),
    }
)


class GetVendorRequest(BaseModel):
    id: str

    def validate(self):
        try:
            get_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_vendor_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50).optional(),
        "last_name": zon.string().min(1).max(50).optional(),
        "email": zon.string().email().optional(),
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
        "vendor_address": zon.string().optional(),
        "vendor_details": zon.string().optional(),
        # "location": zon.string().optional(),
        "is_payment_required": zon.boolean().optional(),
    }
)


class UpdateVendorRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    gender: Gender = Field(default=Gender.Male)
    roles: list[Role] = [Role.vendor]
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    business_type: Optional[BusinessType] = Field(default=BusinessType.individual)
    business_name: Optional[str] = Field(None, max_length=100)
    business_address: Optional[str] = Field(None, max_length=255)
    business_details: Optional[str] = None
    category_id: Optional[str] = Field(None, description="ID of the selected category")
    category_name: Optional[str] = Field(None, description="Name of the selected category")
    services: Optional[List[Service]] = Field(None, description="List of selected services with their IDs and names")
    service_details: Optional[str] = None
    is_payment_required: Optional[bool] = Field(default=False)
    fees: Optional[float] = Field(default=0.0)
    # Additional Fields
    manage_plan: Optional[str] = None
    manage_fee_and_gst: Optional[str] = None
    manage_offer: Optional[str] = None
    location: Optional[Location] = Field(None, description="Location details of the vendor")
    specialization: Optional[str] = Field(None, description="specialization of the vendor")
    status: StatusEnum = Field(default=StatusEnum.Active)

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = []
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
            update_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


delete_vendor_validator = zon.record(
    {
        "id": zon.string().min(1).max(50),
    }
)


class DeleteVendorRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


sign_in_vendor_validator = zon.record(
    {
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
        "password": zon.string().min(6).max(20).optional(),
        "is_login_with_otp": zon.boolean().optional(),
    }
)


class SignInVendorRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[int] = None
    password: Optional[str] = None
    is_login_with_otp: bool = False
    device_token: Optional[str] = None
    web_token: Optional[str] = None

    def validate(self):
        try:
            sign_in_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


sign_up_vendor_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50),
        "last_name": zon.string().min(1).max(50),
        "email": zon.string().email().optional(),  # Optional email validation
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),  # Optional phone validation
        "business_name": zon.string().min(1).max(50),
        "password": zon.string().min(6).max(20),
    }
)


class SignUpVendorRequest(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None  # Make email optional
    phone: Optional[int] = Field(None)
    # vendor_images: Optional[List[str]] = Field(None, description="Array of vendor image URLs")
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    # phone: Optional[str] = Field(None, min_length=10, max_length=10)
    gender: Gender = Field(default=Gender.Male)
    roles: list[Role] = [Role.vendor]
    business_type: BusinessType = Field(default=BusinessType.individual)
    business_name: Optional[str] = Field(None, max_length=100)
    business_address: Optional[str] = Field(None, max_length=255)
    business_details: Optional[str] = None
    category_id: Optional[str] = Field(None, description="ID of the selected category")
    category_name: Optional[str] = Field(None, description="Name of the selected category")
    services: Optional[List[Service]] = Field(None, description="List of selected services with their IDs and names")
    service_details: Optional[str] = None
    # manage_plan: Optional[str] = None
    manage_plan: Optional[str] = Field(None, description="PLan ID for the manage plan")
    is_subscription: bool = Field(default=False)
    manage_fee_and_gst: Optional[str] = None
    manage_offer: Optional[str] = None
    is_payment_verified: bool = Field(default=False)
    is_dashboard_created: bool = Field(default=False)
    is_payment_required: bool = Field(default=False)
    fees: float = Field(default=0.0)
    location: Optional[Location] = Field(None, description="Location details of the vendor")
    specialization: Optional[str] = Field(None, description="specialization of the vendor")
    status: StatusEnum = Field(default=StatusEnum.Active)
    bank_account_number: Optional[int] = None
    ifsc: Optional[str] = None
    account_type: Optional[str] = None
    availability_slots: Optional[List[DaySlot]] = None  # Set as Optional, no default value
    password: str

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "password"]
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

    @validator("roles", pre=True, always=True)
    def ensure_vendor_role(cls, roles):
        """
        Ensure that the 'vendor' role is always present in the roles list.
        """
        if Role.vendor not in roles:
            roles.append(Role.vendor)
        return roles

    def validate(self):
        try:
            sign_up_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


create_vendor_user_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50),
        "last_name": zon.string().min(1).max(50),
        "email": zon.string().email(),
        "phone": zon.string().min(10).max(10).optional(),
    }
)


class VendorUserCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    category: Optional[str] = None
    services: List[Service]
    phone: Optional[str] = None
    fees: Optional[float] = Field(default=0.0)
    gender: Gender = Field(default=Gender.Male)
    status: StatusEnum = Field(default=StatusEnum.Active)
    roles: list[Role] = [Role.vendor_user]
    created_by: Optional[str] = None
    specialization: Optional[str] = None

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "gender", "email"]
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
            create_vendor_user_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


vendor_change_password_validator = zon.record(
    {"email": zon.string().email(), "old_password": zon.string(), "new_password": zon.string()}
)


class ChangePasswordRequest(BaseModel):
    email: str
    old_password: str
    new_password: str

    def validate(self):
        try:
            vendor_change_password_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_vendor_user_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50).optional(),
        "last_name": zon.string().min(1).max(50).optional(),
        "email": zon.string().email().optional(),
        "phone": zon.string().min(10).max(10).optional(),
        "category": zon.string().optional(),
        "fees": zon.number().optional(),
        "specialization": zon.string().optional(),
        "gander": zon.enum(["male", "female", "other"]).optional(),
        "status": zon.enum(["Active", "Inactive"]).optional(),
    }
)


class VendorUserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    category: Optional[str] = None
    services: Optional[List[Service]] = None
    phone: Optional[str] = None
    fees: Optional[float] = None
    gender: Optional[Gender] = None
    status: Optional[StatusEnum] = None
    specialization: Optional[str] = None
    roles: list[Role] = [Role.vendor_user]

    def validate(self):
        try:
            update_vendor_user_validator.validate(self.dict(exclude_none=True))
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


vendor_subscription_validator = zon.record(
    {
        "plan_id": zon.string(),
        "vendor_id": zon.string().optional(),
        "schedule_change_at": zon.string().optional(),
    }
)


class VendorSubscriptionRequest(BaseModel):
    plan_id: str
    vendor_id: Optional[str] = None
    total_count: int
    quantity: int = 1
    type: Optional[str] = None
    start_at: Optional[datetime] = None
    schedule_change_at: Optional[str] = None
    expire_by: Optional[datetime] = None

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["plan_id", "total_count", "quantity"]
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
            vendor_subscription_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


vendor_subscription_update_validator = zon.record(
    {
        "plan_id": zon.string().optional(),
        "total_count": zon.string().optional(),
        "quantity": zon.string().optional(),
        "start_at": zon.string().optional(),
        "expire_by": zon.string().optional(),
    }
)


class UpdateVendorSubscriptionRequest(BaseModel):
    plan_id: Optional[str] = None
    total_count: Optional[int] = None
    quantity: Optional[int] = None
    start_at: Optional[datetime] = None
    expire_by: Optional[datetime] = None

    def validate(self):
        try:
            vendor_subscription_update_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


class AddVendorAccountRequest(BaseModel):
    vendor_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[int] = None
    business_name: Optional[str] = None
    business_type: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    street: Optional[str] = None
    street2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    pan_number: Optional[str] = None
    gst_number: Optional[str] = None
    account_number: Optional[int] = None
    bank_name: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None

    def validate(self):
        try:
            vendor_subscription_update_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
