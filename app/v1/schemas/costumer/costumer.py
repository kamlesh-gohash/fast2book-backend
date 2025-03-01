from datetime import datetime
from enum import Enum
from typing import Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, validator, root_validator

from app.v1.models.category import StatusEnum
from app.v1.models.user import StatusEnum , CustomValidationError
from app.v1.utils.response.response_format import validation_error


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class Gender(str, Enum):
    male = "male"
    female = "female"
    other = "don't_want_to_disclose"


class Role(str, Enum):
    admin = "admin"
    user = "user"
    vendor = "vendor"


costumer_create_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50),
        "last_name": zon.string().min(1).max(50),
        "email": zon.string().email(),
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
        "password": zon.string().min(6).max(20),
    }
)


class CostumerCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[int] = None
    gender: Gender = Field(default=Gender.male)
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    roles: list[Role] = [Role.user]
    status: StatusEnum = StatusEnum.ACTIVE
    costumer_address: Optional[str] = None
    costumer_details: Optional[str] = None

    password: str

    @root_validator(pre=True)
    def check_required_fields(cls, values):
        # Define required fields
        required_fields = ["first_name", "last_name", "gender", "password", "email"]
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
    def ensure_user_role(cls, roles):
        """
        Ensure that the 'vendor' role is always present in the roles list.
        """
        if Role.user not in roles:
            roles.append(Role.user)
        return roles

    def validate(self):
        try:
            costumer_create_validator.validate(self.dict(exclude={"roles"}))
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


costumer_list_validator = zon.record({})


class CostumerListRequest(BaseModel):

    def validate(self):
        try:
            costumer_list_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


get_costumer_validator = zon.record(
    {
        "id": zon.string().min(1).max(50),
    }
)


class GetCostumerRequest(BaseModel):
    id: str

    def validate(self):
        try:
            get_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_costumer_validator = zon.record(
    {
        "first_name": zon.string().min(1).max(50).optional(),
        "last_name": zon.string().min(1).max(50).optional(),
        "email": zon.string().email().optional(),
        "phone": zon.number().int().min(1000000000).max(9999999999).optional(),
        "costumer_address": zon.string().optional(),
        "costumer_details": zon.string().optional(),
    }
)


class UpdateCostumerRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    phone: Optional[int] = None
    status: StatusEnum = StatusEnum.ACTIVE
    gender: Gender = Gender.male
    costumer_address: Optional[str] = None
    costumer_details: Optional[str] = None

    def validate(self):
        try:
            update_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


delete_costumer_validator = zon.record(
    {
        "id": zon.string().min(1).max(50),
    }
)


class DeleteCostumerRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
