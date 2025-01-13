from datetime import datetime
from enum import Enum
from typing import Optional

import bcrypt
import zon

from beanie import PydanticObjectId
from bson import ObjectId
from pydantic import BaseModel, EmailStr, validator
from zon import ZonList, record, string

from app.v1.models.category import Category, StatusEnum
from app.v1.models.subscription import *
from app.v1.utils.response.response_format import validation_error


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


create_subscription_request = zon.record(
    {
        "title": zon.string(),
        "status": zon.string(),
    }
)


class CreateSubscriptionRequest(BaseModel):
    title: str
    price: float
    features: List[FeatureItem]
    status: StatusEnum = StatusEnum.ACTIVE

    @validator("status")
    def validate_status(cls, v):
        if v not in StatusEnum.__members__.values():
            raise ValueError(f"Invalid status. Valid options are {', '.join(StatusEnum.__members__.keys())}")
        return v

    def validate(self):
        """Validates the service request using the zon validator."""
        try:
            create_subscription_request.validate(
                {
                    "title": self.title,
                    "price": self.price,
                    "status": self.status.value,  # Enum to string
                }
            )
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


list_subscription_validator = zon.record({})


class ListSubscriptionRequest(BaseModel):

    def validate(self):
        try:
            list_subscription_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


get_subscription_validator = zon.record({"id": zon.string()})


class GetSubscriptionRequest(BaseModel):
    id: str

    def validate(self):
        try:
            get_subscription_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_subscription_validator = zon.record(
    {
        "title": zon.string().optional(),
        "price": zon.number().optional(),
        "status": zon.string().optional(),
    }
)


class UpdateSubscriptionRequest(BaseModel):
    title: Optional[str] = None
    price: Optional[float] = None
    features: Optional[List[FeatureItem]] = None
    status: Optional[StatusEnum] = None

    def validate(self):
        try:
            update_subscription_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


delete_subscription_validator = zon.record({"id": zon.string()})


class DeleteSubscriptionRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_subscription_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
