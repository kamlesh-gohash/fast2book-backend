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
    Active = "active"
    Inactive = "inactive"
    Draft = "draft"


# create_subscription_request = zon.record(
#     {
#         "name": zon.string(),
#         "description": zon.string(),
#         "amount": zon.number(),
#         "currency": zon.string(),
#         "period": zon.string(),
#         "interval": zon.number(),
#     }
# )


# class CreateSubscriptionRequest(BaseModel):
#     name: str
#     description: str
#     amount: float
#     currency: str = "INR"
#     period: str
#     interval: int
#     features: List[FeatureItem]
#     status: StatusEnum = StatusEnum.Active

#     @validator("status")
#     def validate_status(cls, v):
#         if v not in StatusEnum.__members__.values():
#             raise ValueError(f"Invalid status. Valid options are {', '.join(StatusEnum.__members__.keys())}")
#         return v

#     def validate(self):
#         """Validates the service request using the zon validator."""
#         try:
#             create_subscription_request.validate(
#                 {
#                     "name": self.name,
#                     "description": self.description,
#                     "amount": self.amount,
#                     "currency": self.currency,
#                     "period": self.period,
#                     "interval": self.interval,
#                     "features": self.features,
#                     "status": self.status.value,
#                 }
#             )
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None


class AmountItem(BaseModel):
    type: str  # e.g., "Weekly", "Monthly", "Yearly"
    value: float  # e.g., 100


class FeatureItem(BaseModel):
    item: str


class CreateSubscriptionRequest(BaseModel):
    name: str
    description: str
    currency: str = "INR"
    amountsArray: List[AmountItem]  # List of amounts for different periods
    features: List[FeatureItem]
    interval: int

    @validator("currency")
    def validate_currency(cls, v):
        if v not in ["INR", "USD", "EUR"]:  # Add more currencies if needed
            raise ValueError("Invalid currency")
        return v

    @validator("interval")
    def validate_interval(cls, v):
        if v not in [1, 1, 1, 1, 1]:  # 1 for daily, 7 for weekly, 30 for monthly, 365 for yearly
            raise ValueError("Invalid interval")
        return v


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
    one_month_price: Optional[float] = None
    three_month_price: Optional[float] = None
    yearly_price: Optional[float] = None
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


create_plan_validator = zon.record(
    {
        "name": zon.string(),
        "description": zon.string(),
        "amount": zon.number(),
        "currency": zon.string(),
        "period": zon.string(),
        "interval": zon.number(),
    }
)


class CreatePlanRequest(BaseModel):
    name: str
    description: str
    amount: float
    currency: str = "INR"
    period: str
    interval: int

    def validate(self):
        try:
            create_plan_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
