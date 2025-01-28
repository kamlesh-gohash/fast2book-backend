import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY


class StatusEnum(str, Enum):
    Active = "active"
    Inactive = "inactive"
    Draft = "draft"


class Plan(BaseModel):
    razorpay_plan_id: str
    name: str
    description: str
    amount: float
    currency: str
    period: str
    interval: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        orm_mode = True


class SubscriptionDuration(str, Enum):
    ONE_MONTH = "one_month"
    THREE_MONTHS = "three_months"
    YEARLY = "yearly"


class FeatureItem(BaseModel):
    item: str

    def to_dict(self):
        return {"item": self.item}


class Subscription(Document):
    # title: str = Field(..., min_length=1, max_length=50)
    # prices: dict[SubscriptionDuration, float]
    # features: List[FeatureItem]
    # status: StatusEnum = Field(default=StatusEnum.ACTIVE)
    # created_at: datetime = Field(default_factory=datetime.utcnow)
    name: str
    description: str
    amount: float
    currency: str = "INR"
    period: str
    interval: int
    features: List[FeatureItem]
    status: StatusEnum = StatusEnum.Active
    razorpay_plan_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        orm_mode = True
