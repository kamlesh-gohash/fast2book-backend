import os
import random
import string

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor


class DiscountTypeEnum(str, Enum):
    FLAT = "flat"
    PERCENTAGE = "percentage"


class PaymentMethodEnum(str, Enum):
    CARD = "card"
    UPI = "upi"
    WALLET = "wallet"


class OfferTypeEnum(str, Enum):
    INSTANT = "instant"
    CASHBACK = "cashback"


class OfferForEnum(str, Enum):
    VENDOR = "vendor"
    USER = "user"


class Offer(BaseModel):
    offer_for: List[OfferForEnum]
    display_text: str
    terms: List[str] = Field(default_factory=list)
    offer_type: List[OfferTypeEnum] = Field(default_factory=list)
    discount_type: DiscountTypeEnum
    minimum_order_amount: int
    discount_worth: int
    maximum_discount: int
    payment_method: List[PaymentMethodEnum] = Field(default_factory=list)
    issuer: str
    starting_date: datetime
    ending_date: datetime
    max_usage: int
    status: StatusEnum = Field(default=StatusEnum.Active)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "offer"
