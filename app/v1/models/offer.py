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


class OfferForEnum(str, Enum):
    Vendor = "vendor"
    User = "user"


class Offer(BaseModel):
    offer_for: OfferForEnum = Field(default=OfferForEnum.User)
    offer_name: str
    created_by: str
    is_super_admin: bool = False
    display_text: str
    terms: str
    # offer_type: List[OfferTypeEnum] = Field(default_factory=list)
    discount_type: DiscountTypeEnum
    minimum_order_amount: int
    discount_worth: int
    maximum_discount: int
    starting_date: datetime
    ending_date: datetime
    max_usage: int
    status: StatusEnum = Field(default=StatusEnum.Active)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "offer"


class VendorOffer(BaseModel):
    vendor_id: str
    offer_name: str
    display_text: str
    terms: str
    discount_type: DiscountTypeEnum
    minimum_order_amount: int
    discount_worth: int
    maximum_discount: int
    starting_date: datetime
    ending_date: datetime
    max_usage: int
    status: StatusEnum = Field(default=StatusEnum.Active)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendor_offer"
