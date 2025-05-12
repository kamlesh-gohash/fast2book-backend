from datetime import datetime
from enum import Enum
from typing import List, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, root_validator, validator

from app.v1.models.category import StatusEnum
from app.v1.models.offer import DiscountTypeEnum, OfferForEnum, OfferTypeEnum, PaymentMethodEnum
from app.v1.models.user import CustomValidationError, StatusEnum
from app.v1.utils.response.response_format import validation_error


create_offer_validator = (
    zon.record(
        {
            "display_text": zon.string().min(1).max(200),
            "discount_type": zon.enum(DiscountTypeEnum),
            "minimum_order_amount": zon.number().int().min(0),
            "discount_worth": zon.number().int().min(0),
            "maximum_discount": zon.number().int().min(0),
            "issuer": zon.string().min(1).max(100),
            "starting_date": zon.string().datetime(),
            "ending_date": zon.string().datetime(),
            "max_usage": zon.number().int().min(1),
        }
    )
    .refine(
        lambda data: data["starting_date"] <= data["ending_date"],
        "Ending date must be after or equal to starting date",
    )
    .refine(
        lambda data: (
            data["discount_worth"] <= data["maximum_discount"]
            if data["discount_type"] == DiscountTypeEnum.FLAT
            else True
        ),
        "Discount worth cannot exceed maximum discount for flat discounts",
    )
    .refine(
        lambda data: data["minimum_order_amount"] >= data["maximum_discount"],
        "Minimum order amount must be greater than or equal to maximum discount",
    )
)


# Pydantic model for creating an offer
class CreateOfferRequest(BaseModel):
    offer_for: List[OfferForEnum]
    display_text: str
    terms: List[str] = Field(default_factory=list)
    offer_type: List[OfferTypeEnum]
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

    def validate(self):
        # Validate using zon schema
        try:
            data = self.dict()
            create_offer_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})

        return None
