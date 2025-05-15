from datetime import datetime
from enum import Enum
from typing import List, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, root_validator, validator

from app.v1.models.category import StatusEnum
from app.v1.models.offer import DiscountTypeEnum, OfferForEnum
from app.v1.models.user import CustomValidationError, StatusEnum
from app.v1.utils.response.response_format import validation_error


create_offer_validator = (
    zon.record(
        {
            "offer_for": zon.enum(OfferForEnum),
            "offer_name": zon.string().min(1).max(50),
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
    offer_for: OfferForEnum = Field(default=OfferForEnum.User)
    created_by: Optional[str] = None
    is_super_admin: bool = False
    offer_name: str
    display_text: str
    terms: str
    # offer_type: List[OfferTypeEnum]
    discount_type: DiscountTypeEnum
    minimum_order_amount: int
    discount_worth: int
    maximum_discount: int
    starting_date: str  # Change to str
    ending_date: str
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


update_offer_validator = zon.record(
    {
        "display_text": zon.string().min(1).max(200).optional(),
        "discount_type": zon.enum(DiscountTypeEnum).optional(),
        "minimum_order_amount": zon.number().int().min(0).optional(),
        "discount_worth": zon.number().int().min(0).optional(),
        "maximum_discount": zon.number().int().min(0).optional(),
        "starting_date": zon.string().datetime().optional(),
        "ending_date": zon.string().datetime().optional(),
        "max_usage": zon.number().int().min(1).optional(),
        "status": zon.enum(StatusEnum).optional(),
    },
)


class UpdateOfferRequest(BaseModel):
    offer_for: Optional[str] = None
    offer_name: Optional[str] = None
    display_text: Optional[str] = None
    terms: Optional[str] = None
    # offer_type: Optional[List[OfferTypeEnum]] = None
    discount_type: Optional[DiscountTypeEnum] = DiscountTypeEnum.FLAT
    minimum_order_amount: Optional[int] = None
    discount_worth: Optional[int] = None
    maximum_discount: Optional[int] = None
    # payment_method: Optional[List[PaymentMethodEnum]] = Field(default_factory=list)
    # issuer: Optional[str] = None
    starting_date: Optional[str] = None
    ending_date: Optional[str] = None
    max_usage: Optional[int] = None
    status: Optional[StatusEnum] = StatusEnum.Active
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def validate(self):
        data = {k: v for k, v in self.dict().items() if v is not None and k != "updated_at"}
        try:
            update_offer_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return {"message": f"Validation Error: {error_message}"}
        return None


create_vendor_offer_validator = zon.record(
    {
        "vendor_id": zon.string().min(1).max(50),
        "offer_name": zon.string().min(1).max(50),
        "display_text": zon.string().min(1).max(200),
        "terms": zon.string().min(1).max(200),
        "discount_type": zon.enum(DiscountTypeEnum),
        "minimum_order_amount": zon.number().int().min(0),
        "discount_worth": zon.number().int().min(0),
        "maximum_discount": zon.number().int().min(0),
        "starting_date": zon.string().datetime(),
        "ending_date": zon.string().datetime(),
        "max_usage": zon.number().int().min(1),
    }
)


class CreateVendorOffer(BaseModel):
    vendor_id: Optional[str] = None
    offer_name: Optional[str] = None
    display_text: Optional[str] = None
    terms: Optional[str] = None
    discount_type: Optional[DiscountTypeEnum] = DiscountTypeEnum.FLAT
    minimum_order_amount: Optional[int] = None
    discount_worth: Optional[int] = None
    maximum_discount: Optional[int] = None
    starting_date: Optional[str] = None  # Change to str to match input
    ending_date: Optional[str] = None  # Change to str to match input
    max_usage: Optional[int] = None
    status: StatusEnum = Field(default=StatusEnum.Active)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def validate(self):
        data = {k: v for k, v in self.dict().items() if v is not None and k != "updated_at"}
        try:
            create_vendor_offer_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return {"message": f"Validation Error: {error_message}"}
        return None


update_vendor_offer_validator = zon.record(
    {
        "offer_name": zon.string().min(1).max(50).optional(),
        "display_text": zon.string().min(1).max(200).optional(),
        "terms": zon.string().min(1).max(200).optional(),
        "discount_type": zon.enum(DiscountTypeEnum).optional(),
        "minimum_order_amount": zon.number().int().min(0).optional(),
        "discount_worth": zon.number().int().min(0).optional(),
        "maximum_discount": zon.number().int().min(0).optional(),
        "starting_date": zon.string().datetime().optional(),
        "ending_date": zon.string().datetime().optional(),
        "max_usage": zon.number().int().min(1).optional(),
        "status": zon.enum(StatusEnum).optional(),
    },
)


class UpdateVendorOffer(BaseModel):
    offer_name: Optional[str] = None
    display_text: Optional[str] = None
    terms: Optional[str] = None
    discount_type: Optional[DiscountTypeEnum] = DiscountTypeEnum.FLAT
    minimum_order_amount: Optional[int] = None
    discount_worth: Optional[int] = None
    maximum_discount: Optional[int] = None
    starting_date: Optional[str] = None
    ending_date: Optional[str] = None
    max_usage: Optional[int] = None
    status: Optional[StatusEnum] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def validate(self):
        data = {k: v for k, v in self.dict().items() if v is not None and k != "updated_at"}
        try:
            update_offer_validator.validate(data)
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return {"message": f"Validation Error: {error_message}"}
        return None
