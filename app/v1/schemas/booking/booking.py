from datetime import datetime
from typing import Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr

from app.v1.models.booking import *
from app.v1.utils.response.response_format import validation_error


create_category_validator = zon.record(
    {
        "name": zon.string(),
    }
)


class CreateCategoryRequest(BaseModel):
    name: str
    status: StatusEnum = StatusEnum.Active

    def validate(self):
        try:
            create_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


create_booking_validator = zon.record(
    {
        "user_id": zon.string().optional(),
        "vendor_id": zon.string(),
        "category_id": zon.string(),
        "service_id": zon.string(),
        "booking_date": zon.string(),
        "time_slot": zon.string().optional(),
        "description": zon.string(),
        "booking_order_id": zon.string().optional(),
    }
)


class CreateBookingRequest(BaseModel):
    user_id: Optional[str] = None
    vendor_id: str
    category_id: str
    service_id: str
    booking_date: str
    time_slot: Optional[str] = None
    status: StatusEnum = StatusEnum.Active
    booking_status: BookingStatusEnum = BookingStatusEnum.pending
    payment_status: PaymentStatusEnum = PaymentStatusEnum.unpaid
    description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    booking_order_id: Optional[str] = None

    def validate(self):
        try:
            create_booking_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


cancel_booking_validator = zon.record(
    {
        "booking_id": zon.string(),
        "reason": zon.string(),
    }
)


class CancelBookingRequest(BaseModel):
    booking_id: str
    reason: str

    def validate(self):
        try:
            cancel_booking_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
