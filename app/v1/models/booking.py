import os

from datetime import datetime

# from app.v1.models.transactions import Transaction
from typing import Dict, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.slots import *
from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor


class BookingStatusEnum(str, Enum):
    pending = "pending"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    rescheduled = "rescheduled"


class PaymentStatusEnum(str, Enum):
    paid = "paid"
    unpaid = "unpaid"
    failed = "failed"


class Bookings(BaseModel):
    user_id: Link[User]
    vendor_id: Link[Vendor]
    slots_id: Link[Slots]
    # transaction_id: Link[Transaction]
    slot_data: Dict[str, SlotRequest]
    category_id: Link[Category]
    service: Link[Service]
    booking_date: datetime
    status: StatusEnum = StatusEnum.Active
    booking_status: BookingStatusEnum = BookingStatusEnum.pending
    booking_confirm: bool = Field(default=False)
    payment_status: PaymentStatusEnum = PaymentStatusEnum.unpaid
    created_at: datetime = Field(default_factory=datetime.utcnow)
    booking_order_id: Optional[str] = None
    amount: Optional[float] = None
    payment_method: Optional[str] = None
    booking_cancel_reason: Optional[str] = None
    reaschulding_reason: Optional[str] = None
    payment_id: Optional[str] = None

    class Settings:
        name = "bookings"


# class TransactionStatusEnum(str, Enum):
#     pending = "pending"
#     successful = "successful"
#     failed = "failed"
#     cancelled = "cancelled"

# class BookingPayment(BaseModel):
#     booking_id: Link[Bookings]
#     user_id: Link[User]
#     razorpaytransaction_id: str
#     amount: float
#     currency: str
#     payment_method: str
#     transaction_status: TransactionStatusEnum = TransactionStatusEnum.pending
#     payment_date: datetime
#     razorpay_signature: str

#     class Settings:
#         name = "booking_payments"
