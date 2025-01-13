# from datetime import datetime
# from beanie import Link, Document
# from pydantic import BaseModel
# from app.v1.models.booking import Bookings
# from app.v1.models.user import User
# from enum import Enum


# class TransactionStatusEnum(str, Enum):
#     pending = "pending"
#     successful = "successful"
#     failed = "failed"
#     cancelled = "cancelled"


# class Transaction(BaseModel):
#     user_id: Link[User]  # Link to the user who made the payment
#     booking_id: Link[Bookings]  # Link to the specific booking
#     razorpaytransaction_id: str  # Razorpay transaction ID
#     amount: float  # Amount involved in the transaction
#     currency: str  # Currency used for the transaction (e.g., INR, USD)
#     payment_method: str  # Payment method used (e.g., 'card', 'wallet', 'netbanking')
#     status: TransactionStatusEnum = TransactionStatusEnum.pending  # Status of the transaction
#     payment_date: datetime  # Timestamp when the payment was made
#     razorpay_signature: str  # Razorpay signature for security verification

#     class Settings:
#         name = "transactions"  # Name of the collection in the database


# class RazorpayTransactionCreateRequest(BaseModel):
#     booking_id: str  # The booking ID for which the transaction is being made
#     razorpaytransaction_id: str  # Razorpay transaction ID
#     amount: float  # Amount involved in the transaction
#     currency: str  # Currency used
#     payment_method: str  # Payment method used
#     razorpay_signature: str  # Razorpay signature
#     user_id: str  # User ID of the person making the payment

#     class Config:
#         orm_mode = True
