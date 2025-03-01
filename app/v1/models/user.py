import os

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY


# Enum for gender
class Gender(str, Enum):
    male = "male"
    female = "female"
    other = "don't_want_to_disclose"


class Location(BaseModel):
    address_components: Optional[List[Dict]] = Field(None, description="Address components of the location")
    formatted_address: Optional[str] = Field(None, description="Formatted address of the location")
    geometry: Optional[Dict] = Field(None, description="Geometry details of the location")
    place_id: Optional[str] = Field(None, description="Place ID of the location")
    types: Optional[List[str]] = Field(None, description="Types of the location")
    url: Optional[str] = Field(None, description="URL of the location")
    utc_offset_minutes: Optional[int] = Field(None, description="UTC offset in minutes")
    vicinity: Optional[str] = Field(None, description="Vicinity of the location")
    website: Optional[str] = Field(None, description="Website of the location")


# Enum for role
class Role(str, Enum):
    admin = "admin"
    user = "user"
    vendor = "vendor"  # Fixed from "student" to "vendor"
    vendor_user = "vendor_user"


class TimeSlot(BaseModel):
    start_time: str
    end_time: str
    max_seat: int = Field(..., gt=0, description="Maximum number of seats for the time slot")
    duration: int = Field(default=0, description="Duration of the time slot in minutes")

    def calculate_duration(self):
        """
        Calculate the duration between start_time and end_time in minutes.
        """
        try:
            start = datetime.strptime(self.start_time, "%H:%M")
            end = datetime.strptime(self.end_time, "%H:%M")
            self.duration = int((end - start).total_seconds() / 60)
        except Exception as e:
            raise ValueError(f"Error calculating duration: {str(e)}")


class DaySlot(BaseModel):
    day: str
    time_slots: List[TimeSlot]


def default_availability_slots():
    time_slots = [
        {"start_time": f"{hour:02}:00", "end_time": f"{hour+1:02}:00", "max_seat": 10} for hour in range(9, 17)
    ]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return [{"day": day, "time_slots": time_slots} for day in days]


# def default_availability_slots():
#     def format_time(hour):
#         if hour == 12:
#             return f"12:00 PM"
#         elif hour > 12:
#             return f"{hour - 12}:00 PM"
#         else:
#             return f"{hour}:00 AM"

#     time_slots = [
#         {"start_time": format_time(hour), "end_time": format_time(hour + 1), "max_seat": 10}
#         for hour in range(9, 17)
#     ]

#     days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

#     return [{"day": day, "time_slots": time_slots} for day in days]


class NotificationType(str, Enum):
    PAYMENT_CONFIRMATION = "payment_confirmation"
    BOOKING_CONFIRMATION = "booking_confirmation"


class NotificationPreference(BaseModel):
    user_id: PydanticObjectId
    preferences: Dict[NotificationType, bool]  # True = enabled, False = disabled
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "notification_preferences"


class NotificationPreferenceRequest(BaseModel):
    preferences: Dict[NotificationType, bool]

    class Config:
        schema_extra = {
            "example": {
                "preferences": {
                    "payment_confirmation": True,
                    "booking_confirmation": True,
                }
            }
        }


DEFAULT_NOTIFICATION_PREFERENCES = {
    "payment_confirmation": True,
    "booking_confirmation": True,
}


class BloodGroup(str, Enum):
    A = "A"
    B = "B"
    AB = "AB"
    O_plus = "O+"  # "O+" blood group
    O_minus = "O-"  # "O-" blood group
    A_plus = "A+"  # "A+" blood group
    A_minus = "A-"  # "A-" blood group
    B_plus = "B+"  # "B+" blood group
    B_minus = "B-"  # "B-" blood group
    AB_plus = "AB+"  # "AB+" blood group
    AB_minus = "AB-"


class StatusEnum(str, Enum):
    Active = "active"
    Inactive = "inactive"
    Draft = "draft"


class User(Document, BaseModel):
    id: Optional[PydanticObjectId] = Field(default=None, alias="_id")  # Explicitly include id
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="")
    email: Optional[EmailStr] = Indexed(str, default=None)  # Make email optional
    user_image: Optional[str] = None
    user_image_url: Optional[str] = None
    otp: Optional[str] = None  # OTP field
    otp_expires: Optional[datetime] = None
    password: str
    user_role: int = Field(default=1)
    phone: Optional[int] = Field(default=None)
    is_deleted: bool = Field(default=False)
    is_active: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    register_status: int = Field(default=0)
    register_token: Optional[str] = None
    register_expires: Optional[int] = None
    reset_password_token: Optional[str] = None
    reset_password_expires: Optional[int] = None
    user_profile: Optional[str] = None
    gender: Gender = Field(default=Gender.male)
    blood_group: Optional[BloodGroup] = None
    dob: Optional[str] = None
    status: StatusEnum = StatusEnum.Active
    roles: List[Role] = Field(default=["user"])
    menu: list = Field(default_factory=list)  # Store assigned menu structure
    address: Optional[Location] = Field(None, description="Location details of the vendor")
    secondary_phone_number: Optional[int] = None
    availability_slots: Optional[List[DaySlot]] = None  # Set as Optional, no default value
    notification_settings: Dict[str, bool] = Field(default_factory=dict)
    vendor_id: Optional[PydanticObjectId] = None
    provider: Optional[str] = None

    class Settings:
        name = "users"

    @staticmethod
    async def get_user_by_email(sub: str):
        # Mock database lookup (replace with your actual DB query)
        try:
            user = await User.find_one({"email": sub})
            if user:
                return user
            else:
                return None
        except Exception as e:
            return None

    @staticmethod
    async def get_user_by_phone(sub: int):
        # Mock database lookup (replace with your actual DB query)
        try:
            user = await User.find_one({"phone": int(sub)})
            if user:
                return user
            else:
                return None
        except Exception as e:
            return None

    # @field_validator("password", mode="before")
    # def hash_password(cls, password: str) -> str:
    #     """Automatically hash passwords before saving, incorporating the SECRET_KEY."""
    #     salted_password = f"{SECRET_KEY}{password}"
    #     hashed_password = hashpw(salted_password.encode("utf-8"), gensalt())
    #     return hashed_password.decode("utf-8")


class CustomValidationError(HTTPException):
    def __init__(self, detail: dict):
        super().__init__(status_code=422, detail=detail)
