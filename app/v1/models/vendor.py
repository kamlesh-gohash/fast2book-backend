from datetime import datetime
from enum import Enum
from typing import List, Optional

from beanie import Document, Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum, User


class BusinessType(str, Enum):
    individual = "individual"
    business = "business"


class TimeSlot(BaseModel):
    start_time: str
    end_time: str
    max_seat: int = Field(..., gt=0, description="Maximum number of seats for the time slot")


class DaySlot(BaseModel):
    day: str
    time_slots: List[TimeSlot]


class Service(BaseModel):
    id: str
    name: Optional[str] = None


def default_availability_slots():
    time_slots = [
        {"start_time": f"{hour:02}:00", "end_time": f"{hour+1:02}:00", "max_seat": 10} for hour in range(9, 17)
    ]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return [{"day": day, "time_slots": time_slots} for day in days]


class Vendor(Document):
    # vendor_images: Optional[List[str]] = Field(None, description="Array of vendor image URLs")
    vendor_image: Optional[str] = None
    image_url: Optional[str] = None
    business_name: str = Field(..., min_length=1, max_length=50)
    user_id: Link[User]
    business_type: BusinessType = Field(default=BusinessType.individual)
    business_name: Optional[str] = Field(None, max_length=100)
    business_address: Optional[str] = Field(None, max_length=255)
    business_details: Optional[str] = None
    category_id: Optional[str] = Field(None, description="ID of the selected category")
    category_name: Optional[str] = Field(None, description="Name of the selected category")
    services: Optional[List[Service]] = Field(None, description="List of selected services with their IDs and names")
    service_details: Optional[str] = None
    status: StatusEnum = Field(default=StatusEnum.Active)
    availability_slots: Optional[Link["SlotRequest"]] = None
    # availability_slots: List[DaySlot] = Field(default_factory=default_availability_slots)

    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"
