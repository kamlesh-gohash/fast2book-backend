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
    # availability_slots: Optional[Link["SlotRequest"]] = None
    availability_slots: List[DaySlot] = Field(default_factory=default_availability_slots)
    fees: float = Field(default=0.0)
    location: Optional[List[float]] = Field(None, description="Location of the vendor as [latitude, longitude]")
    specialization: Optional[str] = None
    razorpay_customer_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"
