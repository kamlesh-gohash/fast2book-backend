from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from beanie import Document, Link
from pydantic import BaseModel, Field

from app.v1.models.user import Location, StatusEnum, User


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


# class Location(BaseModel):
#     address_components: Optional[List[Dict]] = Field(None, description="Address components of the location")
#     formatted_address: Optional[str] = Field(None, description="Formatted address of the location")
#     geometry: Optional[Dict] = Field(None, description="Geometry details of the location")
#     place_id: Optional[str] = Field(None, description="Place ID of the location")
#     types: Optional[List[str]] = Field(None, description="Types of the location")
#     url: Optional[str] = Field(None, description="URL of the location")
#     utc_offset_minutes: Optional[int] = Field(None, description="UTC offset in minutes")
#     vicinity: Optional[str] = Field(None, description="Vicinity of the location")
#     website: Optional[str] = Field(None, description="Website of the location")


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
    fees: float = Field(default=0.0)
    location: Optional[Location] = Field(None, description="Location details of the vendor")
    specialization: Optional[str] = None
    razorpay_customer_id: Optional[str] = None
    razorpay_account_id: Optional[str] = None
    is_subscription: bool = Field(default=False)
    is_payment_required: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"
