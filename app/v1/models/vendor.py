from datetime import datetime
from enum import Enum
from typing import List, Optional

from beanie import Document, Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum, User


class BusinessType(str, Enum):
    individual = "individual"
    business = "business"


class Service(BaseModel):
    id: str
    name: Optional[str] = None


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
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"
