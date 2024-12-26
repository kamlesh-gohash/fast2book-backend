import os
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List
from enum import Enum
from app.v1.config.constants import SECRET_KEY
from beanie import PydanticObjectId  # Import PydanticObjectId
from app.v1.models.category import Category


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"

class Vendor(Document):
    name: str = Field(..., min_length=1, max_length=50)
    email: EmailStr = Field(..., min_length=1, max_length=50)
    phone: Optional[str] = Field(pattern=r"^\+?[0-9\-]{7,20}$")
    otp: Optional[str] = None
    otp_expires: Optional[datetime] = None
    password: str = Field(..., min_length=6, max_length=20)
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"