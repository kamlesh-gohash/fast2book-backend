import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY
from app.v1.models.category import Category


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class Service(Document):
    name: str = Field(..., min_length=1, max_length=50)
    service_image: Optional[str] = None
    service_image_url: Optional[str] = None
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)
    category_id: PydanticObjectId = Field(..., description="Reference to the Category document")
    category_name: str = Field(..., description="Name of the category")

    class Settings:
        name = "services"
