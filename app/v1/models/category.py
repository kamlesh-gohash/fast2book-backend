import os
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List
from enum import Enum
from app.v1.config.constants import SECRET_KEY
from beanie import PydanticObjectId  # Import PydanticObjectId


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class Category(Document, BaseModel):
    id: Optional[PydanticObjectId] = Field(default=None, alias="_id")
    name: str = Field(..., min_length=1, max_length=50)
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)

    class Settings:
        name = "categories"
