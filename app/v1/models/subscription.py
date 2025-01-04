import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class Subscription(Document):
    title: str = Field(..., min_length=1, max_length=50)
    price: float
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)
