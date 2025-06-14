import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY
from app.v1.models.user import *
from app.v1.models.vendor import *


class Notification(BaseModel):
    user_id: Link[User]
    seen: bool
    sent: bool
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    user_image_url: Optional[str] = None
    message_title: str
    message: str
    url: str

    class settings:
        name = "notifications"
