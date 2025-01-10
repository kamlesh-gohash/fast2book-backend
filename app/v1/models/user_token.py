import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY


class UserToken(BaseModel):
    user_id: str = Field(..., description="User ID as a string (email or ObjectId)")
    access_token: str = Field(..., description="Token value")
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "user_tokens"
