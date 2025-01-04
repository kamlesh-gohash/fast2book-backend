import os
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List
from enum import Enum
from app.v1.config.constants import SECRET_KEY
from beanie import PydanticObjectId  # Import PydanticObjectId


class UserToken(BaseModel):
    user_id: str = Field(..., description="User ID as a string (email or ObjectId)")
    access_token: str = Field(..., description="Token value")
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "user_tokens"
