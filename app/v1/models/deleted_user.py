import os

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorClient  # Example for MongoDB
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config import DATABASE_NAME, DATABASE_URL
from app.v1.config.constants import SECRET_KEY


class DeletedUser(Document):
    original_user_id: PydanticObjectId
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    roles: List[str] = []
    user_data: dict
    reason: str
    description: str
    deleted_at: datetime = datetime.utcnow()

    class Settings:
        name = "deleted_users"
        indexes = ["original_user_id", "email", "phone", "deleted_at"]
