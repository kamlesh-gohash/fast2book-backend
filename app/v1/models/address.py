from datetime import datetime
from typing import Optional

from beanie import Document, Link
from pydantic import BaseModel, Field

from app.v1.models.user import User


class Address(Document, BaseModel):
    house_number: str = Field(..., min_length=1, max_length=10)
    street: Optional[str] = Field(None, max_length=255)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=1, max_length=100)
    zip_code: str = Field(..., min_length=5, max_length=10)
    country: str = Field(..., min_length=1, max_length=100)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Foreign key to User model
    user_id: Link["User"]

    class Settings:
        name = "addresses"
