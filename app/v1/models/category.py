import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator
from slugify import slugify

from app.v1.config.constants import SECRET_KEY


class StatusEnum(str, Enum):
    Active = "active"
    Inactive = "inactive"
    Draft = "draft"


class Category(Document, BaseModel):
    id: Optional[PydanticObjectId] = Field(default=None, alias="_id")
    name: str = Field(..., min_length=1, max_length=50)
    slug: Optional[str] = None  # Add slug field
    status: StatusEnum = Field(default=StatusEnum.Active)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    number_of_views: int = Field(default=0)
    icon: Optional[str] = None

    class Settings:
        name = "categories"

    def generate_slug(self):
        """Generate and set the slug based on the name."""
        self.slug = slugify(self.name)

    async def save(self, *args, **kwargs):
        """Override save method to generate slug on creation."""
        if not self.slug:  # Only generate slug if it doesn't exist
            self.generate_slug()
        self.updated_at = datetime.utcnow()  # Update timestamp on save
        return await super().save(*args, **kwargs)
