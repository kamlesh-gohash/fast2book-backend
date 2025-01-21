import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import Document, Indexed, PydanticObjectId, before_event
from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_validator
from slugify import slugify

from app.v1.config.constants import SECRET_KEY


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class Blog(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(..., min_length=1, max_length=5000)
    blog_url: Optional[str] = None
    image: Optional[str] = Field(None, min_length=3, max_length=255)  # Optional field

    # blog_image: Optional[str] = None
    # blog_image_url: Optional[str] = None  # Optional field
    author_name: Optional[str] = Field(None, min_length=3, max_length=255)
    category: Optional[str] = Field(None, min_length=1, max_length=50)  # Category field is now optional
    tags: Optional[List[str]] = None  # Making tags optional
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "blogs"

    @before_event("insert")
    def generate_blog_url(self):
        """Generate the blog URL as a slug based on the title before insertion."""
        if not self.blog_url and self.title:  # Ensure title exists
            self.blog_url = slugify(self.title)
        elif not self.title:
            raise ValueError("Blog title is required to generate the blog URL.")
