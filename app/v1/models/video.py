import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from fastapi import File, UploadFile
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY
from app.v1.models.user import *
from app.v1.models.vendor import *


class VideoType(str, Enum):
    url = "url"
    file = "file"


class Video(Document):
    name: str
    description: str
    tags: str
    thumbnail_image: Optional[str] = None
    thumbnail_image_url: Optional[str] = None
    videoType: VideoType
    video_url: Optional[str] = None
    video_file: Optional[UploadFile] = None
    video_file_url: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "videos"
