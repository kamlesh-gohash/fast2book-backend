from typing import Optional

import zon

from pydantic import BaseModel

from app.v1.models.video import *
from app.v1.utils.response.response_format import validation_error


video_upload_validator = zon.record(
    {
        "name": zon.string().min(1).max(50),
        "description": zon.string().min(1).max(500),
        "tags": zon.string().min(1).max(50),
        "thumbnail_image": zon.string().optional(),
        "video_url": zon.string().optional(),
        "video_file": zon.string().optional(),
    }
)


class VideoUploadRequest(BaseModel):
    name: str
    description: str
    tags: str
    thumbnail_image: Optional[str] = None
    thumbnail_image_url: Optional[str] = None
    videoType: VideoType
    video_url: Optional[str] = None
    video_file: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: StatusEnum = Field(default=StatusEnum.Active)

    def validate(self):
        """
        Validate the request data using Zon.
        """
        try:
            video_upload_validator.validate(self.dict(exclude={"roles"}))  # Exclude roles from zon validation
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


video_update_validator = zon.record(
    {
        "name": zon.string().min(1).max(50).optional(),
        "description": zon.string().min(1).max(500).optional(),
        "tags": zon.string().min(1).max(50).optional(),
        "thumbnail_image": zon.string().optional(),
        "thumbnail_image_url": zon.string().optional(),
        "videoType": zon.string().optional(),
        "video_url": zon.string().optional(),
        "video_file": zon.string().optional(),
    }
)


class VideoUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None
    thumbnail_image: Optional[str] = None
    thumbnail_image_url: Optional[str] = None
    videoType: Optional[VideoType] = None
    video_url: Optional[str] = None
    video_file: Optional[str] = None
    status: Optional[StatusEnum] = None

    def validate(self):
        """
        Validate the request data using Zon.
        """
        try:
            video_update_validator.validate(self.dict(exclude={"roles"}))  # Exclude roles from zon validation
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
