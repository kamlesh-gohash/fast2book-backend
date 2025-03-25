import os

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from bcrypt import gensalt, hashpw
from beanie import Document, Indexed, PydanticObjectId, before_event
from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_validator
from slugify import slugify

from app.v1.config.constants import SECRET_KEY


class EmailStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class EmailMonitor(BaseModel):

    to_email: EmailStr = Field(..., description="Recipient email address")
    subject: str = Field(..., description="Email subject")
    source: str = Field(..., description="Source/template of the email (e.g., 'Resend OTP')")
    status: EmailStatus = Field(..., description="Status of the email send attempt")
    message: Optional[str] = Field(None, description="Detailed message or error if any")
    sent_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp when email was sent")
    html_content: Optional[str] = Field(None, description="HTML content of the email")
    context: Optional[Dict[str, Any]] = Field(None, description="Context data used for email template")

    class Settings:
        name = "email_monitars"
