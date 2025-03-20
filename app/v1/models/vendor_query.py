import os
import random
import string

from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum


class VendorQuery(BaseModel):
    name: str
    email: str
    query_type: str
    description: str
    reply: Optional[str] = None
    status: StatusEnum = StatusEnum.Active
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendor_queries"
