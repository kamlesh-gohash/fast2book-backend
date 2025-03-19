import os

from datetime import datetime

# from app.v1.models.transactions import Transaction
from typing import Dict, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.slots import *
from app.v1.models.user import User
from app.v1.models.vendor import Vendor


class Support(BaseModel):
    # user_id: Optional[Link[User]] = None  # Make user_id optional by defaulting to None
    name: str
    email: str
    phone: str
    message: str
    subject: str
    reply: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "support"
