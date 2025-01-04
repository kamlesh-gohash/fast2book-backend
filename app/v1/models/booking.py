import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, Link, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.user import StatusEnum, User


class SuperAdminBooking(BaseModel):
    user: Link[User]
    category: Link[Category]
    service: Link[Service]
    booking_date: datetime
    vendor: Link[User]
    price: float
    description: str
    status: StatusEnum = StatusEnum.Active

    class Settings:
        name = "super_admin_bookings"
