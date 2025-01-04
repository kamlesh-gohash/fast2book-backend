import os
from beanie import Document, Indexed, before_event, Link
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List
from enum import Enum
from app.v1.config.constants import SECRET_KEY
from beanie import PydanticObjectId  # Import PydanticObjectId
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.user import User
from app.v1.models.user import StatusEnum


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
