import os

from datetime import datetime
from enum import Enum
from typing import List, Optional

from bcrypt import gensalt, hashpw
from beanie import PydanticObjectId  # Import PydanticObjectId
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.v1.config.constants import SECRET_KEY
from app.v1.models.user import *
from app.v1.models.vendor import *


class VendorRating(Document):
    vendor_user_id: Link[User]
    vendor_id: Link[Vendor]
    rating: float
    review: str

    class Settings:
        name = "vendor_ratings"
