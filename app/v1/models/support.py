import os

from datetime import datetime

# from app.v1.models.transactions import Transaction
from typing import Dict

from beanie import Link
from pydantic import BaseModel

from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.slots import *
from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor


class Support(BaseModel):
    user_id: Link[User]  # Link to the user who made the request
    title: str
    description: str
    is_open: bool = True

    class Settings:
        name = "support"
