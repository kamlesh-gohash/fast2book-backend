import os

from datetime import datetime

# from app.v1.models.transactions import Transaction
from typing import Dict, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.slots import *
from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor


class SearchQuery(BaseModel):
    user_id: Optional[Link[User]] = None
    category_id: Optional[Link[Category]] = None
    service_id: Optional[Link[Service]] = None
    location: Optional[Location] = Field(None, description="Location details of the vendor")

    class settings:
        name = "search_query"
