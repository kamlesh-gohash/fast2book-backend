import os
import random
import string

from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum


class Ticket(BaseModel):
    email: str
    issue_image: Optional[str] = None
    issue_image_url: Optional[str] = None
    ticket_type: str
    ticket_number: Optional[str] = None
    description: str
    reply: Optional[str] = None
    status: StatusEnum = StatusEnum.Active
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @staticmethod
    def generate_ticket_number():
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        random_str = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"TICKET-{timestamp}-{random_str}"

    class Settings:
        name = "tickets"
