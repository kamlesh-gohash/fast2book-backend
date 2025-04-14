from datetime import datetime
from typing import ClassVar, Literal

from beanie import Document
from pydantic import BaseModel, Field, validator

from app.v1.models.user import StatusEnum


class TransferAmount(Document):
    value: float = Field(default=0.0, ge=0.0, le=100.0)  # Percentage (0.0 to 100.0)

    class Settings:
        name = "transferamount"
