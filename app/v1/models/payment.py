from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, Field, validator

from app.v1.models.user import StatusEnum


class PaymentType(BaseModel):
    name: str = Field(..., unique=True)
    description: str
    status: StatusEnum = StatusEnum.Active
    existing_names: ClassVar[set] = set()  # Keep track of existing names
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @validator("name")
    def check_unique_name(cls, value):
        if value in cls.existing_names:
            raise ValueError(f"The name '{value}' already exists!")
        cls.existing_names.add(value)
        return value
