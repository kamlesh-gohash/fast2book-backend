from beanie import Document, Indexed
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime
from bcrypt import hashpw, gensalt
import pdb
# pdb.set_trace()


class TimeZoneDetails(BaseModel):
    value: Optional[str]
    name: Optional[str]


class CurrencyDetails(BaseModel):
    value: Optional[str]
    name: Optional[str]


class LanguageDetails(BaseModel):
    value: Optional[str]
    name: Optional[str]


class CountryDetails(BaseModel):
    value: Optional[str]
    name: Optional[str]


class User(Document):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="")
    email: Indexed(EmailStr, unique=True)
    password: str
    user_role: int = Field(default=1)
    phone: Optional[str] = Field(default=None, pattern=r"^\+?[0-9\-]{7,20}$")  # Updated to use `pattern`
    is_deleted: bool = Field(default=False)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    register_status: int = Field(default=0)
    register_token: Optional[str] = None
    register_expires: Optional[int] = None
    reset_password_token: Optional[str] = None
    reset_password_expires: Optional[int] = None
    user_profile: Optional[str] = None

    class Settings:
        name = "users"  # MongoDB collection name

    @field_validator("password", mode="before")
    def hash_password(cls, password: str) -> str:
        """Automatically hash passwords before saving."""
        return hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")
