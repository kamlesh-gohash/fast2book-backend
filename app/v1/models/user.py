from beanie import Indexed
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List 
from enum import Enum 

# enum for gender
class Gender(str, Enum):
    male = "male"
    female = "female"

# enum for role
class Role(str, Enum):
    admin = "admin"
    user = "user"
    student = "vendor"

class User(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="")
    email: EmailStr = Indexed(str, unique=True)
    password: str
    user_role: int = Field(default=1)
    phone: Optional[str] = Field(default=None, pattern=r"^\+?[0-9\-]{7,20}$",unique=True)  # Updated to use `pattern`
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
    gender: Gender = Field(default=Gender.male)
    roles: List[Role] = Field(default=["user"])

    class Settings:
        name = "users" 

    @field_validator("password", mode="before")
    def hash_password(cls, password: str) -> str:
        """Automatically hash passwords before saving."""
        return hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")