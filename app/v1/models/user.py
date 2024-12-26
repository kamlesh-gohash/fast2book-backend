import os
from beanie import Document, Indexed, before_event
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from bcrypt import hashpw, gensalt
from typing import Optional, List
from enum import Enum
from app.v1.config.constants import SECRET_KEY
from beanie import PydanticObjectId  # Import PydanticObjectId

# Enum for gender
class Gender(str, Enum):
    male = "male"
    female = "female"

# Enum for role
class Role(str, Enum):
    admin = "admin"
    user = "user"
    vendor = "vendor"  # Fixed from "student" to "vendor"
class BloodGroup(str, Enum):
    A = "A"
    B = "B"
    AB = "AB"
    O_plus = "O+"  # "O+" blood group
    O_minus = "O-"  # "O-" blood group
    A_plus = "A+"  # "A+" blood group
    A_minus = "A-"  # "A-" blood group
    B_plus = "B+"  # "B+" blood group
    B_minus = "B-"  # "B-" blood group
    AB_plus = "AB+"  # "AB+" blood group
    AB_minus = "AB-" 


class User(Document, BaseModel):
    id: Optional[PydanticObjectId] = Field(default=None, alias="_id")  # Explicitly include id
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="")
    email: EmailStr = Indexed(str)
    otp: Optional[str] = None  # OTP field
    otp_expires: Optional[datetime] = None 
    password: str
    user_role: int = Field(default=1)
    phone: Optional[str] = Field(pattern=r"^\+?[0-9\-]{7,20}$")
    is_deleted: bool = Field(default=False)
    is_active: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    register_status: int = Field(default=0)
    register_token: Optional[str] = None
    register_expires: Optional[int] = None
    reset_password_token: Optional[str] = None
    reset_password_expires: Optional[int] = None
    user_profile: Optional[str] = None
    gender: Gender = Field(default=Gender.male)
    blood_group: Optional[BloodGroup] = None
    dob: Optional[str] = None

    roles: List[Role] = Field(default=["user"])

    class Settings:
        name = "users"

    

    # @field_validator("password", mode="before")
    # def hash_password(cls, password: str) -> str:
    #     """Automatically hash passwords before saving, incorporating the SECRET_KEY."""
    #     salted_password = f"{SECRET_KEY}{password}"
    #     hashed_password = hashpw(salted_password.encode("utf-8"), gensalt())
    #     return hashed_password.decode("utf-8")