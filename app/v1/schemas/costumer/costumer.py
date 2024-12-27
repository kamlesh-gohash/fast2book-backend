import zon
from pydantic import BaseModel, EmailStr, validator, Field
from app.v1.utils.response.response_format import validation_error
from typing import Optional
import bcrypt
from datetime import datetime
from app.v1.models.category import StatusEnum
from enum import Enum
from app.v1.models.user import StatusEnum
class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"
class Gender(str, Enum):
    male = "male"
    female = "female"
    other = "other"
class Role(str, Enum):
    admin = "admin"
    user = "user"
    vendor = "vendor"
costumer_create_validator = zon.record({
    "first_name": zon.string().min(1).max(50),
    "last_name": zon.string().min(1).max(50),
    "email": zon.string().email(),
    "phone": zon.string().min(10).max(10),
    # "password": zon.string().min(6).max(20),
})

class CostumerCreateRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    gender: Gender = Field(default=Gender.male)
    roles: list[Role] = [Role.user]
    status: StatusEnum = StatusEnum.ACTIVE
    costumer_address: Optional[str] = None
    costumer_details: Optional[str] = None
    # password: str

    @validator("roles", pre=True, always=True)
    def ensure_user_role(cls, roles):
        """
        Ensure that the 'vendor' role is always present in the roles list.
        """
        if Role.user not in roles:
            roles.append(Role.user)
        return roles

    def validate(self):
        try:
            costumer_create_validator.validate(self.dict(exclude={"roles"}))
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
costumer_list_validator = zon.record({
    
})

class CostumerListRequest(BaseModel):
    
    def validate(self):
        try:
            costumer_list_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
get_costumer_validator = zon.record({
    "id": zon.string().min(1).max(50),
})    

class GetCostumerRequest(BaseModel):
    id: str
    
    def validate(self):
        try:
            get_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None

update_costumer_validator = zon.record({
    "first_name": zon.string().min(1).max(50).optional(),
    "last_name": zon.string().min(1).max(50).optional(),
    "email": zon.string().email().optional(),
    "phone": zon.string().min(10).max(10).optional(),
    "costumer_address": zon.string().optional(),
    "costumer_details": zon.string().optional(),
})

class UpdateCostumerRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    status: StatusEnum = StatusEnum.ACTIVE
    gender: Gender = Gender.male
    costumer_address: Optional[str] = None
    costumer_details: Optional[str] = None
    
    def validate(self):
        try:
            update_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    

delete_costumer_validator = zon.record({
    "id": zon.string().min(1).max(50),
})

class DeleteCostumerRequest(BaseModel):
    id: str
    
    def validate(self):
        try:
            delete_costumer_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    