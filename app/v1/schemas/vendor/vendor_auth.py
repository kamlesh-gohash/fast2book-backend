import zon
from pydantic import BaseModel, EmailStr, validator
from app.v1.utils.response.response_format import validation_error
from typing import Optional
import bcrypt
from datetime import datetime
from enum import Enum

class Role(str, Enum):
    admin = "admin"
    user = "user"
    vendor = "vendor"

# Validator for vendor creation
vendor_create_validator = zon.record({
    "name": zon.string().min(1).max(50),
    "email": zon.string().email(),
    "phone": zon.string().min(10).max(10),
    "password": zon.string().min(6).max(20),
})

# Request model for vendor creation
class VendorCreateRequest(BaseModel):
    name: str
    email: EmailStr
    phone: str
    roles: list[Role] = [Role.vendor]  # Default role is 'vendor'
    password: str

    @validator("roles", pre=True, always=True)
    def ensure_vendor_role(cls, roles):
        """
        Ensure that the 'vendor' role is always present in the roles list.
        """
        if Role.vendor not in roles:
            roles.append(Role.vendor)
        return roles

    def validate(self):
        """
        Validate the request data using Zon.
        """
        try:
            vendor_create_validator.validate(self.dict(exclude={"roles"}))  # Exclude roles from zon validation
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
vendor_list_validator = zon.record({
    
})  

class VendorListRequest(BaseModel):
    
    def validate(self):
        try:
            vendor_list_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
get_vendor_validator = zon.record({
    "id": zon.string().min(1).max(50),
})    

class GetVendorRequest(BaseModel):
    id: str
    
    def validate(self):
        try:
            get_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
update_vendor_validator = zon.record({
    "first_name": zon.string().min(1).max(50).optional(),
    "last_name": zon.string().min(1).max(50).optional(),
    "email": zon.string().email().optional(),
    "phone": zon.string().min(10).max(10).optional(),
})    

class UpdateVendorRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    
    def validate(self):
        try:
            update_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
delete_vendor_validator = zon.record({
    "id": zon.string().min(1).max(50),
})    

class DeleteVendorRequest(BaseModel):
    id: str
    
    def validate(self):
        try:
            delete_vendor_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None