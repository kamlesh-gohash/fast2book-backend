import zon
from pydantic import BaseModel, EmailStr,validator
from app.v1.utils.response.response_format import validation_error
from typing import Optional
import bcrypt
from datetime import datetime
from app.v1.models.category import StatusEnum
from app.v1.models.category import Category
from beanie import PydanticObjectId
from bson import ObjectId
from enum import Enum


class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"

# Validators
create_service_validator = zon.record({
    "name": zon.string(),
    "category_id": zon.string(),
    "status": zon.string(),
})

# Pydantic Model for Service Request
class CreateServiceRequest(BaseModel):
    name: str
    category_id: str
    status: StatusEnum = StatusEnum.ACTIVE

    @validator("category_id", pre=True)
    def validate_category_id(cls, v):
        if isinstance(v, str) and ObjectId.is_valid(v):
            return v
        raise ValueError("Invalid Category ID")

    @validator("status")
    def validate_status(cls, v):
        if v not in StatusEnum.__members__.values():
            raise ValueError(f"Invalid status. Valid options are {', '.join(StatusEnum.__members__.keys())}")
        return v

    def to_object_id(self):
        try:
            if isinstance(self.category_id, str) and ObjectId.is_valid(self.category_id):
                self.category_id = ObjectId(self.category_id)
            else:
                raise ValueError("Invalid Category ID for conversion")
        except Exception as e:
            print(f"Error converting to ObjectId: {e}")
            raise e

    def validate(self):
        """Validates the service request using the zon validator."""
        try:
            create_service_validator.validate({
                "name": self.name,
                "category_id": self.category_id,  # Already validated as a string
                "status": self.status.value,     # Enum to string
            })
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return {"status": "VALIDATION_ERROR", "message": f"Validation Error: {error_message}", "data": None}
        return None

list_service_validator = zon.record({
    
})

class ListServiceRequest(BaseModel):
    
    def validate(self):
        try:
            list_service_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
get_service_validator = zon.record({
    "id": zon.string()
})    

class GetServiceRequest(BaseModel):
    id: str

    def validate(self):    
        try:
            get_service_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
update_service_validator = zon.record({
    "name": zon.string().optional(),
    "category_id": zon.string().optional(),
    "status": zon.string().optional(),
})

class UpdateServiceRequest(BaseModel):
    name: Optional[str] = None 
    category_id: Optional[str] = None
    status: Optional[StatusEnum] = None

    def validate(self):
        try:
            update_service_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
    
delete_service_validator = zon.record({
    "id": zon.string()
})    

class DeleteServiceRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_service_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None

category_list_validator_for_service = zon.record({
    
})    

class CategoryListForServiceRequest(BaseModel):
    def validate(self):
        try:
            category_list_validator_for_service.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None