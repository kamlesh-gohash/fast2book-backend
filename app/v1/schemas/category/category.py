import zon
from pydantic import BaseModel, EmailStr
from app.v1.utils.response.response_format import validation_error
from typing import Optional
import bcrypt
from datetime import datetime
from app.v1.models.category import StatusEnum

create_category_validator = zon.record(
    {
        "name": zon.string(),
    }
)


class CreateCategoryRequest(BaseModel):
    name: str
    status: StatusEnum = StatusEnum.ACTIVE

    def validate(self):
        try:
            create_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


all_category_validator = zon.record({})


class AllCategoryRequest(BaseModel):

    def validate(self):
        try:
            all_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


get_category_validator = zon.record({})


class GetCategoryRequest(BaseModel):
    id: str

    def validate(self):
        try:
            get_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


update_category_validator = zon.record(
    {
        "name": zon.string().optional(),
        "status": zon.string().optional(),
    }
)


# UpdateCategoryRequest with optional fields
class UpdateCategoryRequest(BaseModel):
    name: Optional[str] = None  # Optional field
    status: Optional[StatusEnum] = None  # Optional field

    def validate(self):
        try:
            update_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None


delete_category_validator = zon.record({})


class DeleteCategoryRequest(BaseModel):
    id: str

    def validate(self):
        try:
            delete_category_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
