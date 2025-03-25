from datetime import datetime
from enum import Enum
from typing import Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, root_validator, validator

from app.v1.models.category import StatusEnum
from app.v1.models.user import CustomValidationError, StatusEnum
from app.v1.utils.response.response_format import validation_error


rating_validator = zon.record(
    {
        "user_id": zon.string().min(1).max(50).optional(),
        "vendor_id": zon.string().min(1).max(50).optional(),
        "rating": zon.number().int().min(1).max(5).optional(),
        "review": zon.string().min(1).max(50).optional(),
    }
)


class Rating(BaseModel):
    user_id: Optional[str] = None
    vendor_id: Optional[str] = None
    rating: Optional[float] = None
    review: Optional[str] = None

    def validate(self):
        try:
            rating_validator.validate(self.dict())
        except zon.error.ZonError as e:
            raise CustomValidationError(detail=validation_error(e))
        return None
