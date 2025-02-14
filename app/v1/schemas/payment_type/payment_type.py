from datetime import datetime
from enum import Enum
from typing import Literal, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, validator

from app.v1.models.category import StatusEnum
from app.v1.models.user import StatusEnum
from app.v1.utils.response.response_format import validation_error


update_payment_validator = zon.record(
    {
        "name": zon.string().min(1).max(50).optional(),
        "status": zon.string().min(1).max(50).optional(),
        "charge_type": zon.string().min(1).max(50).optional(),
        "charge_value": zon.number().optional(),
    }
)


class UpdatePaymentRequest(BaseModel):
    name: Optional[str] = None
    status: StatusEnum = StatusEnum.Active
    charge_type: Literal["percentage", "fixed"] = None
    charge_value: float = 0

    def validate(self):
        try:
            update_payment_validator.validate(self.dict())
        except zon.error.ZonError as e:
            error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
            return validation_error({"message": f"Validation Error: {error_message}"})
        return None
