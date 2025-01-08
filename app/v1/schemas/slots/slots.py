from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional

import zon

from beanie import Link
from pydantic import BaseModel, EmailStr, Field, validator

from app.v1.models.slots import *
from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor
from app.v1.utils.response.response_format import validation_error


# slots_create_validator = zon.record(
#     {
#         "date": zon.string().datetime(),  # Expecting string in datetime format
#         "start_time": zon.string().datetime(),
#         "end_time": zon.string().datetime(),
#         "status": zon.enum(StatusEnum),
#     }
# )

# class SlotsCreateRequest(BaseModel):
#     user_id: Optional[Link[User]] = None
#     vendor_id: Optional[Link[Vendor]] = None
#     day: Optional[DayEnum] = None
#     date: Optional[datetime] = None
#     start_time: Optional[datetime] = None
#     end_time: Optional[datetime] = None
#     slots: Optional[List[Slot]] = None
#     status: StatusEnum = StatusEnum.Active

#     def validate(self):
#         try:
#             # Convert datetime fields to ISO format strings
#             valid_data = {key: (value.isoformat() if isinstance(value, datetime) else value) for key, value in self.dict().items() if value is not None}
#             slots_create_validator.validate(valid_data)
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None
