from datetime import datetime
from enum import Enum
from typing import List, Optional

import bcrypt
import zon

from pydantic import BaseModel, EmailStr, Field, validator

from app.v1.utils.response.response_format import validation_error


# class Gender(str, Enum):
#     male = "male"
#     female = "female"
#     other = "other"
# class Role(str, Enum):
#     admin = "admin"
#     user = "user"
#     vendor = "vendor"

# class BusinessType(str, Enum):
#     individual = "individual"
#     business = "business"

# class Service(BaseModel):
#     id: str
#     name: Optional[str] = None
# # Validator for vendor creation
# vendor_user_create_validator = zon.record({
#     "name": zon.string().min(1).max(50),
#     "email": zon.string().email(),
#     "phone": zon.string().min(10).max(10),
#     # "password": zon.string().min(6).max(20),
# })

# # Request model for vendor creation
# class VendorUserCreateRequest(BaseModel):
#     first_name: str
#     last_name: str
#     email: EmailStr
#     phone: str
#     gender: Gender = Field(default=Gender.Male)
#     roles: list[Role] = [Role.vendor]  # Default role is 'vendor'
#     business_type: BusinessType=Field(default=BusinessType.individual)
#     business_name: Optional[str] = Field(None, max_length=100)
#     business_address: Optional[str] = Field(None, max_length=255)
#     business_details: Optional[str] = None
#     category_id: Optional[str] = Field(None, description="ID of the selected category")
#     category_name: Optional[str] = Field(None, description="Name of the selected category")
#     services: Optional[List[Service]] = Field(
#         None,
#         description="List of selected services with their IDs and names"
#     )
#     service_details: Optional[str] = None

#     # Additional Fields
#     manage_plan: Optional[str] = None
#     manage_fee_and_gst: Optional[str] = None
#     manage_offer: Optional[str] = None
#     # password: str

#     @validator("roles", pre=True, always=True)
#     def ensure_vendor_role(cls, roles):
#         """
#         Ensure that the 'vendor' role is always present in the roles list.
#         """
#         if Role.vendor not in roles:
#             roles.append(Role.vendor)
#         return roles

#     def validate(self):
#         """
#         Validate the request data using Zon.
#         """
#         try:
#             vendor_create_validator.validate(self.dict(exclude={"roles"}))  # Exclude roles from zon validation
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None

# vendor_list_validator = zon.record({

# })

# class VendorListRequest(BaseModel):

#     def validate(self):
#         try:
#             vendor_list_validator.validate(self.dict())
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None

# get_vendor_validator = zon.record({
#     "id": zon.string().min(1).max(50),
# })

# class GetVendorRequest(BaseModel):
#     id: str

#     def validate(self):
#         try:
#             get_vendor_validator.validate(self.dict())
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None

# update_vendor_validator = zon.record({
#     "first_name": zon.string().min(1).max(50).optional(),
#     "last_name": zon.string().min(1).max(50).optional(),
#     "email": zon.string().email().optional(),
#     "phone": zon.string().min(10).max(10).optional(),
#     "vendor_address": zon.string().optional(),
#     "vendor_details": zon.string().optional(),
# })

# class UpdateVendorRequest(BaseModel):
#     first_name: Optional[str] = None
#     last_name: Optional[str] = None
#     email: Optional[EmailStr] = None
#     phone: Optional[str] = None
#     gender: Gender = Field(default=Gender.Male)
#     business_type: BusinessType=Field(default=BusinessType.individual)
#     business_name: Optional[str] = Field(None, max_length=100)
#     business_address: Optional[str] = Field(None, max_length=255)
#     business_details: Optional[str] = None
#     category_id: Optional[str] = Field(None, description="ID of the selected category")
#     category_name: Optional[str] = Field(None, description="Name of the selected category")
#     services: Optional[List[Service]] = Field(
#         None,
#         description="List of selected services with their IDs and names"
#     )
#     service_details: Optional[str] = None

#     # Additional Fields
#     manage_plan: Optional[str] = None
#     manage_fee_and_gst: Optional[str] = None
#     manage_offer: Optional[str] = None

#     def validate(self):
#         try:
#             update_vendor_validator.validate(self.dict())
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None

# delete_vendor_validator = zon.record({
#     "id": zon.string().min(1).max(50),
# })

# class DeleteVendorRequest(BaseModel):
#     id: str

#     def validate(self):
#         try:
#             delete_vendor_validator.validate(self.dict())
#         except zon.error.ZonError as e:
#             error_message = ", ".join([f"{issue.message} for value '{issue.value}'" for issue in e.issues])
#             return validation_error({"message": f"Validation Error: {error_message}"})
#         return None
