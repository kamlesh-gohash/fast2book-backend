from datetime import datetime, time, timedelta
from enum import Enum
from typing import Dict, List

from beanie import Link
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum, User


class TableType(str, Enum):
    DASHBOARD = "dashboard"
    AGENCY_MANAGEMENT = "agency_management"
    INQUIRY_MANAGEMENT = "inquiry_management"
    TESTIMONIAL_MANAGEMENT = "testimonial_management"


# Permission model
class Permission(BaseModel):
    user_id: Link[User]  # Link to the User (sub-admin)
    table: TableType  # The table the permission applies to
    actions: Dict[str, bool]  # Actions with true/false values (view, edit, etc.)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "permissions"


# Input model for assigning permissions
class PermissionAssignRequest(BaseModel):
    user_id: Link[User]  # The ID of the user
    permissions: List[dict]  # List of permissions with table and actions

    class Config:
        schema_extra = {
            "example": {
                "user_id": "64f21cabc3c2ab1e54d302dc",
                "permissions": [
                    {"table": "dashboard", "actions": {"view": True, "edit": False, "create": True, "delete": False}},
                    {
                        "table": "agency_management",
                        "actions": {"view": True, "edit": True, "create": False, "delete": False},
                    },
                ],
            }
        }
