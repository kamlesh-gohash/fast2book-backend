from datetime import datetime, time, timedelta
from enum import Enum
from typing import Dict, List, Optional

from beanie import Link, PydanticObjectId
from pydantic import BaseModel, Field

from app.v1.models.user import StatusEnum, User


class TableType(str, Enum):
    DASHBOARD = "dashboard"
    AGENCY_MANAGEMENT = "agency_management"
    INQUIRY_MANAGEMENT = "inquiry_management"
    TESTIMONIAL_MANAGEMENT = "testimonial_management"


# Permission model
class Permission(BaseModel):
    user_id: PydanticObjectId
    table: TableType
    actions: Dict[str, bool]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "permissions"


# Input model for assigning permissions
class PermissionAssignRequest(BaseModel):
    permissions: List[dict]

    class Config:
        schema_extra = {
            "example": {
                "permissions": [
                    {"table": "dashboard", "actions": {"view": True, "edit": False, "create": True, "delete": False}},
                    {
                        "table": "agency_management",
                        "actions": {"view": True, "edit": True, "create": False, "delete": False},
                    },
                ],
            }
        }


DEFAULT_MENU_STRUCTURE = [
    {
        "id": "dashboard",
        "title": "Dashboard",
        "icon": "LayoutDashboard",
        "path": "/dashboard",
        "status": True,
        "actions": {"totalBookings": True, "cancelBookings": False, "reScheduleBookings": True, "totalCustomer": False},
    },
    {
        "id": "overall-bookings",
        "title": "Overall Bookings",
        "icon": "Building2",
        "path": "/overall-bookings",
        "status": True,
        "actions": {"listBookings": True},
    },
    {
        "id": "appointment",
        "title": "Appointment",
        "icon": "MessagesSquare",
        "path": "/appointment",
        "status": True,
        "actions": {"listAppointment": True, "viewAppointment": True},
    },
    {
        "id": "category",
        "title": "Category",
        "icon": "Quote",
        "path": "/category",
        "status": True,
        "actions": {"addCategory": True, "updateCategory": True},
    },
    {
        "id": "services",
        "title": "Services",
        "icon": "Quote",
        "path": "/services",
        "status": True,
        "actions": {"addServices": True, "updateServices": True, "listServices": True, "viewServices": True},
    },
    {
        "id": "subscription",
        "title": "Subscription",
        "icon": "Quote",
        "path": "/subscription",
        "status": True,
        "actions": {
            "addSubscription": True,
            "updateSubscription": True,
            "listSubscription": True,
            "viewSubscription": True,
        },
    },
    {
        "id": "vendor-management",
        "title": "Vendor Management",
        "icon": "Quote",
        "path": "/vendor-management",
        "status": True,
        "actions": {"addVendor": True, "updateVendor": True, "listVendor": True, "viewVendor": True},
    },
    {
        "id": "customer-management",
        "title": "Customer Management",
        "icon": "Quote",
        "path": "/customer-management",
        "status": True,
        "actions": {"addCustomer": True, "updateCustomer": True, "listCustomer": True, "viewCustomer": True},
    },
    {
        "id": "user-management",
        "title": "User Management",
        "icon": "Quote",
        "path": "/user-management",
        "status": True,
        "actions": {"addUser": True, "updateUser": True, "listUser": True, "viewUser": True},
    },
    {
        "id": "bookings",
        "title": "Bookings",
        "icon": "Quote",
        "path": "/bookings",
        "status": True,
        "actions": {"addBookings": True, "updateBookings": True, "listBookings": True, "viewBookings": True},
    },
    {
        "id": "blog-management",
        "title": "Blog Management",
        "icon": "Quote",
        "path": "/blog-management",
        "status": True,
        "actions": {"addBlog": True, "updateBlog": True, "listBlog": True, "viewBlog": True},
    },
]
