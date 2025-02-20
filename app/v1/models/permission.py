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
        "icon": "dashboard",
        "path": "/super-admin/dashboard",
        "status": True,
        "actions": {
            "List": True,
            "totalBookings": True,
            "cancelBookings": True,
            "reScheduleBookings": True,
            "totalCustomer": True,
            "appointmentList": True,
        },
    },
    {
        "id": "category",
        "title": "Category Management",
        "icon": "category-management",
        "path": "/super-admin/category-management",
        "status": True,
        "actions": {
            "List": True,
            "addCategory": True,
            "editCategory": True,
            "deleteCategory": True,
            "categoryStatus": True,
        },
    },
    {
        "id": "service-management",
        "title": "Service Management",
        "icon": "service-management",
        "path": "/super-admin/service-management",
        "status": True,
        "actions": {
            "List": True,
            "addServices": True,
            "editServices": True,
            "deleteServices": True,
            "servicesStatus": True,
        },
    },
    {
        "id": "subscription",
        "title": "Subscription Management",
        "icon": "subscription-managemen",
        "path": "/super-admin/subscription-management",
        "status": True,
        "actions": {"List": True, "deleteSubscription": True, "addSubscription": True},
    },
    {
        "id": "vendor-management",
        "title": "Vendor Management",
        "icon": "vendor-management",
        "path": "/super-admin/vendor-management",
        "status": True,
        "actions": {"List": True, "addVendor": True, "editVendor": True, "deleteVendor": True, "vendorStatus": True},
    },
    {
        "id": "costumer-management",
        "title": "Customer Management",
        "icon": "costumer-management",
        "path": "/super-admin/customer-management",
        "status": True,
        "actions": {
            "List": True,
            "addCostumer": True,
            "editCostumer": True,
            "deleteCostumer": True,
            "costumerStatus": True,
        },
    },
    {
        "id": "user-management",
        "title": "User Management",
        "icon": "user-management",
        "path": "/super-admin/user-management",
        "status": True,
        "actions": {"List": True, "addUser": True, "editUser": True, "deleteUser": True, "userStatus": True},
    },
    {
        "id": "booking",
        "title": "Booking",
        "icon": "booking",
        "path": "/super-admin/booking-management",
        "status": True,
        "actions": {"List": True},
    },
    {
        "id": "blog-management",
        "title": "Blog Management",
        "icon": "blog-management",
        "path": "/super-admin/blog-management",
        "status": True,
        "actions": {"List": True, "addBlog": True, "editBlog": True, "deleteBlog": True, "blogStatus": True},
    },
    {
        "id": "permissions-management",
        "title": "Permissions Management",
        "icon": "permissions-management",
        "path": "/super-admin/permissions-management",
        "status": True,
        "actions": {"List": True, "editPermissions": True},
    },
    {
        "id": "support",
        "title": "Support",
        "icon": "support",
        "path": "/super-admin/support",
        "status": True,
        "actions": {"List": True},
    },
    {
        "id": "payment-management",
        "title": "Payment Configuration",
        "icon": "payment-management",
        "path": "/super-admin/payment-configuration",
        "status": True,
        "actions": {"List": True, "editPermissions": True, "permissionsStatus": True},
    },
    {
        "id": "slot",
        "title": "Slot",
        "icon": "slot",
        "path": "/super-admin/setting/slot",
        "status": True,
        "actions": {"List": True, "editSlot": True},
    },
]
