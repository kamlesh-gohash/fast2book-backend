import random

from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, permission_collection, user_collection
from app.v1.models.permission import *
from app.v1.models.slots import *
from app.v1.schemas.vendor.vendor_auth import *


class PermissionManager:

    async def admin_list(self, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # if current_user.user_role != 2:
            #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")

            query = {
                "roles": {"$regex": "^admin$", "$options": "i"},
                "user_role": {"$ne": 2},  # Exclude users with user_role == 2
            }
            admin_list = await user_collection.find(query).to_list(length=100)

            processed_admin_list = []
            for admin in admin_list:
                processed_admin = {
                    "id": str(admin["_id"]),
                    "email": admin.get("email"),
                    "name": admin.get("first_name") + " " + admin.get("last_name"),
                }
                processed_admin_list.append(processed_admin)

            return processed_admin_list

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def permission_list(self, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            permission_list = DEFAULT_MENU_STRUCTURE
            return {"data": permission_list}

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_permission_by_adminid(self, current_user: User, admin_id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # if current_user.user_role != 2:
            #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")
            if not admin_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin ID is required")

            admin_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
            if not admin_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

            user_id = admin_user["_id"]

            return {"admin_id": admin_id, "permissions": admin_user.get("menu")}

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_permission(self, current_user: User, admin_id: str, updates: dict):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # if current_user.user_role != 2:
            #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")
            if not admin_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin ID is required")

            admin_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
            if not admin_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

            if not isinstance(updates, dict) or "menu" not in updates:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid updates format")

            existing_menu = admin_user.get("menu", [])

            menu_updates = updates["menu"]
            for update_item in menu_updates:
                item_id = update_item.get("id")
                if not item_id:
                    continue

                existing_item = next((item for item in existing_menu if item["id"] == item_id), None)
                if existing_item:
                    if "actions" in update_item:
                        existing_item["actions"].update(update_item["actions"])
                else:
                    new_item = {"id": item_id}
                    if "actions" in update_item:
                        new_item["actions"] = update_item["actions"]
                    existing_menu.append(new_item)

            update_result = await user_collection.update_one(
                {"_id": ObjectId(admin_id)},
                {"$set": {"menu": existing_menu}},
            )

            if update_result.modified_count == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields updated")

            # Fetch the updated user document
            updated_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
            if updated_user:
                updated_user["id"] = str(updated_user["_id"])
                updated_user.pop("_id", None)

            return {"status": "SUCCESS", "message": "Permissions updated successfully", "data": updated_user}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )
