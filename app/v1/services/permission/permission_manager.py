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

    async def admin_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # if current_user.user_role != 2:
            #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")

            query = {"roles": {"$regex": "^admin$", "$options": "i"}}
            admin_list = await user_collection.find(query).to_list(length=100)

            # processed_admin_list = []
            # for admin in admin_list:
            #     processed_admin = {
            #         "id": str(admin["_id"]),
            #         **{
            #             key: value
            #             for key, value in admin.items()
            #             if key not in ["_id", "password", "otp"]
            #         }
            #     }
            #     processed_admin_list.append(processed_admin)
            processed_admin_list = []
            for admin in admin_list:
                processed_admin = {
                    "id": str(admin["_id"]),
                    "email": admin.get("email"),
                }
                processed_admin_list.append(processed_admin)

            return processed_admin_list

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def permission_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            permission_list = DEFAULT_MENU_STRUCTURE
            return {"data": permission_list}

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    # async def assign_permission(self, request: Request, token: str, admin_id: str, permission_assign: PermissionAssignRequest):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    #         if current_user.user_role != 2:
    #             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page ")

    #         if not admin_id:
    #             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin ID is required")

    #         admin_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
    #         if not admin_user:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

    #         user_id = admin_user["_id"]

    #         for permission_data in permission_assign.permissions:
    #             table = permission_data.get("table")
    #             actions = permission_data.get("actions")

    #             if table not in TableType._value2member_map_:
    #                 raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid table type: {table}")

    #             existing_permission = await permission_collection.find_one({"user_id": PydanticObjectId(str(user_id)), "table": table})
    #             print(existing_permission, 'existing_permission')

    #             if existing_permission:
    #                 existing_permission.actions = actions
    #                 existing_permission.updated_at = datetime.utcnow()
    #                 await permission_collection.save(existing_permission)
    #             else:
    #                 new_permission = Permission(
    #                     user_id=PydanticObjectId(str(user_id)),
    #                     table=table,
    #                     actions=actions,
    #                     created_at=datetime.utcnow(),
    #                     updated_at=datetime.utcnow(),
    #                 )
    #                 print(new_permission, 'new_permission')
    #                 await permission_collection.insert_one(new_permission.dict(exclude_unset=True))

    #         return {"admin_id": admin_id, "permissions": permission_assign.permissions}

    #     except Exception as ex:
    #         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_permission_by_adminid(self, request: Request, token: str, admin_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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

    # async def update_permission(self, request: Request, token: str, admin_id: str, updates: dict):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(
    #                 status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
    #             )
    #         if current_user.user_role != 2:
    #             raise HTTPException(
    #                 status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
    #             )
    #         if not admin_id:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail="Admin ID is required"
    #             )

    #         admin_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
    #         if not admin_user:
    #             raise HTTPException(
    #                 status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found"
    #             )

    #         if not isinstance(updates, dict):
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid updates format"
    #             )
    #         for item in updates.get("menu", []):
    #             if "title" not in item or "status" not in item:
    #                 raise HTTPException(
    #                     status_code=status.HTTP_400_BAD_REQUEST,
    #                     detail="Each menu item must include 'title' and 'status'.",
    #                 )

    #         updates = jsonable_encoder(updates)
    #         update_result = await user_collection.update_one(
    #             {"_id": ObjectId(admin_id)},
    #             {"$set": {"menu": updates.get("menu", DEFAULT_MENU_STRUCTURE)}},
    #         )

    #         if update_result.modified_count == 0:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail="No fields updated"
    #             )

    #         updated_user = await user_collection.find_one({"_id": ObjectId(admin_id)})
    #         if updated_user:
    #             updated_user["id"] = str(updated_user["_id"])
    #             updated_user.pop("_id", None)
    #         return {"data": updated_user}

    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         print(ex,'ex')
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    #             detail=f"An unexpected error occurred: {str(ex)}",
    #         )

    async def update_permission(self, request: Request, token: str, admin_id: str, updates: dict):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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
