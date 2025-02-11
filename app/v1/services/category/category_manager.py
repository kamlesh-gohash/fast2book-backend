import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status
from slugify import slugify

from app.v1.middleware.auth import get_current_user
from app.v1.models import category_collection, services_collection
from app.v1.models.category import Category
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class CategoryManager:

    async def create_category(self, request: Request, token: str, category_request: Category) -> dict:
        """
        category creating
        """
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            existing_category = await category_collection.find_one({"name": category_request.name})

            if existing_category:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Category with name '{category_request.name}' already exists.",
                )
            slug = slugify(category_request.name)
            category_data = {
                "name": category_request.name,
                "slug": slug,
                "status": category_request.status.value,
                "created_at": datetime.utcnow(),
            }

            result = await category_collection.insert_one(category_data)

            created_category = await category_collection.find_one({"_id": result.inserted_id})
            response_data = {
                "id": str(result.inserted_id),
                "name": created_category["name"],
                "slug": created_category["slug"],
                "status": created_category["status"],
                "created_at": created_category["created_at"],
            }

            return response_data

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def category_list(
        self, request: Request, token: str, page: int = 1, limit: int = 10, search: str = None
    ) -> dict:
        """
        Get list of all active categories.
        """
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Fetch all active categories
            skip = (page - 1) * limit
            query = {}
            if search:
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"name": search_regex},
                    {"slug": search_regex},
                    {"category_name": search_regex},
                ]
            active_categories = await category_collection.find({**query}).skip(skip).limit(limit).to_list(length=100)
            category_data = [
                {
                    "id": str(category["_id"]),
                    "name": category["name"],
                    "slug": category["slug"] if "slug" in category else None,
                    "status": category["status"],
                    "created_at": category["created_at"],
                }
                for category in active_categories
            ]
            total_categories = await category_collection.count_documents({})
            total_pages = (total_categories + limit - 1) // limit
            return {"data": category_data, "total_items": total_categories, "total_pages": total_pages}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_category_by_id(self, request: Request, token: str, id: str) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Convert the string ID to ObjectId
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: '{id}'")

            category = await category_collection.find_one({"_id": ObjectId(id)})
            if not category:
                return None

            # Format the result
            return {
                "id": str(category["_id"]),
                "name": category["name"],
                "slug": category["slug"] if "slug" in category else None,
                "status": category["status"],
                "created_at": category["created_at"],
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_category_by_id(self, request: Request, token: str, id: str, category_request: Category) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: '{id}'")

            # Check if the category exists
            existing_category = await category_collection.find_one({"_id": ObjectId(id)})
            if not existing_category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Category with ID '{id}' not found")

            # Prepare the update data
            update_data = {}
            if category_request.name:
                update_data["name"] = category_request.name
            if category_request.status:
                update_data["status"] = category_request.status.value

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )

            # Perform the update
            result = await category_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            if result.matched_count == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Category with ID '{id}' not found")

            updated_category = {**existing_category, **update_data}

            return {
                "id": str(updated_category["_id"]),
                "name": updated_category["name"],
                "slug": updated_category["slug"] if "slug" in updated_category else None,
                "status": updated_category["status"],
                "created_at": updated_category["created_at"],
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def delete_category_by_id(self, request: Request, token: str, id: str) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: '{id}'")

            existing_category = await category_collection.find_one({"_id": ObjectId(id)})
            if not existing_category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Category with ID '{id}' not found")

            query = {"category_id": ObjectId(id)}  # or {"category_id": id} based on field type

            result_services = await services_collection.update_many(query, {"$set": {"status": "inactive"}})

            # Proceed even if no services are updated
            result = await category_collection.delete_one({"_id": ObjectId(id)})

            if result.deleted_count == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Category with ID '{id}' not found")

            return {"data": None}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )
