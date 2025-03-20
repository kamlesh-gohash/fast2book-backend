import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import pytz

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status
from slugify import slugify

from app.v1.middleware.auth import get_current_user
from app.v1.models import category_collection, services_collection
from app.v1.models.category import Category
from app.v1.models.user import User
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class CategoryManager:

    async def create_category(self, current_user: User, category_request: Category) -> dict:
        """
        category creating
        """
        try:
            # current_user = await get_current_user(request=request, token=token)
            # if not current_user:
            #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
            #     raise HTTPException(
            #         status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
            #     )
            existing_categorys = await category_collection.find_one(
                {"name": {"$regex": f"^{category_request.name}$", "$options": "i"}}
            )

            if existing_categorys:
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
                "icon": created_category["icon"] if "icon" in created_category else None,
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
        self,
        request: Request,
        current_user: User,
        page: int = 1,
        limit: int = 10,
        search: str = None,
        statuss: str = None,
    ) -> dict:
        """
        Get list of all active categories.
        """
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
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
            if statuss:
                query["status"] = statuss
            active_categories = await category_collection.find({**query}).skip(skip).limit(limit).to_list(length=100)
            category_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")  # IST timezone
            for category in active_categories:
                # Convert created_at to IST
                created_at = category.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    category["created_at"] = created_at_ist.isoformat()
                else:
                    category["created_at"] = str(created_at)

                category_data.append(
                    {
                        "id": str(category["_id"]),
                        "name": category["name"],
                        "slug": category.get("slug"),  # Use .get() to avoid KeyError
                        "status": category["status"],
                        "icon": category["icon"] if "icon" in category else None,
                        "created_at": category["created_at"],
                    }
                )
            total_categories = await category_collection.count_documents({})
            total_pages = (total_categories + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": category_data,
                "paginator": {
                    "itemCount": total_categories,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }
            # return {"data": category_data, "total_items": total_categories, "total_pages": total_pages}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_category_by_id(self, current_user: User, id: str) -> dict:
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
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
                "icon": category["icon"] if "icon" in category else None,
                "created_at": category["created_at"],
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_category_by_id(self, current_user: User, id: str, category_request: Category) -> dict:
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
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
                if category_request.name != existing_category.get("name"):
                    existing_categorys = await category_collection.find_one(
                        {"name": {"$regex": f"^{category_request.name}$", "$options": "i"}}
                    )
                    if existing_categorys:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Category with name '{category_request.name}' already exists.",
                        )
                update_data["name"] = category_request.name

            if category_request.status:
                update_data["status"] = category_request.status.value
            if category_request.icon:
                update_data["icon"] = category_request.icon

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
                "icon": updated_category["icon"] if "icon" in updated_category else None,
                "created_at": updated_category["created_at"],
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def delete_category_by_id(self, current_user: User, id: str) -> dict:
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

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
