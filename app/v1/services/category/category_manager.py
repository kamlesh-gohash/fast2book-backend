import random
from app.v1.models.category import Category
from app.v1.models import category_collection
from app.v1.models import services_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body,Path
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token

class CategoryManager:

    async def create_category(self, category_request: Category) -> dict:
        """
        category creating
        """
        try:
            existing_category = await category_collection.find_one({"name": category_request.name})

            if existing_category:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Category with name '{category_request.name}' already exists."
                )
            category_data = {
                "name": category_request.name,
                "status": category_request.status.value,  # Convert Enum to string
                "created_at": datetime.utcnow()  # Optional timestamp
            }
            
            result = await category_collection.insert_one(category_data)
            
            created_category = await category_collection.find_one({"_id": result.inserted_id})
            
            # Format the response to include category name, status, and inserted id
            response_data = {
                "id": str(result.inserted_id),
                "name": created_category["name"],
                "status": created_category["status"],
                "created_at": created_category["created_at"]
            }

            return response_data

        except HTTPException as e:
            raise e 
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def category_list(self, page: int = 1, limit: int = 10, search: str = None)  -> dict:
        """
        Get list of all active categories.
        """
        try:
        # Fetch all active categories
            skip = (page - 1) * limit
            query = {}  # Start with an empty query

            # If there's a search term, modify the query to search by name or category_name
            if search:
                search_regex = {"$regex": search, "$options": "i"}  # Case-insensitive search
                query["$or"] = [
                    {"name": search_regex},  # Search by service name
                    {"category_name": search_regex}  # Search by category name (if the category is loaded)
                ]
            active_categories = await category_collection.find({"status": "active", **query}).skip(skip).limit(limit).to_list(length=100)

            # Format the response with category name, status, and created_at
            category_data = [
                {
                    "id": str(category["_id"]),
                    "name": category["name"],
                    "status": category["status"],
                    "created_at": category["created_at"]
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def get_category_by_id(self, id: str) -> dict:
        try:
            # Convert the string ID to ObjectId
            if not ObjectId.is_valid(id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category ID: '{id}'"
                )

            category = await category_collection.find_one({"_id": ObjectId(id)})
            if not category:
                return None

            # Format the result
            return {
                "id": str(category["_id"]),
                "name": category["name"],
                "status": category["status"],
                "created_at": category["created_at"]
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
            
    async def update_category_by_id(self, id: str, category_request: Category) -> dict:
        try:
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category ID: '{id}'"
                )

            # Check if the category exists
            existing_category = await category_collection.find_one({"_id": ObjectId(id)})
            if not existing_category:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Category with ID '{id}' not found"
                )

            # Prepare the update data
            update_data = {}
            if category_request.name:
                update_data["name"] = category_request.name
            if category_request.status:
                update_data["status"] = category_request.status.value

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid fields provided for update"
                )

            # Perform the update
            result = await category_collection.update_one(
                {"_id": ObjectId(id)},
                {"$set": update_data}
            )

            if result.matched_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Category with ID '{id}' not found"
                )

            # Merge the updated data with the existing data for the response
            updated_category = {**existing_category, **update_data}

            # Format and return the response
            return {
                "id": str(updated_category["_id"]),
                "name": updated_category["name"],
                "status": updated_category["status"],
                "created_at": updated_category["created_at"]
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
    async def delete_category_by_id(self, id: str) -> dict:
        try:
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category ID: '{id}'"
                )

            # Check if the category exists
            existing_category = await category_collection.find_one({"_id": ObjectId(id)})
            if not existing_category:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Category with ID '{id}' not found"
                )

            # Update all services that are using this category to set their status to 'inactive'
            result_services = await services_collection.update_many(
                {"category_id": ObjectId(id)},
                {"$set": {"status": "inactive"}}
            )

            # Check if any services were updated
            if result_services.modified_count == 0:
                print(f"No services found for category ID: {id} to update status")

            # Perform the deletion of the category
            result = await category_collection.delete_one({"_id": ObjectId(id)})

            if result.deleted_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Category with ID '{id}' not found"
                )

            # Format and return the response
            return {
                "data": None
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )