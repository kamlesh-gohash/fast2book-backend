import random
from app.v1.models.services import Service
from app.v1.models.category import Category
from app.v1.models import services_collection
from app.v1.models import category_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body,Path
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from app.v1.schemas.service.service import CreateServiceRequest, UpdateServiceRequest
class ServicesManager:
    
    async def service_create(self, service_request: CreateServiceRequest) -> dict:
        try:
            category = await category_collection.find_one({"_id": ObjectId(service_request.category_id)})
            if not category:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Category with ID '{service_request.category_id}' does not exist."
                )

            existing_service = await services_collection.find_one({"name": service_request.name})
            if existing_service:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Service with name '{service_request.name}' already exists."
                )

            # Prepare service data
            service_data = {
                "name": service_request.name,
                "status": service_request.status,
                "category_id": ObjectId(service_request.category_id),
                "category_name": category["name"],
                "created_at": datetime.utcnow()
            }

            result = await services_collection.insert_one(service_data)

            # Fetch the inserted service
            created_service = await services_collection.find_one({"_id": result.inserted_id})
            response_data = {
                "id": str(created_service["_id"]),
                "name": created_service["name"],
                "status": created_service["status"],
                "category_id": str(created_service["category_id"]),
                "category_name": created_service["category_name"],
                "created_at": created_service["created_at"]
            }

            return {"data": response_data}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}"
            )
        
    async def service_list(self, page: int, limit: int, search: str = None):
        try:
            skip = (page - 1) * limit
            query = {}

            if search:
                search_regex = {"$regex": search, "$options": "i"}  
                query["$or"] = [
                    {"name": search_regex},
                ]
                
                category = await category_collection.find_one({"name": {"$regex": search, "$options": "i"}})
                if category:
                    query["$or"].append({"category_id": category["_id"]})
                
            services = await services_collection.find(query).skip(skip).limit(limit).to_list(length=None)
            service_data = []
            for service in services:
                category = await category_collection.find_one({"_id": service["category_id"]})
                category_name = category["name"] if category else "Unknown Category"
                service_data.append({
                    "id": str(service["_id"]),
                    "name": service["name"],
                    "status": service["status"],
                    "category_id": str(service["category_id"]),
                    "category_name": category_name,
                    "created_at": service["created_at"]
                })
            
            total_services = await services_collection.count_documents(query)
            total_pages = (total_services + limit - 1) // limit
            
            return {
                    "data": service_data,
                    "total_items": total_services,
                    "total_pages": total_pages
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}"
            )
        
    async def service_get(self, id: str):
        try:
            service = await services_collection.find_one({"_id": ObjectId(id)})
            if not service:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Service not found"
                )
            category = await category_collection.find_one({"_id": ObjectId(service["category_id"])})
            if not category:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Category not found"
                )
            return {
                "id": str(service["_id"]),
                "name": service["name"],
                "status": service["status"],
                "category_id": str(service["category_id"]),
                "category_name": category["name"],
                "created_at": service["created_at"]
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}"
            )    
        
    async def service_update(self, id: str, service_request: UpdateServiceRequest):
        try:
            # Validate service ID
            if not ObjectId.is_valid(id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid service ID: '{id}'"
                )

            # Check if the service exists
            service = await services_collection.find_one({"_id": ObjectId(id)})
            if not service:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Service not found"
                )

            # Validate category_id if provided
            if service_request.category_id:
                category = await category_collection.find_one({"_id": ObjectId(service_request.category_id)})
                if not category:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Category with ID '{service_request.category_id}' does not exist."
                    )

            # Prepare update data
            update_data = {}
            if service_request.name is not None:
                update_data["name"] = service_request.name
            if service_request.status is not None:
                update_data["status"] = service_request.status
            if service_request.category_id is not None:
                update_data["category_id"] = ObjectId(service_request.category_id)

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid fields provided for update"
                )

            # Perform the update
            await services_collection.update_one(
                {"_id": ObjectId(id)},
                {"$set": update_data}
            )

            # Fetch the updated service
            updated_service = await services_collection.find_one({"_id": ObjectId(id)})
            category_name = None
            if updated_service.get("category_id"):
                category = await category_collection.find_one({"_id": updated_service["category_id"]})
                category_name = category["name"] if category else "Unknown Category"
            return {
                "id": str(updated_service["_id"]),
                "name": updated_service.get("name"),
                "status": updated_service.get("status"),
                "category_id": str(updated_service.get("category_id")),
                "category_name": category_name,
                "updated_at": updated_service.get("updated_at")
            }
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}"
            )
    async def service_delete(self, id: str):
        try:
            await services_collection.delete_one({"_id": ObjectId(id)})
            return {"data": None}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}"
            )   
        
    async def category_list_for_service(self) -> dict: 
        try:
            active_categories = await category_collection.find({"status": "active"}).to_list(length=100)

            # Format the response with category name, status, and created_at
            category_data = [
                {
                    "id": str(category["_id"]),
                    "name": category["name"]
                }
                for category in active_categories
            ]

            return {"categories": category_data}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )