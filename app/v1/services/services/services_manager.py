import os
import random

from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import category_collection, services_collection
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.schemas.service.service import CreateServiceRequest, UpdateServiceRequest
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class ServicesManager:

    async def service_create(self, request: Request, token: str, service_request: CreateServiceRequest) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            category = await category_collection.find_one({"_id": ObjectId(service_request.category_id)})
            if not category:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Category with ID '{service_request.category_id}' does not exist.",
                )

            existing_service = await services_collection.find_one({"name": service_request.name})
            if existing_service:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Service with name '{service_request.name}' already exists.",
                )
            image_name = service_request.service_image
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
            # Prepare service data
            service_data = {
                "name": service_request.name,
                "status": service_request.status,
                "service_image": service_request.service_image,
                "service_image_url": file_url,
                "category_id": ObjectId(service_request.category_id),
                "category_name": category["name"],
                "category_slug": category["slug"],
                "created_at": datetime.utcnow(),
            }

            result = await services_collection.insert_one(service_data)

            # Fetch the inserted service
            created_service = await services_collection.find_one({"_id": result.inserted_id})
            response_data = {
                "id": str(created_service["_id"]),
                "name": created_service["name"],
                "service_image": created_service["service_image"],
                "service_image_url": file_url,
                "image_url": file_url,
                "status": created_service["status"],
                "category_id": str(created_service["category_id"]),
                "category_name": created_service["category_name"],
                "created_at": created_service["created_at"],
            }

            return response_data

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def service_list(self, request: Request, token: str, page: int, limit: int, search: str = None):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
                service_data.append(
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                        "status": service["status"],
                        "category_id": str(service["category_id"]),
                        "category_name": category_name,
                        "created_at": service["created_at"],
                    }
                )

            total_services = await services_collection.count_documents(query)
            total_pages = (total_services + limit - 1) // limit

            return {"data": service_data, "total_items": total_services, "total_pages": total_pages}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def service_get(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            service = await services_collection.find_one({"_id": ObjectId(id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
            category = await category_collection.find_one({"_id": ObjectId(service["category_id"])})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
            return {
                "id": str(service["_id"]),
                "name": service["name"],
                "service_image": service["service_image"],
                "service_image_url": service["service_image_url"],
                "status": service["status"],
                "category_id": str(service["category_id"]),
                "category_name": category["name"],
                "created_at": service["created_at"],
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def service_update(self, request: Request, token: str, id: str, service_request: UpdateServiceRequest):
        try:
            # Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the user has the required role
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Validate service ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid service ID: '{id}'")

            # Check if the service exists
            service = await services_collection.find_one({"_id": ObjectId(id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            # Validate category_id if provided
            if service_request.category_id:
                if not ObjectId.is_valid(service_request.category_id):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid category ID: '{service_request.category_id}'",
                    )
                category = await category_collection.find_one({"_id": ObjectId(service_request.category_id)})
                if not category:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Category with ID '{service_request.category_id}' does not exist.",
                    )

            # Prepare update data
            update_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")

            # Update image if provided
            if service_request.service_image:
                image_name = service_request.service_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                update_data["service_image"] = image_name
                update_data["service_image_url"] = file_url
            else:
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{service.get('service_image')}"

            if service_request.name is not None:
                update_data["name"] = service_request.name

            if service_request.status is not None:
                update_data["status"] = service_request.status

            if service_request.category_id is not None:
                update_data["category_id"] = ObjectId(service_request.category_id)

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )

            # Perform the update
            await services_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            # Fetch the updated service
            updated_service = await services_collection.find_one({"_id": ObjectId(id)})
            category_name = None
            if updated_service.get("category_id"):
                category = await category_collection.find_one({"_id": updated_service["category_id"]})
                category_name = category["name"] if category else "Unknown Category"

            return {
                "id": str(updated_service["_id"]),
                "name": updated_service.get("name"),
                "service_image": updated_service.get("service_image"),
                "service_image_url": file_url,
                "status": updated_service.get("status"),
                "category_id": str(updated_service.get("category_id")),
                "category_name": category_name,
                "updated_at": updated_service.get("updated_at"),
            }
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def service_delete(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            await services_collection.delete_one({"_id": ObjectId(id)})
            return {"data": None}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def category_list_for_service(self, request: Request, token: str) -> dict:
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            allowed_roles = ["admin", "vendor"]
            user_roles = [role.value for role in current_user.roles]

            if not any(role in allowed_roles for role in user_roles) and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            active_categories = await category_collection.find({"status": "active"}).to_list(length=100)

            # Format the response with category name, status, and created_at
            category_data = [{"id": str(category["_id"]), "name": category["name"]} for category in active_categories]

            return {"categories": category_data}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )
