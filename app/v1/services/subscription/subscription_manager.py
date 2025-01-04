import random
from app.v1.models.services import Service
from app.v1.models.category import Category
from app.v1.models import subscription_collection
from app.v1.models import category_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt

# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body, Path
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest


class SubscriptionManager:
    async def subscription_create(self, subscription_request: CreateSubscriptionRequest) -> dict:
        try:
            existing_subscription = await subscription_collection.find_one({"title": subscription_request.title})
            if existing_subscription:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Subscription with title '{subscription_request.title}' already exists.",
                )

            # Prepare service data
            subscription_data = {
                "title": subscription_request.title,
                "price": subscription_request.price,
                "status": subscription_request.status,
                "created_at": datetime.utcnow(),
            }

            result = await subscription_collection.insert_one(subscription_data)

            # Fetch the inserted service
            created_subscription = await subscription_collection.find_one({"_id": result.inserted_id})
            response_data = {
                "id": str(created_subscription["_id"]),
                "title": created_subscription["title"],
                "price": created_subscription["price"],
                "status": created_subscription["status"],
                "created_at": created_subscription["created_at"],
            }

            return response_data

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_list(self, page: int, limit: int, search: str = None):
        try:
            skip = (page - 1) * limit
            query = {}  # Start with an empty query

            if search:
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"title": search_regex},  # Search by service name
                ]

            subscriptions = await subscription_collection.find(query).skip(skip).limit(limit).to_list(length=None)
            subscription_data = []
            for subscription in subscriptions:
                subscription_data.append(
                    {
                        "id": str(subscription["_id"]),
                        "title": subscription["title"],
                        "price": subscription["price"],
                        "status": subscription["status"],
                        "created_at": subscription["created_at"],
                    }
                )

            total_subscriptions = await subscription_collection.count_documents(query)
            total_pages = (total_subscriptions + limit - 1) // limit

            return {"data": subscription_data, "total_items": total_subscriptions, "total_pages": total_pages}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_get(self, id: str):
        try:
            subscription = await subscription_collection.find_one({"_id": ObjectId(id)})
            if not subscription:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")
            return {
                "id": str(subscription["_id"]),
                "title": subscription["title"],
                "price": subscription["price"],
                "status": subscription["status"],
                "created_at": subscription["created_at"],
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_update(self, id: str, subscription_request: UpdateSubscriptionRequest):
        try:
            # Validate service ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid subscription ID: '{id}'")

            # Check if the service exists
            subscription = await subscription_collection.find_one({"_id": ObjectId(id)})
            if not subscription:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

            # Prepare update data
            update_data = {}
            if subscription_request.title is not None:
                update_data["title"] = subscription_request.title
            if subscription_request.price is not None:
                update_data["price"] = subscription_request.price
            if subscription_request.status is not None:
                update_data["status"] = subscription_request.status

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )

            # Perform the update
            await subscription_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            # Fetch the updated service
            updated_subscription = await subscription_collection.find_one({"_id": ObjectId(id)})
            return {
                "id": str(updated_subscription["_id"]),
                "title": updated_subscription.get("title"),
                "price": updated_subscription.get("price"),
                "status": updated_subscription.get("status"),
                "updated_at": updated_subscription.get("updated_at"),
            }
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_delete(self, id: str):
        try:
            await subscription_collection.delete_one({"_id": ObjectId(id)})
            return {"data": None}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
