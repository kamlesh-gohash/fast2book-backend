import os
import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import pytz
import razorpay
import razorpay.errors

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import category_collection, plan_collection, subscription_collection
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.subscription import Subscription, SubscriptionDuration
from app.v1.models.user import User
from app.v1.schemas.subscription.subscription_auth import *
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


razorpay_client = razorpay.Client(auth=(os.getenv("RAZOR_PAY_KEY_ID"), os.getenv("RAZOR_PAY_KEY_SECRET")))


class SubscriptionManager:
    async def subscription_create(self, current_user: User, subscription_request: CreateSubscriptionRequest) -> dict:
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Check for existing subscription with the same title
            existing_subscription = await subscription_collection.find_one({"title": subscription_request.title})
            if existing_subscription:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Subscription with title '{subscription_request.title}' already exists.",
                )

            # Prepare subscription data
            subscription_data = {
                "title": subscription_request.title,
                "one_month_price": subscription_request.one_month_price,
                "three_months_price": subscription_request.three_months_price,
                "yearly_price": subscription_request.yearly_price,
                "features": [{"item": feature.item} for feature in subscription_request.features],
                "status": subscription_request.status,
                "created_at": datetime.utcnow(),
            }

            # Insert the subscription into the database
            result = await subscription_collection.insert_one(subscription_data)

            # Fetch the created subscription
            created_subscription = await subscription_collection.find_one({"_id": result.inserted_id})
            response_data = {
                "id": str(created_subscription["_id"]),
                "title": created_subscription["title"],
                "one_month_price": created_subscription["one_month_price"],
                "three_months_price": created_subscription["three_months_price"],
                "yearly_price": created_subscription["yearly_price"],
                "features": created_subscription["features"],
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

    async def subscription_list(
        self, request: Request, current_user: User, page: int, limit: int, search: str = None, statuss: str = None
    ):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            skip = (page - 1) * limit
            query = {}  # Start with an empty query

            if search:
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"title": search_regex},  # Search by service name
                ]

            if statuss:
                query["status"] = statuss

            subscriptions = await subscription_collection.find(query).skip(skip).limit(limit).to_list(length=None)
            subscription_data = []

            ist_timezone = pytz.timezone("Asia/Kolkata")  # IST timezone
            for subscription in subscriptions:
                created_at = subscription.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    subscription["created_at"] = created_at_ist.isoformat()
                else:
                    subscription["created_at"] = str(created_at)
                subscription_data.append(
                    {
                        "id": str(subscription["_id"]),
                        "title": subscription["title"],
                        "one_month_price": subscription["one_month_price"],
                        "three_months_price": subscription["three_months_price"],
                        "yearly_price": subscription["yearly_price"],
                        "features": subscription["features"],
                        "status": subscription["status"],
                        "created_at": subscription["created_at"],
                    }
                )

            total_subscriptions = await subscription_collection.count_documents(query)
            total_pages = (total_subscriptions + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": subscription_data,
                "paginator": {
                    "itemCount": total_subscriptions,
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
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_get(self, current_user: User, id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Validate service ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid subscription ID: '{id}'")

            # Check if the service exists
            subscription = await subscription_collection.find_one({"_id": ObjectId(id)})
            if not subscription:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")
            return {
                "id": str(subscription["_id"]),
                "title": subscription["title"],
                "one_month_price": subscription["one_month_price"],
                "three_months_price": subscription["three_months_price"],
                "yearly_price": subscription["yearly_price"],
                "features": subscription["features"],
                "status": subscription["status"],
                "created_at": subscription["created_at"],
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def subscription_update(self, current_user: User, id: str, subscription_request: UpdateSubscriptionRequest):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
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
            if subscription_request.one_month_price is not None:
                update_data["one_month_price"] = subscription_request.one_month_price
            if subscription_request.three_month_price is not None:
                update_data["three_month_price"] = subscription_request.three_month_price
            if subscription_request.yearly_price is not None:
                update_data["yearly_price"] = subscription_request.yearly_price
            if subscription_request.features is not None:
                update_data["features"] = [
                    {"item": feature.item} for feature in subscription_request.features
                ]  # Ensure features are correctly updated
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
                "one_month_price": updated_subscription.get("one_month_price"),
                "three_month_price": updated_subscription.get("three_month_price"),
                "yearly_price": updated_subscription.get("yearly_price"),
                "features": updated_subscription.get("features"),
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
            await plan_collection.delete_one({"_id": ObjectId(id)})
            return {"data": None}
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    # async def plan_create(self, request: Request, token: str, plan_request: CreateSubscriptionRequest):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    #         if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
    #             raise HTTPException(
    #                 status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
    #             )
    #         if plan_request.period.lower() == "monthly":
    #             interval = 1
    #         elif plan_request.period.lower() == "yearly":
    #             interval = 1
    #         elif plan_request.period.lower() == "daily":
    #             interval = 7
    #         elif plan_request.period.lower() == "weekly":
    #             interval = 1
    #         else:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST,
    #                 detail="Invalid period. Allowed values are 'daily' or 'weekly' or 'monthly' or 'yearly'.",
    #             )
    #         razorpay_plan_data = {
    #             "period": plan_request.period,
    #             "interval": interval,
    #             "item": {
    #                 "name": plan_request.name,
    #                 "description": plan_request.description,
    #                 "amount": int(plan_request.amount * 100),
    #                 "currency": plan_request.currency,
    #             },
    #         }
    #         try:
    #             razorpay_plan = razorpay_client.plan.create(data=razorpay_plan_data)
    #         except Exception as e:
    #             raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    #         except razorpay.errors.BadRequestError as e:
    #             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Bad request: {str(e)}")
    #         except razorpay.errors.GatewayError as e:
    #             raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Gateway error: {str(e)}")
    #         except razorpay.errors.ServerError as e:
    #             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Server error: {str(e)}")
    #         except razorpay.errors.SignatureVerificationError as e:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail=f"Signature verification error: {str(e)}"
    #             )
    #         except Exception as e:
    #             raise HTTPException(
    #                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(e)}"
    #             )
    #         insert_data = {
    #             "name": plan_request.name,
    #             "description": plan_request.description,
    #             "amount": plan_request.amount,
    #             "currency": plan_request.currency,
    #             "period": plan_request.period,
    #             "interval": plan_request.interval,
    #             "razorpay_plan_id": razorpay_plan["id"],
    #             "features": [feature.to_dict() for feature in plan_request.features],
    #             "created_at": datetime.utcnow(),
    #             "status": plan_request.status,
    #         }

    #         await plan_collection.insert_one(insert_data)

    #         inserted_plan = await plan_collection.find_one({"razorpay_plan_id": razorpay_plan["id"]})
    #         return {
    #             "id": str(inserted_plan["_id"]),
    #             "name": inserted_plan["name"],
    #             "description": inserted_plan["description"],
    #             "amount": inserted_plan["amount"],
    #             "currency": inserted_plan["currency"],
    #             "period": inserted_plan["period"],
    #             "interval": inserted_plan["interval"],
    #             "features": inserted_plan["features"],
    #             "razorpay_plan_id": inserted_plan["razorpay_plan_id"],
    #             "created_at": inserted_plan["created_at"],
    #             "status": inserted_plan["status"],
    #         }

    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
    #         )

    async def plan_create(self, current_user: User, plan_request: CreateSubscriptionRequest):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            created_plan = None

            for amount_item in plan_request.amountsArray:
                period = amount_item.type.lower()
                amount = amount_item.value

                if period == "weekly":
                    interval = 1
                elif period == "monthly":
                    interval = 1
                elif period == "quarterly":
                    interval = 1
                elif period == "yearly":
                    interval = 1
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid period: {period}. Allowed values are 'weekly', 'monthly', or 'yearly'.",
                    )

                razorpay_plan_data = {
                    "period": period,
                    "interval": interval,
                    "item": {
                        "name": plan_request.name,
                        "description": plan_request.description,
                        "amount": int(amount * 100),  # Convert to cents/pence
                        "currency": plan_request.currency,
                    },
                }

                try:
                    razorpay_plan = razorpay_client.plan.create(data=razorpay_plan_data)
                except razorpay.errors.BadRequestError as e:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Bad request: {str(e)}")
                except razorpay.errors.GatewayError as e:
                    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Gateway error: {str(e)}")
                except razorpay.errors.ServerError as e:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Server error: {str(e)}"
                    )
                except razorpay.errors.SignatureVerificationError as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Signature verification error: {str(e)}"
                    )
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"An unexpected error occurred: {str(e)}",
                    )

                insert_data = {
                    "name": plan_request.name,
                    "description": plan_request.description,
                    "amount": amount,
                    "currency": plan_request.currency,
                    "period": period,
                    "interval": interval,
                    "razorpay_plan_id": razorpay_plan["id"],
                    "features": [feature.dict() for feature in plan_request.features],
                    "created_at": datetime.utcnow(),
                    "status": "active",  # Default status
                }

                await plan_collection.insert_one(insert_data)
                created_plan = await plan_collection.find_one({"razorpay_plan_id": razorpay_plan["id"]})

            # Return a single dictionary with the plan details
            return {
                "id": str(created_plan["_id"]),
                "name": created_plan["name"],
                "description": created_plan["description"],
                "amount": created_plan["amount"],
                "currency": created_plan["currency"],
                "period": created_plan["period"],
                "interval": created_plan["interval"],
                "features": created_plan["features"],
                "razorpay_plan_id": created_plan["razorpay_plan_id"],
                "created_at": created_plan["created_at"],
                "status": created_plan["status"],
            }

        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    # async def plan_create(self, request: Request, token: str, plan_request: CreateSubscriptionRequest):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    #         if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
    #             raise HTTPException(
    #                 status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
    #             )

    #         base_amount = plan_request.amountsArray[0].value
    #         base_period = plan_request.amountsArray[0].type.lower()
    #         print(base_amount, "hhhhhhhhhhhhhhhhh")
    #         razorpay_plan_data = {
    #             "period": base_period,
    #             "interval": 1,
    #             "item": {
    #                 "name": plan_request.name,
    #                 "description": plan_request.description,
    #                 "amount": int(base_amount * 100),  # Convert to cents/pence
    #                 "currency": plan_request.currency,
    #             },
    #         }

    #         try:
    #             razorpay_plan = razorpay_client.plan.create(data=razorpay_plan_data)
    #         except razorpay.errors.BadRequestError as e:
    #             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Bad request: {str(e)}")
    #         except razorpay.errors.GatewayError as e:
    #             raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Gateway error: {str(e)}")
    #         except razorpay.errors.ServerError as e:
    #             raise HTTPException(
    #                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Server error: {str(e)}"
    #             )
    #         except razorpay.errors.SignatureVerificationError as e:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail=f"Signature verification error: {str(e)}"
    #             )
    #         except Exception as e:
    #             raise HTTPException(
    #                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    #                 detail=f"An unexpected error occurred: {str(e)}",
    #             )

    #         insert_data = {
    #             "name": plan_request.name,
    #             "description": plan_request.description,
    #             "amounts": [
    #                 {"type": amount_item.type, "value": amount_item.value}
    #                 for amount_item in plan_request.amountsArray
    #             ],
    #             "currency": plan_request.currency,
    #             "razorpay_plan_id": razorpay_plan["id"],
    #             "features": [feature.dict() for feature in plan_request.features],
    #             "created_at": datetime.utcnow(),
    #             "status": "active",  # Default status
    #         }
    #         print(insert_data,"insert_data")

    #         await plan_collection.insert_one(insert_data)
    #         inserted_plan = await plan_collection.find_one({"razorpay_plan_id": razorpay_plan["id"]})

    #         return {
    #             "message": "Plan created successfully",
    #             "data": {
    #                 "id": str(inserted_plan["_id"]),
    #                 "name": inserted_plan["name"],
    #                 "description": inserted_plan["description"],
    #                 "amounts": inserted_plan["amounts"],
    #                 "currency": inserted_plan["currency"],
    #                 "features": inserted_plan["features"],
    #                 "razorpay_plan_id": inserted_plan["razorpay_plan_id"],
    #                 "created_at": inserted_plan["created_at"],
    #                 "period": base_period,
    #                 "status": inserted_plan["status"],
    #             },
    #         }

    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
    #         )

    async def plan_list(self, current_user: User, page: int, limit: int, search: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            query = {}
            if search:
                query["name"] = {"$regex": search, "$options": "i"}

            total_count = await plan_collection.count_documents(query)
            skip = (page - 1) * limit

            plans = await plan_collection.find(query).skip(skip).limit(limit).to_list(length=None)
            plan_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")
            for plan in plans:
                created_at = plan.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    plan["created_at"] = created_at_ist.isoformat()
                else:
                    plan["created_at"] = str(created_at)

                plan_data.append(
                    {
                        "id": str(plan["_id"]),
                        "name": plan["name"],
                        "description": plan["description"],
                        "amount": plan["amount"],
                        "currency": plan["currency"],
                        "period": plan["period"],
                        "interval": plan["interval"],
                        "features": plan["features"],
                        "razorpay_plan_id": plan["razorpay_plan_id"],
                        "created_at": plan["created_at"],
                        "status": plan["status"],
                    }
                )

            total_pages = (total_count + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": plan_data,
                "paginator": {
                    "itemCount": total_count,
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

        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    # async def plan_list(self, request: Request, token: str, page: int, limit: int, search: str):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    #         if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
    #             raise HTTPException(
    #                 status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
    #             )

    #         query = {}
    #         if search:
    #             query["name"] = {"$regex": search, "$options": "i"}

    #         total_count = await plan_collection.count_documents(query)
    #         skip = (page - 1) * limit

    #         plans = await plan_collection.find(query).skip(skip).limit(limit).to_list(length=None)
    #         plan_data = []
    #         ist_timezone = pytz.timezone("Asia/Kolkata")
    #         for plan in plans:
    #             created_at = plan.get("created_at")
    #             if isinstance(created_at, datetime):
    #                 created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
    #                 created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
    #                 plan["created_at"] = created_at_ist.isoformat()
    #             else:
    #                 plan["created_at"] = str(created_at)

    #             # Handle the `amounts` field
    #             amounts = plan.get("amounts", [])
    #             base_amount = amounts[0]["value"] if amounts else 0  # Use the first amount as the base amount

    #             plan_data.append(
    #                 {
    #                     "id": str(plan["_id"]),
    #                     "name": plan["name"],
    #                     "description": plan["description"],
    #                     "amount": base_amount,  # Use the base amount
    #                     "amounts": amounts,  # Include the full list of amounts
    #                     "currency": plan["currency"],
    #                     "period": plan.get("period", ""),  # Use get to avoid KeyError
    #                     "interval": plan.get("interval", 1),  # Use get to avoid KeyError
    #                     "features": plan.get("features", []),  # Use get to avoid KeyError
    #                     "razorpay_plan_id": plan["razorpay_plan_id"],
    #                     "created_at": plan["created_at"],
    #                     "status": plan.get("status", "active"),  # Use get to avoid KeyError
    #                 }
    #             )

    #         return {
    #             "data": plan_data,
    #             "total_items": total_count,
    #             "total_pages": (total_count + limit - 1) // limit,
    #         }
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
    #         )
