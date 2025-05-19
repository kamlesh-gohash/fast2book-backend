from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pytz

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, offer_collection, permission_collection, user_collection, vendor_offers_collection
from app.v1.models.permission import *
from app.v1.models.slots import *
from app.v1.schemas.offer.offer import *
from app.v1.schemas.vendor.vendor_auth import *


class OfferManager:

    async def create_offer(self, current_user: User, offer_request: CreateOfferRequest):
        try:
            # Parse and convert dates to datetime objects
            try:
                start_dt = datetime.fromisoformat(offer_request.starting_date.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(offer_request.ending_date.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid date format for starting_date or ending_date: {str(e)}",
                )

            # Validate date range
            if end_dt < start_dt:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="ending_date cannot be before starting_date"
                )

            # Check for existing offer
            existing_offer = await offer_collection.find_one(
                {"offer_name": offer_request.offer_name, "offer_for": offer_request.offer_for}
            )
            if existing_offer:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"An offer with the name '{offer_request.offer_name}' already exists for {offer_request.offer_for}",
                )

            # Prepare offer data with datetime objects
            offer_data = {
                "offer_for": offer_request.offer_for,
                "created_by": str(current_user.id),
                "is_super_admin": "admin" in [role.value for role in current_user.roles],  # Fixed condition
                "offer_name": offer_request.offer_name,
                "display_text": offer_request.display_text,
                "terms": offer_request.terms,
                "discount_type": offer_request.discount_type,
                "minimum_order_amount": offer_request.minimum_order_amount,
                "discount_worth": offer_request.discount_worth,
                "maximum_discount": offer_request.maximum_discount,
                "starting_date": start_dt,  # Store as datetime (ISODate in MongoDB)
                "ending_date": end_dt,  # Store as datetime (ISODate in MongoDB)
                "max_usage": offer_request.max_usage,
                "status": offer_request.status,
                "created_at": offer_request.created_at or datetime.now(),
                "updated_at": offer_request.updated_at or datetime.now(),
            }

            # Insert into MongoDB
            result = await offer_collection.insert_one(offer_data)
            return_value = {"id": str(result.inserted_id), **offer_data}
            return_value.pop("_id", None)  # Ensure _id is removed if present
            return return_value
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_offers(self, current_user: User, page: int, limit: int, search: str = None, statuss: str = None):
        try:

            skip = max((page - 1) * limit, 0)
            query = {"is_super_admin": True}
            # Search query
            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"display_text": search_regex},
                    {"issuer": search_regex},
                ]
            if statuss:
                query["status"] = statuss

            pipeline = [
                {"$match": query},
                {"$skip": skip},
                {"$limit": limit},
                {"$addFields": {"id": {"$toString": "$_id"}}},
                {"$unset": "_id"},
            ]
            offers = await offer_collection.aggregate(pipeline).to_list(length=limit)
            total_offers = await offer_collection.count_documents(query)
            total_pages = (total_offers + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None

            return {
                "data": offers,
                "paginator": {
                    "itemCount": total_offers,
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

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_offer(self, offer_id: str, current_user: User):
        try:
            offer = await offer_collection.find_one({"_id": ObjectId(offer_id)})
            if not offer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Offer not found")
            offer["id"] = str(offer["_id"])
            offer.pop("_id")
            return offer
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def update_offer(self, offer_id: str, offer_request: UpdateOfferRequest, current_user: User):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to update offers"
                )

            if not ObjectId.is_valid(offer_id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid offer ID: '{offer_id}'")

            offer = await offer_collection.find_one({"_id": ObjectId(offer_id)})
            if not offer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Offer not found")

            validation_result = offer_request.validate()
            if validation_result:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=validation_result["message"])

            update_data = {}
            if offer_request.offer_for is not None:
                update_data["offer_for"] = offer_request.offer_for
            if offer_request.offer_name is not None:
                update_data["offer_name"] = offer_request.offer_name
            if offer_request.display_text is not None:
                update_data["display_text"] = offer_request.display_text.strip()
            if offer_request.terms is not None:
                update_data["terms"] = offer_request.terms
            # if offer_request.offer_type is not None:
            #     update_data["offer_type"] = [item.value for item in offer_request.offer_type]
            if offer_request.discount_type is not None:
                update_data["discount_type"] = offer_request.discount_type.value
            if offer_request.minimum_order_amount is not None:
                update_data["minimum_order_amount"] = offer_request.minimum_order_amount
            if offer_request.discount_worth is not None:
                update_data["discount_worth"] = offer_request.discount_worth
            if offer_request.maximum_discount is not None:
                update_data["maximum_discount"] = offer_request.maximum_discount
            # if offer_request.payment_method is not None:
            #     update_data["payment_method"] = [item.value for item in offer_request.payment_method]
            # if offer_request.issuer is not None:
            #     update_data["issuer"] = offer_request.issuer.strip()
            if offer_request.starting_date is not None:
                update_data["starting_date"] = offer_request.starting_date
            if offer_request.ending_date is not None:
                update_data["ending_date"] = offer_request.ending_date
            if offer_request.status is not None:
                update_data["status"] = offer_request.status.value
            if offer_request.max_usage is not None:
                update_data["max_usage"] = offer_request.max_usage

            update_data["updated_at"] = datetime.utcnow()

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            await offer_collection.update_one({"_id": ObjectId(offer_id)}, {"$set": update_data})
            updated_offer = await offer_collection.find_one({"_id": ObjectId(offer_id)})

            return {
                "id": str(updated_offer["_id"]),
                "offer_for": updated_offer.get("offer_for"),
                "offer_name": updated_offer.get("offer_name"),
                "display_text": updated_offer.get("display_text"),
                "terms": updated_offer.get("terms"),
                "offer_type": updated_offer.get("offer_type"),
                "discount_type": updated_offer.get("discount_type"),
                "minimum_order_amount": updated_offer.get("minimum_order_amount"),
                "discount_worth": updated_offer.get("discount_worth"),
                "maximum_discount": updated_offer.get("maximum_discount"),
                "payment_method": updated_offer.get("payment_method"),
                "issuer": updated_offer.get("issuer"),
                "starting_date": updated_offer.get("starting_date"),
                "ending_date": updated_offer.get("ending_date"),
                "max_usage": updated_offer.get("max_usage"),
                "status": updated_offer.get("status"),
                "updated_at": updated_offer.get("updated_at"),
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def delete_offer(self, offer_id: str, current_user: User):
        try:
            offer_data = await offer_collection.find_one({"_id": ObjectId(offer_id)})
            if not offer_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Offer not found")
            await offer_collection.delete_one({"_id": ObjectId(offer_id)})
            return offer_data
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_all_offer_for_user(self, current_user: User, vendor_id: str):
        try:
            current_date = datetime.now(pytz.UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            next_day = current_date + timedelta(days=1)
            match_condition = {
                "status": "active",
                "offer_for": "user",
                "starting_date": {"$lte": next_day},
                "ending_date": {"$gte": current_date},
                "$or": [
                    {"is_super_admin": True},
                    {"created_by": vendor_id},
                ],
            }
            matched_offers = await offer_collection.find(match_condition).to_list(length=None)

            offer_pipeline = [
                {"$match": match_condition},
                {"$set": {"id": {"$toString": "$_id"}}},
                {"$unset": "_id"},
            ]

            offers = await offer_collection.aggregate(offer_pipeline).to_list(length=None)

            return offers
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def vendor_offer_create(self, vendor_offer_request: CreateVendorOffer, current_user: User):
        try:
            try:
                start_dt = datetime.fromisoformat(vendor_offer_request.starting_date.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(vendor_offer_request.ending_date.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid date format for starting_date or ending_date: {str(e)}",
                )

            if end_dt < start_dt:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="ending_date cannot be before starting_date"
                )
            vendor_id = str(current_user.id)
            existing_offer = await vendor_offers_collection.find_one(
                {
                    "vendor_id": vendor_id,
                    "offer_name": vendor_offer_request.offer_name,
                }
            )
            if existing_offer:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"An offer with the name '{vendor_offer_request.offer_name}' already exists",
                )

            vendor_data = {
                "vendor_id": vendor_id,
                "offer_name": vendor_offer_request.offer_name,
                "display_text": vendor_offer_request.display_text.strip(),
                "terms": vendor_offer_request.terms,
                "discount_type": vendor_offer_request.discount_type.value,
                "minimum_order_amount": vendor_offer_request.minimum_order_amount,
                "discount_worth": vendor_offer_request.discount_worth,
                "maximum_discount": vendor_offer_request.maximum_discount,
                "starting_date": vendor_offer_request.starting_date,
                "ending_date": vendor_offer_request.ending_date,
                "max_usage": vendor_offer_request.max_usage,
                "status": "active",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
            result = await vendor_offers_collection.insert_one(vendor_data)
            return_value = {"id": str(result.inserted_id), **vendor_data}
            return_value.pop("_id")
            return return_value
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_vendor_offer_list(
        self,
        current_user: User,
        page: int = 1,
        limit: int = 10,
        search: Optional[str] = None,
        statuss: Optional[str] = None,
    ):
        try:
            skip = max((page - 1) * limit, 0)
            query = {"created_by": str(current_user.id)}
            # Search query
            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"display_text": search_regex},
                    {"issuer": search_regex},
                ]
            if statuss:
                query["status"] = statuss

            pipeline = [
                {"$match": query},
                {"$skip": skip},
                {"$limit": limit},
                {"$addFields": {"id": {"$toString": "$_id"}}},
                {"$unset": "_id"},
            ]
            vendor_offers = await offer_collection.aggregate(pipeline).to_list(length=limit)
            total_offers = await offer_collection.count_documents(query)
            total_pages = (total_offers + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None

            return {
                "data": vendor_offers,
                "paginator": {
                    "itemCount": total_offers,
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

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_vendor_offer(self, vendor_offer_id: str, current_user: User):
        try:
            vendor_offer = await offer_collection.find_one({"_id": ObjectId(vendor_offer_id)})
            if not vendor_offer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor offer not found")
            vendor_offer["id"] = str(vendor_offer["_id"])
            vendor_offer.pop("_id")
            return vendor_offer
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def update_vendor_offer(
        self, vendor_offer_id: str, vendor_offer_request: UpdateVendorOffer, current_user: User
    ):
        try:
            if vendor_offer_request.offer_name:
                existing_offer = await offer_collection.find_one(
                    {
                        "created_by": str(current_user.id),
                        "offer_name": vendor_offer_request.offer_name,
                        "_id": {"$ne": ObjectId(vendor_offer_id)},
                    }
                )
                if existing_offer:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"An offer with the name '{vendor_offer_request.offer_name}' already exists",
                    )
            vendor_offer = await vendor_offers_collection.find_one(
                {"_id": ObjectId(vendor_offer_id), "vendor_id": str(current_user.id)}
            )
            if not vendor_offer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor offer not found")
            if vendor_offer_request.offer_name is not None:
                vendor_offer["offer_name"] = vendor_offer_request.offer_name
            if vendor_offer_request.display_text is not None:
                vendor_offer["display_text"] = vendor_offer_request.display_text.strip()
            if vendor_offer_request.terms is not None:
                vendor_offer["terms"] = vendor_offer_request.terms.strip()
            if vendor_offer_request.status is not None:
                vendor_offer["status"] = vendor_offer_request.status
            if vendor_offer_request.discount_type is not None:
                vendor_offer["discount_type"] = vendor_offer_request.discount_type
            if vendor_offer_request.minimum_order_amount is not None:
                vendor_offer["minimum_order_amount"] = vendor_offer_request.minimum_order_amount
            if vendor_offer_request.discount_worth is not None:
                vendor_offer["discount_worth"] = vendor_offer_request.discount_worth
            if vendor_offer_request.maximum_discount is not None:
                vendor_offer["maximum_discount"] = vendor_offer_request.maximum_discount
            if vendor_offer_request.starting_date is not None:
                vendor_offer["starting_date"] = vendor_offer_request.starting_date
            if vendor_offer_request.ending_date is not None:
                vendor_offer["ending_date"] = vendor_offer_request.ending_date
            if vendor_offer_request.max_usage is not None:
                vendor_offer["max_usage"] = vendor_offer_request.max_usage
            vendor_offer["updated_at"] = datetime.utcnow()
            await vendor_offers_collection.update_one({"_id": ObjectId(vendor_offer_id)}, {"$set": vendor_offer})
            vendor_offer["id"] = str(vendor_offer["_id"])
            vendor_offer.pop("_id")
            return vendor_offer
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def delete_vendor_offer(self, vendor_offer_id: str, current_user: User):
        try:
            vendor_offer = await vendor_offers_collection.find_one(
                {"_id": ObjectId(vendor_offer_id), "vendor_id": str(current_user.id)}
            )
            if not vendor_offer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor offer not found")
            await vendor_offers_collection.delete_one(
                {"_id": ObjectId(vendor_offer_id), "vendor_id": str(current_user.id)}
            )
            return vendor_offer
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_offer_for_vendor(self, current_user: User) -> List[Dict[str, Any]]:
        try:
            # Use UTC to match MongoDB's ISODate
            current_date = datetime.now(pytz.UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            next_day = current_date + timedelta(days=1)

            match_condition = {
                "offer_for": "vendor",
                "status": "active",
                "starting_date": {"$lte": next_day},  # Include offers starting today
                "ending_date": {"$gte": current_date},  # Include offers ending today or later
            }

            # Debug: Check matched documents before aggregation
            matched_offers = await offer_collection.find(match_condition).to_list(length=None)

            offer_pipeline = [
                {"$match": match_condition},
                {"$set": {"id": {"$toString": "$_id"}}},
                {"$unset": "_id"},
            ]

            offers = await offer_collection.aggregate(offer_pipeline).to_list(length=None)
            return offers
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
