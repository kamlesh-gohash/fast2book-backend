from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, offer_collection, permission_collection, user_collection
from app.v1.models.permission import *
from app.v1.models.slots import *
from app.v1.schemas.offer.offer import *
from app.v1.schemas.vendor.vendor_auth import *


class OfferManager:

    async def create_offer(self, offer_request: CreateOfferRequest):
        try:

            # Convert Pydantic model to dictionary
            offer_data = offer_request.dict()
            offer_data["created_at"] = datetime.utcnow()
            offer_data["updated_at"] = datetime.utcnow()

            # Insert into MongoDB
            result = await offer_collection.insert_one(offer_data)
            inserted_offer = await offer_collection.find_one({"_id": result.inserted_id})
            inserted_offer["_id"] = str(inserted_offer["_id"])
            return inserted_offer
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_offers(self, current_user: User):
        try:
            offers = await offer_collection.find().to_list(length=100)
            return offers
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
