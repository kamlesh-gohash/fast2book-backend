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
from app.v1.models import booking_collection, user_collection, vendor_collection, vendor_ratings_collection
from app.v1.models.category import Category
from app.v1.models.user import User
from app.v1.models.vendor_rating import VendorRating
from app.v1.schemas.rating.rating import Rating
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class RatingManager:

    async def vendor_rating(self, current_user: User, vendor_rating: Rating):
        try:
            vendor_id = vendor_rating.vendor_id
            if not vendor_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor ID is required")

            vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found with this ID")

            if str(current_user.id) == vendor_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot rate yourself")

            if vendor_rating.rating is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rating is required")
            if not (1 <= vendor_rating.rating <= 5):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rating must be between 1 and 5")
            completed_booking = await booking_collection.find_one(
                {
                    "user_id": ObjectId(current_user.id),
                    "vendor_user_id": vendor_id,
                    "payment_status": "paid",
                    # "booking_status": "completed",
                }
            )

            if not completed_booking:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only rate vendors with whom you have completed a booking",
                )
            existing_rating = await vendor_ratings_collection.find_one(
                {"user_id": current_user.id, "vendor_id": vendor_rating.vendor_id}
            )

            if existing_rating:
                await vendor_ratings_collection.update_one(
                    {"_id": existing_rating["_id"]},
                    {"$set": {"rating": vendor_rating.rating, "review": vendor_rating.review or ""}},
                )
            else:
                rating_data = {
                    "user_id": current_user.id,
                    "vendor_id": vendor_rating.vendor_id,
                    "rating": vendor_rating.rating,
                    "review": vendor_rating.review or "",
                }
                await vendor_ratings_collection.insert_one(rating_data)

            ratings = await vendor_ratings_collection.find({"vendor_id": (vendor_id)}).to_list(None)
            avg_rating = sum(r["rating"] for r in ratings) / len(ratings) if ratings else 0
            await vendor_collection.update_one({"_id": ObjectId(vendor_id)}, {"$set": {"average_rating": avg_rating}})

            return {"rating": vendor_rating.rating, "review": vendor_rating.review, "average_rating": avg_rating}

        except HTTPException as e:
            raise e
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_vendor_rating(self, current_user: User, vendor_id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if vendor:
                vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
                if not vendor_user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found with this ID"
                    )
            else:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
                if not vendor_user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found with this ID"
                    )

            ratings = await vendor_ratings_collection.find({"vendor_id": str(vendor_user["_id"])}).to_list(None)
            if not ratings:
                return {"average_rating": 0, "ratings": []}

            avg_rating = sum(r["rating"] for r in ratings) / len(ratings)

            detailed_ratings = []
            for rating in ratings:
                user = await user_collection.find_one({"_id": ObjectId(rating["user_id"])})
                user_info = (
                    {
                        "user_id": str(rating["user_id"]),
                        "first_name": user.get("first_name", ""),
                        "last_name": user.get("last_name", ""),
                        "email": user.get("email", ""),
                    }
                    if user
                    else {"user_id": str(rating["user_id"]), "first_name": "Unknown", "last_name": "", "email": ""}
                )

                detailed_ratings.append(
                    {"rating": rating["rating"], "review": rating.get("review", ""), "user": user_info}
                )

            return {"average_rating": avg_rating, "ratings": detailed_ratings}

        except HTTPException as e:
            raise e
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_rating_list_for_vendor(self, current_user: User, vendor_id: Optional[str] = None):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            current_vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not current_vendor:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Current user's vendor profile not found"
                )

            business_type = current_vendor.get("business_type", "individual")
            if business_type == "individual":
                if vendor_id is not None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Vendor ID should not be provided for individual business type",
                    )
                target_vendor_id = str(current_user.id)
                vendor_user = await user_collection.find_one({"_id": ObjectId(target_vendor_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Current vendor user not found")
            elif business_type == "business":
                if not vendor_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor ID is required for business type"
                    )
                vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
                if vendor:
                    vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
                    if not vendor_user:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found with this ID"
                        )
                else:
                    vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
                    if not vendor_user:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found with this ID"
                        )
                target_vendor_id = str(vendor_user["_id"])

            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid business type")
            ratings = await vendor_ratings_collection.find({"vendor_id": target_vendor_id}).to_list(None)
            if not ratings:
                return {"average_rating": 0, "ratings": []}

            avg_rating = sum(r["rating"] for r in ratings) / len(ratings)

            detailed_ratings = []
            for rating in ratings:
                user = await user_collection.find_one({"_id": ObjectId(rating["user_id"])})
                user_info = (
                    {
                        "user_id": str(rating["user_id"]),
                        "first_name": user.get("first_name", ""),
                        "last_name": user.get("last_name", ""),
                        "email": user.get("email", ""),
                    }
                    if user
                    else {"user_id": str(rating["user_id"]), "first_name": "Unknown", "last_name": "", "email": ""}
                )

                detailed_ratings.append(
                    {"rating": rating["rating"], "review": rating.get("review", ""), "user": user_info}
                )

            return {"average_rating": avg_rating, "ratings": detailed_ratings}

        except HTTPException as e:
            raise e
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
