import base64
import json
import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import httpx
import pytz
import razorpay
import requests

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from dateutil.relativedelta import relativedelta

# from app.v1.utils.token import generate_jwt_token
from fastapi import BackgroundTasks, Body, HTTPException, Query, Request, status
from pymongo import ASCENDING, DESCENDING

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    booking_collection,
    category_collection,
    payment_collection,
    plan_collection,
    services_collection,
    slots_collection,
    user_collection,
    vendor_collection,
    vendor_query_collection,
    vendor_ratings_collection,
    vendor_services_collection,
)
from app.v1.models.booking import *
from app.v1.models.slots import *
from app.v1.models.vendor import Vendor
from app.v1.models.vendor_query import VendorQuery
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.utils.email import *
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


def convert_objectid(obj):
    """Recursively convert all ObjectId fields in a dictionary or list to strings."""
    if isinstance(obj, dict):
        return {key: convert_objectid(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid(item) for item in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)
    return obj


def serialize_mongo_document(document):
    """Helper function to serialize MongoDB documents."""
    if "_id" in document:
        document["_id"] = str(document["_id"])
    return document


VALID_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

PERIOD_TO_DURATION = {
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
    "yearly": 365,
}


def calculate_remaining_amount(current_subscription, current_plan_details):
    current_plan_amount = int(current_plan_details["item"]["amount"])
    current_plan_start_date = datetime.fromtimestamp(current_subscription["created_at"])
    current_plan_period = current_plan_details["period"].lower()
    PERIOD_TO_DURATION = {
        "weekly": 7,
        "monthly": 30,
        "yearly": 365,
    }
    total_days_in_plan = PERIOD_TO_DURATION.get(current_plan_period, 30)

    # Calculate remaining days and amount
    current_date = datetime.now()
    subscription_end_date = current_plan_start_date + timedelta(days=total_days_in_plan)
    remaining_days = max((subscription_end_date - current_date).days, 0)  # Ensure it doesn’t go negative
    remaining_amount = (current_plan_amount / total_days_in_plan) * remaining_days

    return remaining_amount, remaining_days


def validate_time_format(time_str: str):
    try:
        datetime.strptime(time_str, "%H:%M")
    except ValueError:
        return False
    return True


import razorpay.errors


RAZOR_PAY_KEY_ID = os.getenv("RAZOR_PAY_KEY_ID")
RAZOR_PAY_KEY_SECRET = os.getenv("RAZOR_PAY_KEY_SECRET")
razorpay_client = razorpay.Client(auth=(RAZOR_PAY_KEY_ID, RAZOR_PAY_KEY_SECRET))


class VendorManager:

    async def create_vendor(
        self, current_user: User, create_vendor_request: SignUpVendorRequest, background_tasks: BackgroundTasks
    ):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            existing_user_by_email = None
            existing_user_by_phone = None

            if create_vendor_request.email:
                existing_user_by_email = await user_collection.find_one({"email": create_vendor_request.email.lower()})

            if create_vendor_request.phone:
                existing_user_by_phone = await user_collection.find_one({"phone": int(create_vendor_request.phone)})

            # Raise an error if either email or phone already exists
            if existing_user_by_email or existing_user_by_phone:
                raise HTTPException(
                    status_code=400, detail="Vendor with this email or phone already exists in the database."
                )

            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)

            email = create_vendor_request.email.lower()
            create_vendor_request.email = email
            category_id = create_vendor_request.category_id
            category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category_data:
                raise HTTPException(status_code=400, detail=f"Invalid category ID: {category_id}.")

            services = create_vendor_request.services
            if not isinstance(services, list):
                services = [services]

            service_ids = [ObjectId(service.id) for service in services]

            valid_services = await services_collection.find(
                {
                    "category_id": ObjectId(category_id),
                    "_id": {"$in": service_ids},
                    "status": "active",
                }
            ).to_list(None)

            if len(valid_services) != len(service_ids):
                raise HTTPException(
                    status_code=400, detail="One or more services are invalid for the selected category."
                )

            plain_text_password = create_vendor_request.password
            hashed_password = hashpw(plain_text_password.encode("utf-8"), gensalt()).decode("utf-8")

            create_vendor_request_dict = create_vendor_request.dict()
            create_vendor_request_dict["password"] = hashed_password
            create_vendor_request_dict["services"] = [
                {
                    "id": str(service["_id"]),
                    "name": service["name"],
                    "service_image": f"{service['service_image']}",
                    "service_image_url": f"{service['service_image_url']}",
                }
                for service in valid_services
            ]
            user_image_url = None
            if create_vendor_request.user_image:
                # If user_image is provided, generate the URL
                image_name = create_vendor_request.user_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                user_image_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"

            vendor_data = {
                # "vendor_image": create_vendor_request.vendor_image,
                # "vendor_image_url": file_url,
                "business_name": create_vendor_request.business_name,
                "business_type": create_vendor_request.business_type,
                "business_address": create_vendor_request.business_address,
                "business_details": create_vendor_request.business_details,
                "category_id": category_id,
                "category_name": category_data.get("name"),
                "services": [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": f"{service['service_image']}",
                        "service_image_url": f"{service['service_image_url']}",
                    }
                    for service in valid_services
                ],
                "service_details": create_vendor_request.service_details,
                "manage_plan": create_vendor_request.manage_plan,
                "manage_fee_and_gst": create_vendor_request.manage_fee_and_gst,
                "manage_offer": create_vendor_request.manage_offer,
                "is_payment_verified": create_vendor_request.is_payment_verified,
                "is_payment_required": create_vendor_request.is_payment_required,
                "status": create_vendor_request.status,
                "is_subscription": create_vendor_request.is_subscription,
                "created_at": datetime.utcnow(),
                "location": (
                    create_vendor_request.location.dict() if create_vendor_request.location else None
                ),  # Add location
                "specialization": create_vendor_request.specialization,
            }

            # razorpay_response = create_razorpay_subaccount(vendor_data, user_data)
            # vendor_data["razorpay_account_id"] = razorpay_response["id"]
            # Insert vendor data into the database
            vendor_result = await vendor_collection.insert_one(vendor_data)
            user_data = {
                "first_name": create_vendor_request.first_name,
                "last_name": create_vendor_request.last_name,
                "email": create_vendor_request.email,
                "phone": int(create_vendor_request.phone) if create_vendor_request.phone else None,
                "gender": create_vendor_request.gender,
                "roles": create_vendor_request.roles,
                "user_image": create_vendor_request.user_image,
                "user_image_url": user_image_url,
                "password": hashed_password,
                "status": create_vendor_request.status,
                "fees": create_vendor_request.fees,
                "is_dashboard_created": create_vendor_request.is_dashboard_created,
                "specialization": create_vendor_request.specialization,
                "vendor_id": ObjectId(vendor_result.inserted_id),
                # "otp": otp,
                # "otp_expiration_time": otp_expiration_time,
            }
            user_data["is_active"] = True
            if create_vendor_request.business_type.lower() == "individual":
                user_data["availability_slots"] = default_availability_slots()
            user_result = await user_collection.insert_one(user_data)
            vendor_service_data = {
                "vendor_id": ObjectId(vendor_result.inserted_id),
                "vendor_user_id": ObjectId(user_result.inserted_id),
                "services": [
                    {
                        "service_id": ObjectId(service["id"]),
                        "service_name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in create_vendor_request_dict["services"]
                ],
            }

            vendor_service = await vendor_services_collection.insert_one(vendor_service_data)
            response_data = {
                "first_name": create_vendor_request.first_name,
                "last_name": create_vendor_request.last_name,
                "email": create_vendor_request.email,
                "phone": create_vendor_request.phone,
                "gender": create_vendor_request.gender,
                "roles": create_vendor_request.roles,
                "password": plain_text_password,
                "status": create_vendor_request.status,
                "fees": create_vendor_request.fees,
                "id": str(user_result.inserted_id),
                "vendor_data": {
                    "vendor_id": str(vendor_result.inserted_id),
                    # "vendor_image_url": file_url,
                    "business_name": create_vendor_request.business_name,
                    "business_type": create_vendor_request.business_type,
                    "business_address": create_vendor_request.business_address,
                    "business_details": create_vendor_request.business_details,
                    "category_id": category_id,
                    "category_name": category_data.get("name"),
                    "services": [
                        {
                            "id": str(service["_id"]),
                            "name": service["name"],
                            "service_image": f"{service['service_image']}",
                            "service_image_url": f"{service['service_image_url']}",
                        }
                        for service in valid_services
                    ],
                    "service_details": create_vendor_request.service_details,
                    "availability_slots": default_availability_slots(),
                    "manage_plan": create_vendor_request.manage_plan,
                    "manage_fee_and_gst": create_vendor_request.manage_fee_and_gst,
                    "manage_offer": create_vendor_request.manage_offer,
                    "is_payment_verified": create_vendor_request.is_payment_verified,
                    "is_payment_required": create_vendor_request.is_payment_required,
                    # "razorpay_account_id": sub_account["id"],
                    "created_at": vendor_data["created_at"],
                    "location": (
                        create_vendor_request.location.dict() if create_vendor_request.location else None
                    ),  # Add location
                },
            }

            # Send email to the vendor
            login_link = "https://fast2book.com/vendor-admin/sign-in"
            source = "Vendor Create"
            context = {
                "password": plain_text_password,
                "login_link": login_link,
                "vendor_name": create_vendor_request.first_name,
            }
            to_email = create_vendor_request.email
            background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

            return {"data": response_data}

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_list(
        self,
        request: Request,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
        role: str = "vendor",
    ):
        try:
            # Verify current user
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Validate role
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            # Pagination and search query
            skip = max((page - 1) * limit, 0)
            query = {"roles": {"$regex": "^vendor$", "$options": "i"}}

            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"first_name": search_regex},
                    {"last_name": search_regex},
                    {"email": search_regex},
                    {"phone": search_regex},
                ]

            if statuss:
                query["status"] = statuss

            # Fetch vendor data
            vendors = await user_collection.find(query).skip(skip).limit(limit).to_list(length=limit)
            vendor_data = []

            for vendor in vendors:
                # Fetch associated vendor details
                vendor_id = str(vendor.pop("_id"))
                vendor["id"] = vendor_id
                # Capitalize names and format email
                vendor["first_name"] = vendor["first_name"].capitalize()
                vendor["last_name"] = vendor["last_name"].capitalize()
                vendor["email"] = vendor["email"]
                vendor["user_image"] = vendor.get("user_image", "")
                if vendor["user_image"] is not None:
                    vendor["user_image_url"] = vendor.get("user_image_url", "")
                else:
                    vendor["user_image_url"] = None
                vendor["specialization"] = vendor.get("specialization", [])
                vendor_user_id = vendor.get("vendor_id")
                vendor.pop("vendor_id")

                # Fetch vendor-specific data
                vendor_details = await vendor_collection.find_one({"_id": ObjectId(vendor_user_id)})

                ist_timezone = pytz.timezone("Asia/Kolkata")
                created_at = vendor_details.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    vendor_details["created_at"] = created_at_ist.isoformat()
                if vendor_details:
                    vendor["business_name"] = vendor_details.get("business_name")
                    vendor["business_type"] = vendor_details.get("business_type")
                    vendor["business_address"] = vendor_details.get("business_address")
                    vendor["business_details"] = vendor_details.get("business_details")
                    vendor["services"] = vendor_details.get("services", [])
                    vendor["service_details"] = vendor_details.get("service_details", [])
                    vendor["manage_plan"] = vendor_details.get("manage_plan", False)
                    vendor["manage_fee_and_gst"] = vendor_details.get("manage_fee_and_gst", False)
                    vendor["manage_offer"] = vendor_details.get("manage_offer", False)
                    vendor["is_payment_verified"] = vendor_details.get("is_payment_verified", False)
                    vendor["status"] = vendor_details.get("status", "N/A")
                    vendor["location"] = vendor_details.get("location")
                    vendor["is_payment_required"] = vendor_details.get("is_payment_required", False)
                    vendor["created_at"] = vendor_details.get("created_at")
                    vendor["id"] = str(vendor_details.get("_id"))
                    vendor_details.pop("_id", None)

                    # Fetch category name
                    category_id = vendor_details.get("category_id")
                    if category_id:
                        category = await category_collection.find_one({"_id": ObjectId(category_id)})
                        vendor["category_name"] = category.get("name", "Unknown") if category else "Unknown"
                    else:
                        vendor["category_name"] = "Unknown"

                vendor_data.append(vendor)
                vendor_data[-1].pop("password", None)
                vendor_data[-1].pop("otp", None)

            # Fetch total count and calculate total pages
            total_vendors = await user_collection.count_documents(query)
            total_pages = (total_vendors + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": vendor_data,
                "paginator": {
                    "itemCount": total_vendors,
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_vendor(self, current_user: User, id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            query = {"vendor_id": ObjectId(id), "roles": {"$in": ["vendor"]}}

            result = await user_collection.find_one(query)
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            result["id"] = str(result.pop("_id"))
            result["first_name"] = result.get("first_name", "").capitalize()
            result["last_name"] = result.get("last_name", "").capitalize()
            result["email"] = result.get("email", "")
            result["phone"] = result.get("phone", "Unknown")
            result["user_image"] = result.get("user_image", "")  # Default to empty string if missing
            if result["user_image"] is not None:
                result["user_image_url"] = result.get("user_image_url", "")
            else:
                result["user_image_url"] = None  # Default to empty string if missing
            result["gender"] = result.get("gender", "Unknown")
            result["specialization"] = result.get("specialization", [])
            result["created_by"] = result.get("created_by", "Unknown")
            result["fees"] = result.get("fees")
            result.pop("vendor_id")
            vendor_details = await vendor_collection.find_one({"_id": ObjectId(id)})
            if vendor_details:
                result["business_name"] = vendor_details.get("business_name")
                result["business_type"] = vendor_details.get("business_type")
                result["business_address"] = vendor_details.get("business_address")
                result["business_details"] = vendor_details.get("business_details")
                category_id = vendor_details.get("category_id")
                if category_id:
                    category = await category_collection.find_one({"_id": ObjectId(category_id)})
                    result["category_id"] = str(category_id)
                    result["category_name"] = category.get("name", "Unknown") if category else "Unknown"
                else:
                    result["category_name"] = "Unknown"
                result["services"] = vendor_details.get("services", [])
                result["service_details"] = vendor_details.get("service_details", [])
                result["manage_plan"] = vendor_details.get("manage_plan", False)
                result["manage_fee_and_gst"] = vendor_details.get("manage_fee_and_gst", False)
                result["manage_offer"] = vendor_details.get("manage_offer", False)
                result["is_payment_verified"] = vendor_details.get("is_payment_verified", False)
                result["is_payment_required"] = vendor_details.get("is_payment_required", False)
                result["status"] = vendor_details.get("status", "N/A")
                result["location"] = vendor_details.get("location")
                result["created_at"] = vendor_details.get("created_at")
                result["id"] = str(vendor_details.get("_id"))
                vendor_details.pop("_id", None)

            result.pop("password", None)

            return result
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_vendor(self, current_user: User, id: str, update_vendor_request: UpdateVendorRequest):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Validate the vendor ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID: '{id}'")

            # Fetch the vendor from the user collection
            vendor = await user_collection.find_one({"vendor_id": ObjectId(id), "roles": {"$in": ["vendor"]}})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare update data for user collection
            user_update_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")

            if update_vendor_request.user_image:
                image_name = update_vendor_request.user_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                user_update_data["user_image"] = image_name
                user_update_data["user_image_url"] = file_url
            else:
                file_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{vendor.get('user_image')}"
                )
            if update_vendor_request.email is not None:
                # Check if the new email already exists (only if the email is being updated)
                email = update_vendor_request.email.lower()
                user_with_email = await User.find_one(User.email == email)
                if user_with_email and ObjectId(user_with_email.vendor_id) != ObjectId(
                    id
                ):  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this email"
                    )
                user_update_data["email"] = email
            if update_vendor_request.gender is not None:
                user_update_data["gender"] = update_vendor_request.gender
            if update_vendor_request.specialization is not None:
                user_update_data["specialization"] = update_vendor_request.specialization
            if update_vendor_request.fees is not None:
                user_update_data["fees"] = update_vendor_request.fees
            if update_vendor_request.phone is not None:
                # Check if the new phone already exists (only if the phone is being updated)
                user_with_phone = await User.find_one(User.phone == update_vendor_request.phone)
                if user_with_phone and ObjectId(user_with_phone.vendor_id) != ObjectId(
                    id
                ):  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this phone"
                    )
                user_update_data["phone"] = update_vendor_request.phone
            for field in ["first_name", "last_name", "email", "phone", "gender", "status"]:
                value = getattr(update_vendor_request, field, None)
                if value is not None:
                    user_update_data[field] = value

            vendor_update_data = {}
            for field in [
                "business_type",
                "business_details",
                "business_address",
                "business_name",
                "manage_plan",
                "manage_fee_and_gst",
                "manage_offer",
                "status",
            ]:
                value = getattr(update_vendor_request, field, None)
                if value is not None:
                    vendor_update_data[field] = value

            if update_vendor_request.category_id is not None:
                category_id = update_vendor_request.category_id
                category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
                if not category_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: {category_id}."
                    )
                vendor_update_data["category_id"] = category_id
                vendor_update_data["category_name"] = category_data.get("name")

            if update_vendor_request.fees is not None:
                vendor_update_data["fees"] = update_vendor_request.fees

            if update_vendor_request.services is not None:
                services = update_vendor_request.services
                if not isinstance(services, list):
                    services = [services]

                service_ids = [
                    ObjectId(service.id) if isinstance(service, Service) else ObjectId(service["id"])
                    for service in services
                ]

                query = {
                    "category_id": ObjectId(update_vendor_request.category_id or vendor.get("category_id")),
                    "_id": {"$in": service_ids},
                    "status": "active",
                }
                valid_services = await services_collection.find(query).to_list(None)

                if len(valid_services) != len(service_ids):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="One or more services are invalid for the selected category.",
                    )

                # vendor_update_data["services"] = [
                #     {
                #         "id": str(service["_id"]),
                #         "name": service["name"],
                #         "service_image": service["service_image"],
                #         "service_image_url": service["service_image_url"],
                #     }
                #     for service in valid_services
                # ]
                updated_services = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

                # Update vendor collection with the new services
                vendor_update_data["services"] = updated_services

                # Update the vendor_services_collection with the updated services
                vendor_service_update_result = await vendor_services_collection.update_one(
                    {"vendor_id": ObjectId(id)},
                    {"$set": {"services": updated_services}},
                )
            # if update_vendor_request.rating is not None:
            #     rating_data = {
            #         "vendor_id": ObjectId(id),
            #         "vendor_user_id": ObjectId(vendor.get("_id")),  # Assuming current_user has an 'id' field
            #         "rating": update_vendor_request.rating,
            #         "review": update_vendor_request.reviews,
            #     }

            #     # Insert or update the rating in the vendor_rating_collection
            #     await vendor_ratings_collection.update_one(
            #         {"vendor_id": ObjectId(id), "vendor_user_id": ObjectId(vendor.get("_id"))},
            #         {"$set": rating_data},
            #         upsert=True,
            #     )

            #     # Calculate the average rating for the vendor
            #     ratings = await vendor_ratings_collection.find({"vendor_id": ObjectId(id)}).to_list(None)
            #     total_ratings = len(ratings)
            #     if total_ratings > 0:
            #         average_rating = sum(rating["rating"] for rating in ratings) / total_ratings
            #         vendor_update_data["rating"] = average_rating

            if update_vendor_request.specialization is not None:
                vendor_update_data["specialization"] = update_vendor_request.specialization

            if update_vendor_request.location is not None:
                vendor_update_data["location"] = update_vendor_request.location.dict()
            if update_vendor_request.is_payment_required is not None:
                vendor_update_data["is_payment_required"] = update_vendor_request.is_payment_required
            if update_vendor_request.service_details is not None:
                vendor_update_data["service_details"] = update_vendor_request.service_details
            # Check if there are any updates to perform
            if not user_update_data and not vendor_update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update."
                )

            if user_update_data:
                await user_collection.update_one(
                    {"vendor_id": ObjectId(id), "roles": {"$in": ["vendor"]}}, {"$set": user_update_data}
                )

            if vendor_update_data:
                await vendor_collection.update_one(
                    {"_id": ObjectId(id)},
                    {"$set": vendor_update_data},
                    upsert=True,
                )

            # Fetch updated vendor details
            updated_vendor = await vendor_collection.find_one({"_id": ObjectId(id)})
            updated_user = await user_collection.find_one({"vendor_id": ObjectId(id), "roles": {"$in": ["vendor"]}})

            # Return the combined response
            return {
                "id": str(updated_vendor.pop("_id")),
                "first_name": updated_user.get("first_name"),
                "last_name": updated_user.get("last_name"),
                "email": updated_user.get("email"),
                "phone": updated_user.get("phone"),
                "gender": updated_user.get("gender"),
                "user_image": updated_user.get("user_image"),
                "user_image_url": updated_user.get("user_image_url"),
                "business_type": updated_vendor.get("business_type"),
                "business_details": updated_vendor.get("business_details"),
                "business_address": updated_vendor.get("business_address"),
                "business_name": updated_vendor.get("business_name"),
                "category_id": updated_vendor.get("category_id"),
                "category_name": updated_vendor.get("category_name"),
                "services": updated_vendor.get("services"),
                "manage_plan": updated_vendor.get("manage_plan"),
                "manage_fee_and_gst": updated_vendor.get("manage_fee_and_gst"),
                "manage_offer": updated_vendor.get("manage_offer"),
                "location": updated_vendor.get("location"),
                "specialization": updated_user.get("specialization"),
                "is_payment_required": updated_vendor.get("is_payment_required"),
                "fees": updated_user.get("fees"),
                "status": updated_vendor.get("status"),
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def delete_vendor(self, current_user: User, id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            result = await user_collection.delete_one({"vendor_id": ObjectId(id)})
            vendor = await vendor_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            return {"data": None}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_service_by_category(self, current_user: User, id: str):
        try:
            allowed_roles = ["admin", "vendor"]
            user_roles = [role.value for role in current_user.roles]

            if not any(role in allowed_roles for role in user_roles) and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            services = await services_collection.find({"category_id": ObjectId(id), "status": "active"}).to_list(None)

            if not services:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No services found for this category")

            formatted_services = [
                {"id": str(service["_id"]), "name": service["name"], "status": service["status"]}
                for service in services
            ]

            return {"services": formatted_services}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def vendor_sign_in(
        self,
        vendor_request: SignInVendorRequest,
    ):
        try:
            if vendor_request.email:
                query = {"email": vendor_request.email}
            elif vendor_request.phone:
                query = {"phone": vendor_request.phone}
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone is required")

            vendor = await user_collection.find_one(query)

            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            if "vendor" not in vendor["roles"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a vendor")

            if vendor["status"] != "active":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Vendor status is not active, please contact admin"
                )

            if vendor_request.is_login_with_otp:
                if not vendor.get("is_active", False):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Please verify your email to activate your account",
                    )

                if vendor.get("status") == "inactive":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Your account is inactive, please contact admin",
                    )
                otp = generate_otp()
                otp_expires = datetime.utcnow() + timedelta(minutes=10)
                await user_collection.update_one(
                    {"_id": vendor["_id"]},
                    {"$set": {"login_otp": otp, "login_otp_expires": datetime.utcnow() + timedelta(minutes=10)}},
                )

                if vendor.get("email"):
                    # Send OTP to email
                    source = "Login With Otp"
                    context = {"otp": otp}
                    to_email = vendor["email"]
                    await send_email(to_email, source, context)
                elif vendor.get("phone"):
                    to_phone = vendor["phone"]
                    expiry_minutes = 10
                    await send_sms_on_phone(to_phone, otp, expiry_minutes)
                return {"message": "OTP sent to registered email/phone"}

            stored_password_hash = vendor.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                )

            if not bcrypt.checkpw(
                vendor_request.password.encode("utf-8"),
                stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")

            if not vendor.get("is_active", False):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Vendor user is not active")

            vendor_data = await vendor_collection.find_one({"_id": ObjectId(vendor["vendor_id"])})
            if not vendor_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor details not found")

            subscription = vendor_data.get("is_subscription")
            access_token = create_access_token(data={"sub": vendor["email"] or vendor["phone"]})
            refresh_token = create_refresh_token(data={"sub": vendor["email"] or vendor["phone"]})

            user_data = {
                "first_name": vendor.get("first_name"),
                "last_name": vendor.get("last_name"),
                "email": vendor.get("email"),
                "user_image": vendor.get("user_image"),
                "user_image_url": vendor.get("user_image_url"),
                "otp_expires": vendor.get("otp_expires"),
                "user_role": vendor.get("user_role"),
                "phone": vendor.get("phone"),
                "is_deleted": vendor.get("is_deleted", False),
                "is_active": vendor.get("is_active", False),
                "created_at": vendor.get("created_at"),
                "updated_at": vendor.get("updated_at"),
                "register_status": vendor.get("register_status"),
                "register_token": vendor.get("register_token"),
                "register_expires": vendor.get("register_expires"),
                "reset_password_token": vendor.get("reset_password_token"),
                "reset_password_expires": vendor.get("reset_password_expires"),
                "user_profile": vendor.get("user_profile"),
                "gender": vendor.get("gender"),
                "blood_group": vendor.get("blood_group"),
                "dob": vendor.get("dob"),
                "status": vendor.get("status"),
                "roles": vendor.get("roles"),
                "menu": vendor.get("menu", []),
                "address": vendor.get("address"),
                "secondary_phone_number": vendor.get("secondary_phone_number"),
                "availability_slots": vendor_data.get("availability_slots"),
                "notification_settings": vendor.get("notification_settings", {}),
                "id": str(vendor["_id"]),
                "is_subscription": subscription,
                "business_type": vendor_data.get("business_type"),
                "category_id": vendor_data.get("category_id"),
                "category_name": vendor_data.get("category_name"),
                "services": vendor_data.get("services"),
                "is_payment_required": vendor_data.get("is_payment_required"),
            }

            response = {
                "user_data": user_data,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }

            return response

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def vendor_sign_up(self, vendor_request: SignUpVendorRequest, background_tasks: BackgroundTasks):
        try:
            existing_vendor = None

            if vendor_request.email:
                existing_vendor = await user_collection.find_one({"email": vendor_request.email})
            elif vendor_request.phone:
                existing_vendor = await user_collection.find_one({"phone": vendor_request.phone})

            if existing_vendor:
                if existing_vendor.get("is_active", False):
                    raise HTTPException(
                        status_code=400, detail="User with this email or phone already exists and is active."
                    )

                # If the user exists but is not active, update their data and send a new OTP
                if vendor_request.email:  # Check if email is provided
                    email = vendor_request.email.lower()
                    vendor_request.email = email
                otp = generate_otp()
                expiry_time = datetime.utcnow() + timedelta(minutes=10)
                expiry_minutes = 10

                # Send OTP to email if provided
                if vendor_request.email:
                    source = "Activation_code"
                    context = {"otp": otp, "to_email": vendor_request.email, "name": vendor_request.first_name}
                    to_email = vendor_request.email
                    background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

                # Send OTP to phone if provided
                if vendor_request.phone:
                    to_phone = vendor_request.phone
                    await send_sms_on_phone(to_phone, otp, expiry_minutes)

                # Update the existing user with new data
                user_data = {
                    "sign_up_otp": otp,
                    "sign_up_otp_expires": expiry_time,
                    "password": hashpw(vendor_request.password.encode("utf-8"), gensalt()).decode("utf-8"),
                    "first_name": vendor_request.first_name,
                    "last_name": vendor_request.last_name,
                    "email": vendor_request.email if vendor_request.email else None,
                    "phone": int(vendor_request.phone) if vendor_request.phone else None,
                    "gender": vendor_request.gender,
                }

                # Update the user in the database
                await user_collection.update_one({"_id": ObjectId(existing_vendor["_id"])}, {"$set": user_data})

                # Update the vendor in the database
                vendor_data = {
                    "is_dashboard_created": True,
                    "business_name": vendor_request.business_name,
                    "business_type": vendor_request.business_type,
                    "is_subscription": False,
                }
                await vendor_collection.update_one(
                    {"_id": ObjectId(existing_vendor["vendor_id"])}, {"$set": vendor_data}
                )

                # Return the updated user data
                update_data = {
                    "first_name": vendor_request.first_name,
                    "last_name": vendor_request.last_name,
                    "email": vendor_request.email,
                    "phone": int(vendor_request.phone) if vendor_request.phone else None,
                    "sign_up_otp": otp,
                    "sign_up_otp_expires": expiry_time,
                    "roles": vendor_request.roles,
                    "is_dashboard_created": vendor_request.is_dashboard_created,
                    "business_name": vendor_request.business_name,
                    "business_type": vendor_request.business_type,
                }
                return update_data

            hashed_password = bcrypt.hashpw(vendor_request.password.encode("utf-8"), bcrypt.gensalt())
            vendor_request.is_dashboard_created = True
            otp = generate_otp()
            expiry_time = datetime.utcnow() + timedelta(minutes=10)
            expiry_minutes = 10

            vendor_data = {
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
                "is_subscription": False,
                "created_at": datetime.utcnow(),
            }

            vendor_result = await vendor_collection.insert_one(vendor_data)
            if vendor_result.inserted_id is None:
                raise HTTPException(status_code=500, detail="Failed to create vendor")

            new_vendor_user = {
                "first_name": vendor_request.first_name,
                "last_name": vendor_request.last_name,
                "email": vendor_request.email if vendor_request.email else None,
                "phone": int(vendor_request.phone) if vendor_request.phone else None,
                "sign_up_otp": otp,
                "sign_up_otp_expires": expiry_time,
                "roles": vendor_request.roles,
                "password": hashed_password,
                "status": vendor_request.status,
                "is_dashboard_created": vendor_request.is_dashboard_created,
                "vendor_id": ObjectId(vendor_result.inserted_id),
                "gender": vendor_request.gender,
            }

            if vendor_request.business_type.lower() == "individual":
                new_vendor_user["availability_slots"] = default_availability_slots()

            result = await user_collection.insert_one(new_vendor_user)
            if result.inserted_id is None:
                raise HTTPException(status_code=500, detail="Failed to create user")

            user_id = str(result.inserted_id)

            new_vendor_user["id"] = user_id
            new_vendor_user.pop("_id", None)
            new_vendor_user.pop("password", None)
            new_vendor_user.pop("sign_up_otp", None)
            new_vendor_user.pop("vendor_id")
            new_vendor_user["vendor_details"] = {
                "id": str(vendor_result.inserted_id),
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
            }

            if vendor_request.email:
                source = "Activation_code"
                context = {"otp": otp}
                to_email = vendor_request.email
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)
            elif vendor_request.phone:
                to_phone = vendor_request.phone
                await send_sms_on_phone(to_phone, otp, expiry_minutes)

            return new_vendor_user
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def vendor_profile(self, current_user: User):
        try:
            # current_user = await get_current_user(request=request, token=token)
            # if not current_user:
            #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            query = {"vendor_id": ObjectId(current_user.vendor_id)}
            vendor = await user_collection.find_one(query)
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            user_id = ObjectId(vendor["_id"])
            vendor_data = await vendor_collection.find_one({"_id": ObjectId(vendor["vendor_id"])})
            # Format the vendor to include only the necessary fields (id and name)
            vendor["id"] = str(vendor.pop("_id"))
            vendor.pop("password", None)
            vendor.pop("otp", None)
            vendor["first_name"] = vendor["first_name"].capitalize()
            vendor["last_name"] = vendor["last_name"].capitalize()
            if vendor["phone"]:
                vendor["phone"] = vendor["phone"] or ""
            if vendor["email"]:
                vendor["email"] = vendor["email"] or ""
            if vendor["gender"] is not None:
                vendor["gender"] = vendor.get("gender", "")
            else:
                vendor["gender"] = ""

            vendor["created_by"] = vendor.get("created_by", "Unknown")
            vendor["user_image"] = vendor.get("user_image", "")
            if vendor["user_image"] is not None:

                vendor["user_image_url"] = vendor.get("user_image_url", "")
            else:
                vendor["user_image_url"] = None
            vendor["fees"] = vendor.get("fees", "")
            vendor["specialization"] = vendor.get("specialization", "")
            vendor.pop("vendor_id", None)
            if vendor_data:
                vendor_data["id"] = str(vendor_data.pop("_id"))
                vendor_data["is_payment_required"] = vendor_data.get("is_payment_required", False)
                vendor_data["location"] = vendor_data.get("location", "")
                vendor_data.pop("_id", None)
                vendor.update(vendor_data)

            return vendor
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_profile(self, current_user: User, update_vendor_request: UpdateVendorRequest):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            if update_vendor_request.category_id is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Category ID is required.")

            if update_vendor_request.services is None or len(update_vendor_request.services) == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one service is required.")

            user_query = {"vendor_id": ObjectId(current_user.vendor_id)}
            user_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")

            if update_vendor_request.first_name is not None:
                user_data["first_name"] = update_vendor_request.first_name
            if update_vendor_request.last_name is not None:
                user_data["last_name"] = update_vendor_request.last_name
            if update_vendor_request.email is not None:
                email = update_vendor_request.email.lower()
                user_with_email = await User.find_one(User.email == email)
                if user_with_email and str(user_with_email.id) != str(current_user.id):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this email"
                    )
                user_data["email"] = email
            if update_vendor_request.phone is not None:
                user_with_phone = await User.find_one(User.phone == update_vendor_request.phone)
                if user_with_phone and str(user_with_phone.id) != str(current_user.id):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this phone"
                    )
                user_data["phone"] = update_vendor_request.phone
            if update_vendor_request.gender is not None:
                user_data["gender"] = update_vendor_request.gender
            if update_vendor_request.specialization is not None:
                user_data["specialization"] = update_vendor_request.specialization
            if update_vendor_request.fees is not None:
                user_data["fees"] = update_vendor_request.fees
            if update_vendor_request.user_image:
                image_name = update_vendor_request.user_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                user_data["user_image"] = image_name
                user_data["user_image_url"] = file_url
            else:
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{current_user.get('user_image')}"

            if user_data:
                await user_collection.update_one(user_query, {"$set": user_data})

            updated_user = await user_collection.find_one(user_query)
            if not updated_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            vendor_query = {"_id": ObjectId(current_user.vendor_id)}
            vendor_data = {}
            if update_vendor_request.location is not None:
                vendor_data["location"] = update_vendor_request.location.dict()
            if update_vendor_request.business_type is not None:
                vendor_data["business_type"] = update_vendor_request.business_type
            if update_vendor_request.fees is not None:
                vendor_data["fees"] = update_vendor_request.fees
            if update_vendor_request.business_address is not None:
                vendor_data["business_address"] = update_vendor_request.business_address
            if update_vendor_request.business_name is not None:
                vendor_data["business_name"] = update_vendor_request.business_name
            if update_vendor_request.is_payment_required is not None:
                vendor_data["is_payment_required"] = update_vendor_request.is_payment_required
            if update_vendor_request.category_id is not None:
                category_id = update_vendor_request.category_id
                category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
                if not category_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: {category_id}."
                    )
                vendor_data["category_id"] = category_id
                vendor_data["category_name"] = category_data.get("name")

            # Process services
            if update_vendor_request.services is not None:
                services = update_vendor_request.services
                if not isinstance(services, list):
                    services = [services]

                # Extract service IDs
                service_ids = [
                    ObjectId(service.id) if isinstance(service, Service) else ObjectId(service["id"])
                    for service in services
                ]

                # Fetch only active services matching the category and IDs
                query = {
                    "category_id": ObjectId(update_vendor_request.category_id or updated_user.get("category_id")),
                    "_id": {"$in": service_ids},
                    "status": "active",
                }
                valid_services = await services_collection.find(query).to_list(None)

                # Validate if all provided services are valid
                if len(valid_services) != len(service_ids):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="One or more services are invalid for the selected category.",
                    )

                # Add services details to the update data
                # vendor_data["services"] = [
                #     {
                #         "id": str(service["_id"]),
                #         "name": service["name"],
                #         "service_image": service["service_image"],
                #         "service_image_url": service["service_image_url"],
                #     }
                #     for service in valid_services
                # ]
                updated_services = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

                # Update vendor collection with the new services
                vendor_data["services"] = updated_services

                # Update the vendor_services_collection with the updated services
                vendor_service_update_result = await vendor_services_collection.update_one(
                    {
                        "vendor_id": ObjectId(current_user.vendor_id),
                        "vendor_user_id": ObjectId(current_user.id),
                    },
                    {"$set": {"services": updated_services}},
                )

            if update_vendor_request.service_details is not None:
                vendor_data["service_details"] = update_vendor_request.service_details
            if update_vendor_request.manage_plan is not None:
                vendor_data["manage_plan"] = update_vendor_request.manage_plan
            if update_vendor_request.manage_fee_and_gst is not None:
                vendor_data["manage_fee_and_gst"] = update_vendor_request.manage_fee_and_gst
            if update_vendor_request.manage_offer is not None:
                vendor_data["manage_offer"] = update_vendor_request.manage_offer
            if update_vendor_request.status is not None:
                vendor_data["status"] = update_vendor_request.status
            if update_vendor_request.business_details is not None:
                vendor_data["business_details"] = update_vendor_request.business_details

            if vendor_data:
                await vendor_collection.update_one(vendor_query, {"$set": vendor_data})

            updated_vendor = await vendor_collection.find_one(vendor_query)
            if not updated_vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            response_data = {
                # "user_id": str(updated_user["_id"]),
                "first_name": updated_user.get("first_name"),
                "last_name": updated_user.get("last_name"),
                "email": updated_user.get("email"),
                "phone": updated_user.get("phone"),
                "gender": updated_user.get("gender"),
                "user_image": updated_user.get("user_image"),
                "user_image_url": updated_user.get("user_image_url"),
                "specialization": updated_user.get("specialization"),
                "fees": updated_user.get("fees"),
                "vendor_details": {
                    "business_details": updated_vendor.get("business_details"),
                    "business_name": updated_vendor.get("business_name"),
                    "business_type": updated_vendor.get("business_type"),
                    "fees": updated_vendor.get("fees"),
                    "business_address": updated_vendor.get("business_address"),
                    "category_id": updated_vendor.get("category_id"),
                    "category_name": updated_vendor.get("category_name"),
                    "services": updated_vendor.get("services"),
                    "service_details": updated_vendor.get("service_details"),
                    "manage_plan": updated_vendor.get("manage_plan"),
                    "manage_fee_and_gst": updated_vendor.get("manage_fee_and_gst"),
                    "manage_offer": updated_vendor.get("manage_offer"),
                    "is_payment_required": updated_vendor.get("is_payment_required"),
                    "availability_slots": updated_vendor.get("availability_slots"),
                    "location": updated_vendor.get("location"),
                    "status": updated_vendor.get("status"),
                },
            }
            return response_data

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def create_vendor_user(self, current_user: User, vendor_user_create_request: VendorUserCreateRequest):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor or vendor.get("business_type") != "business":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only vendors with business type 'business' can create vendor users.",
                )

            if (
                not vendor_user_create_request.first_name
                or not vendor_user_create_request.last_name
                or not vendor_user_create_request.email
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="First name, last name, and email are required for vendor user creation.",
                )

            query = {"email": vendor_user_create_request.email}
            existing_vendor_user = await user_collection.find_one(query)
            if existing_vendor_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A user with the provided email already exists.",
                )

            # Handling image URL logic
            image_name = vendor_user_create_request.user_image
            file_url = None
            if image_name:
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"

            vendor_user_create_request.category = vendor.get("category_name")
            services = vendor_user_create_request.services
            if not isinstance(services, list):
                services = [services]

            service_ids = [ObjectId(service.id) for service in services]
            vendor_services = vendor.get("services", [])
            vendor_service_ids = [ObjectId(service["id"]) for service in vendor_services]
            if not all(service_id in vendor_service_ids for service_id in service_ids):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="One or more services are invalid or not associated with the vendor.",
                )
            valid_services = [service for service in vendor_services if ObjectId(service["id"]) in service_ids]

            # Create the new vendor user
            new_vendor_user = {
                "first_name": vendor_user_create_request.first_name,
                "last_name": vendor_user_create_request.last_name,
                "email": vendor_user_create_request.email,
                "fees": vendor_user_create_request.fees,
                "gender": vendor_user_create_request.gender,
                "phone": vendor_user_create_request.phone,
                "roles": vendor_user_create_request.roles,
                "status": vendor_user_create_request.status,
                "created_by": str(current_user.id),
                "vendor_id": ObjectId(current_user.vendor_id),
                "category": vendor_user_create_request.category,
                "user_image": vendor_user_create_request.user_image,
                "user_image_url": file_url,
                "specialization": vendor_user_create_request.specialization,
                "created_at": datetime.utcnow(),
                "services": [
                    {
                        "id": str(service["id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ],
                "availability_slots": default_availability_slots(),
            }

            # Insert the new vendor user
            result = await user_collection.insert_one(new_vendor_user)

            # Create vendor service record
            vendor_service_data = {
                "vendor_id": ObjectId(vendor["_id"]),  # Vendor ObjectId
                "vendor_user_id": ObjectId(result.inserted_id),
                "services": [
                    {
                        "service_id": ObjectId(service["id"]),
                        "service_name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ],
            }

            # Insert into vendor services collection
            await vendor_services_collection.insert_one(vendor_service_data)

            # Add ID to the response and clean up unnecessary fields
            new_vendor_user["id"] = str(result.inserted_id)
            new_vendor_user.pop("_id", None)
            new_vendor_user.pop("vendor_id", None)

            return new_vendor_user

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def vendor_users_list(
        self,
        current_user: User,
        page: int,
        limit: int,
        search: str = None,
    ):
        try:

            # Check if the current user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Query to filter users with the "vendor_user" role and created by the current user
            skip = max((page - 1) * limit, 0)
            query = {
                "roles": {"$in": ["vendor_user"]},
                "vendor_id": ObjectId(current_user.vendor_id),  # Match created_by with the current user's ID
            }
            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"first_name": search_regex},
                    {"last_name": search_regex},
                    {"email": search_regex},
                    {"phone": search_regex},
                ]

            vendor_users = await user_collection.find(query).skip(skip).limit(limit).to_list(length=limit)
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")
            formatted_users = []

            for user in vendor_users:
                user["id"] = str(user.pop("_id", ""))
                user.pop("vendor_id", None)
                ist_timezone = pytz.timezone("Asia/Kolkata")

                created_at = user.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    user["created_at"] = created_at_ist.isoformat()
                formatted_users.append(user)
            total_users = await user_collection.count_documents(query)
            total_pages = (total_users + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": formatted_users,
                "paginator": {
                    "itemCount": total_users,
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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def set_individual_vendor_availability(
        self, current_user: User, slots: List[DaySlot], vendor_user_id: Optional[str] = None
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Get the vendor's current data
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            if vendor_user_id:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
                if vendor_user["vendor_id"] != ObjectId(current_user.vendor_id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                    )
                new_availability_slots = []
                for day_slot in slots:
                    day_slot_data = day_slot.dict()
                    for time_slot in day_slot_data.get("time_slots", []):
                        # Ensure max_seat is included
                        if "max_seat" not in time_slot:
                            time_slot["max_seat"] = 10
                        time_slot["max_seat"] = int(time_slot["max_seat"])
                        # Convert time objects to strings if necessary
                        if isinstance(time_slot["start_time"], time):
                            time_slot["start_time"] = time_slot["start_time"].strftime("%H:%M")
                        if isinstance(time_slot["end_time"], time):
                            time_slot["end_time"] = time_slot["end_time"].strftime("%H:%M")
                    new_availability_slots.append(day_slot_data)
                await user_collection.update_one(
                    {"_id": ObjectId(vendor_user_id)},
                    {"$set": {"availability_slots": new_availability_slots}},
                )

                # Return updated data
                updated_vendor = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not updated_vendor:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
                updated_vendor["id"] = str(updated_vendor.pop("_id", ""))
                updated_vendor.pop("vendor_id", None)
                return updated_vendor

            # Prepare the new availability slots
            new_availability_slots = []
            for day_slot in slots:
                day_slot_data = day_slot.dict()
                for time_slot in day_slot_data.get("time_slots", []):
                    # Ensure max_seat is included
                    if "max_seat" not in time_slot:
                        time_slot["max_seat"] = 10
                    time_slot["max_seat"] = int(time_slot["max_seat"])
                    # Convert time objects to strings if necessary
                    if isinstance(time_slot["start_time"], time):
                        time_slot["start_time"] = time_slot["start_time"].strftime("%H:%M")
                    if isinstance(time_slot["end_time"], time):
                        time_slot["end_time"] = time_slot["end_time"].strftime("%H:%M")
                new_availability_slots.append(day_slot_data)

            # Replace old availability slots with new ones
            await user_collection.update_one(
                {"vendor_id": ObjectId(vendor["_id"])}, {"$set": {"availability_slots": new_availability_slots}}
            )

            # Return updated data

            updated_vendor = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
            if not updated_vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            updated_vendor["id"] = str(updated_vendor.pop("_id", ""))
            updated_vendor.pop("vendor_id", "")

            return updated_vendor

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_vendor_availability(self, current_user: User, vendor_user_id: str = None):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            if vendor_user_id:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
                availability_slots = vendor_user.get("availability_slots", [])
                return availability_slots
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            availability_slots = vendor_user.get("availability_slots", [])
            return availability_slots
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_vendor_availability(self, current_user: User, slots: List[DaySlot]):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            availability_slots = vendor.get("availability_slots", [])
            for day_slot in slots:
                day_slot_data = day_slot.dict()
                for time_slot in day_slot_data.get("time_slots", []):
                    time_slot["start_time"] = (
                        time_slot["start_time"].strftime("%H:%M")
                        if isinstance(time_slot["start_time"], time)
                        else time_slot["start_time"]
                    )
                    time_slot["end_time"] = (
                        time_slot["end_time"].strftime("%H:%M")
                        if isinstance(time_slot["end_time"], time)
                        else time_slot["end_time"]
                    )

                    ts = TimeSlot(**time_slot)
                    ts.calculate_duration()
                    time_slot["duration"] = ts.duration
                availability_slots.append(day_slot_data)
            await vendor_collection.update_one(
                {"_id": vendor["_id"]}, {"$set": {"availability_slots": availability_slots}}
            )

            updated_vendor = await vendor_collection.find_one({"_id": (vendor["_id"])})
            if updated_vendor:
                updated_vendor = serialize_mongo_document(updated_vendor)

            updated_vendor["id"] = str(updated_vendor.pop("_id"))
            return updated_vendor

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def add_slot_time_vendor(self, current_user: User, id: str, slots: List[DaySlot]):
        """
        Set availability slots for a specific user created by the current business user.

        Args:
                request (Request): The HTTP request object.
                token (str): Authentication token for the current user.
                user_id (str): ID of the user for whom slots are being set.
                slots (List[DaySlot]): List of slots to be added.

        Returns:
                dict: Updated user availability slots.
        """
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            if vendor.get("business_type") != "business":

                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: User is not a business")
            user = await user_collection.find_one({"_id": ObjectId(id), "created_by": str(current_user.id)})
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: The provided user ID is not associated with this business user",
                )
            new_availability_slots = user.get("availability_slots", [])
            new_availability_slots = []
            for day_slot in slots:
                day_slot_data = day_slot.dict()
                for time_slot in day_slot_data.get("time_slots", []):
                    time_slot["start_time"] = (
                        time_slot["start_time"].strftime("%H:%M")
                        if isinstance(time_slot["start_time"], time)
                        else time_slot["start_time"]
                    )
                    time_slot["end_time"] = (
                        time_slot["end_time"].strftime("%H:%M")
                        if isinstance(time_slot["end_time"], time)
                        else time_slot["end_time"]
                    )

                    ts = TimeSlot(**time_slot)
                    ts.calculate_duration()
                    time_slot["duration"] = ts.duration

                new_availability_slots.append(day_slot_data)
            await user_collection.update_one(
                {"_id": ObjectId(id)}, {"$set": {"availability_slots": new_availability_slots}}
            )
            updated_user = await user_collection.find_one({"_id": ObjectId(id)})
            if updated_user:
                updated_user = serialize_mongo_document(updated_user)

            updated_user["id"] = str(updated_user.pop("_id"))
            return updated_user

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def change_password_vendor(self, email: str, old_password: str, new_password: str) -> dict:
        try:
            user = await User.find_one(User.email == email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            if old_password is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Old Password required")
            if not bcrypt.checkpw(old_password.encode("utf-8"), user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Old password does not match",
                )

            if bcrypt.checkpw(new_password.encode("utf-8"), user.password.encode("utf-8")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password cannot be the same as the old password",
                )

            hashed_new_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            await user_collection.update_one(
                {"email": email}, {"$set": {"password": hashed_new_password, "is_dashboard_created": True}}
            )
            return {"email": user.email}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def create_vendor_slots(self, current_user: User, vendor_id: str, slots: List[DaySlot]):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor = await vendor_collection.find_one({"_id": ObjectId(user["vendor_id"])})
            if not vendor:
                # user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
                # if not user:
                #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
                # vendor = await vendor_collection.find_one({"user_id": user["created_by"]})
                # if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            new_availability_slots = []

            for day_slot in slots:
                day_slot_data = day_slot.dict()
                for time_slot in day_slot_data.get("time_slots", []):
                    # Ensure max_seat is included
                    if "max_seat" not in time_slot:
                        time_slot["max_seat"] = 10
                    time_slot["max_seat"] = int(time_slot["max_seat"])
                    # Convert time objects to strings if necessary
                    if isinstance(time_slot["start_time"], time):
                        time_slot["start_time"] = time_slot["start_time"].strftime("%H:%M")
                    if isinstance(time_slot["end_time"], time):
                        time_slot["end_time"] = time_slot["end_time"].strftime("%H:%M")
                    # Create TimeSlot instance and calculate duration
                    # ts = TimeSlot(**time_slot)
                    # ts.calculate_duration()  # Calculate duration
                    # time_slot["duration"] = ts.duration  # Add duration to the time_slot

                new_availability_slots.append(day_slot_data)
            update_result = await user_collection.update_one(
                {"_id": ObjectId(vendor_id)}, {"$set": {"availability_slots": new_availability_slots}}
            )
            updated_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if updated_user:
                updated_user = serialize_mongo_document(updated_user)
                updated_user["id"] = str(updated_user.pop("_id"))
                updated_user["vendor_id"] = str(updated_user.pop("vendor_id"))
                return updated_user

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_slots(self, current_user: User, vendor_id: str):
        """
        Fetch availability slots for a vendor or vendor_user.

        Args:
                request (Request): The HTTP request object.
                token (str): Authentication token for the current user.
                vendor_id (str): ID of the vendor or vendor_user.

        Returns:
                dict: Vendor data along with availability slots.
        """
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            user_data = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if not user_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            vendor = await vendor_collection.find_one({"_id": ObjectId(user_data["vendor_id"])})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent vendor not found")

            # availability_slots = user_data.get("availability_slots", [])
            business_type = vendor.get("business_type", "individual")
            if business_type == "individual":
                availability_slots = user_data.get("availability_slots", [])
                return {
                    # "vendor_id": vendor["user_id"],
                    "vendor_name": vendor.get("business_name", "N/A"),
                    "business_type": business_type,
                    "availability_slots": availability_slots,
                }

            parent_vendor = await vendor_collection.find_one({"_id": ObjectId(user_data["vendor_id"])})
            if not parent_vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent vendor not found")

            user_slots = user_data.get("availability_slots", [])

            response = {
                # "vendor_id": parent_vendor["user_id"],
                "vendor_name": parent_vendor.get("business_name", "N/A"),
                "vendor_user_id": str(user_data["_id"]),
                "vendor_user_name": f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip(),
                "business_type": business_type,
                "availability_slots": user_slots,
            }
            return response

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_list_for_slot(
        self,
        current_user: User,
    ):
        try:
            # Ensure the user is a super admin
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            query = {"roles": {"$regex": "^vendor$", "$options": "i"}}
            # Fetch all vendors from the user collection (consider filtering for vendor-specific users)
            vendors = await user_collection.find(query).to_list(None)  # Assuming role 'vendor' is used for vendor users
            vendor_data = []

            for vendor in vendors:
                vendor_id = str(vendor.pop("_id"))  # Extract vendor ID and remove it from the document
                vendor["id"] = vendor_id

                # Capitalize names and format email
                vendor["first_name"] = vendor.get("first_name", "").capitalize()
                vendor["last_name"] = vendor.get("last_name", "").capitalize()
                vendor["email"] = vendor.get("email", "").lower()
                vendor_user_id = vendor.get("vendor_id", None)
                vendor.pop("vendor_id", None)

                # Fetch vendor-specific data in parallel using asyncio.gather
                vendor_details = await vendor_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if vendor_details:
                    vendor["business_name"] = vendor_details.get("business_name", "Unknown")
                    vendor["business_type"] = vendor_details.get("business_type", "Unknown")
                    vendor["business_address"] = vendor_details.get("business_address", "Unknown")
                    vendor["business_details"] = vendor_details.get("business_details", "No Details")
                    vendor["services"] = vendor_details.get("services", [])
                    vendor["service_details"] = vendor_details.get("service_details", [])
                    vendor["manage_plan"] = vendor_details.get("manage_plan", False)
                    vendor["manage_fee_and_gst"] = vendor_details.get("manage_fee_and_gst", False)
                    vendor["manage_offer"] = vendor_details.get("manage_offer", False)
                    vendor["is_payment_verified"] = vendor_details.get("is_payment_verified", False)
                    vendor["status"] = vendor_details.get("status", "N/A")
                    vendor["created_at"] = vendor_details.get("created_at")

                    # Fetch category name
                    category_id = vendor_details.get("category_id")
                    if category_id:
                        category = await category_collection.find_one({"_id": ObjectId(category_id)})
                        vendor["category_name"] = category.get("name", "Unknown") if category else "Unknown"
                    else:
                        vendor["category_name"] = "Unknown"

                vendor.pop("password", None)
                vendor.pop("otp", None)

                vendor_data.append(vendor)

            return {
                "data": vendor_data,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def vendor_user_list_for_slot(self, current_user: User, vendor_id: str):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            if not ObjectId.is_valid(vendor_id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID")
            # vendor_details = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            # if not vendor_details:
            #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            # if vendor_details.get("business_type") != "business":
            #     raise HTTPException(
            #         status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor's business type is not 'business'"
            #     )
            users = await user_collection.find({"created_by": vendor_id}).to_list(None)
            if not users:
                users = await user_collection.find({"vendor_id": ObjectId(vendor_id), "roles": "vendor_user"}).to_list(
                    None
                )
            vendor_user_data = []

            for user in users:
                user_data = {
                    "id": str(user["_id"]),
                    "first_name": user.get("first_name", "").capitalize(),
                    "last_name": user.get("last_name", "").capitalize(),
                    "email": user.get("email", ""),
                    "created_at": user.get("created_at"),
                }
                vendor_user_data.append(user_data)

            return {
                "data": vendor_user_data,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def update_vendor_user_by_id(
        self, current_user: User, id: str, vendor_user_request: VendorUserUpdateRequest, role: str = "vendor"
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vendor user ID")

            vendor_user = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            if vendor_user.get("created_by") != str(current_user.id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to update this user"
                )
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            user_vendor_update_data = {}

            if vendor_user_request.first_name is not None:
                user_vendor_update_data["first_name"] = vendor_user_request.first_name.capitalize()
            if vendor_user_request.last_name is not None:
                user_vendor_update_data["last_name"] = vendor_user_request.last_name.capitalize()
            if vendor_user_request.email is not None:
                user_vendor_update_data["email"] = vendor_user_request.email
            if vendor_user_request.phone is not None:
                user_vendor_update_data["phone"] = vendor_user_request.phone
            if vendor_user_request.fees is not None:
                user_vendor_update_data["fees"] = vendor_user_request.fees
            if vendor_user_request.status is not None:
                user_vendor_update_data["status"] = vendor_user_request.status
            if vendor_user_request.gender is not None:
                user_vendor_update_data["gender"] = vendor_user_request.gender
            if vendor_user_request.specialization is not None:
                user_vendor_update_data["specialization"] = vendor_user_request.specialization
            if vendor_user_request.services is not None:
                services = vendor_user_request.services
                if not isinstance(services, list):
                    services = [services]

                service_ids = [
                    ObjectId(service.id) if isinstance(service, Service) else ObjectId(service["id"])
                    for service in services
                ]

                query = {
                    "category_id": ObjectId(vendor.get("category_id")),
                    "_id": {"$in": service_ids},
                    "status": "active",
                }
                valid_services = await services_collection.find(query).to_list(None)

                if len(valid_services) != len(service_ids):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="One or more services are invalid for the selected category.",
                    )

                # vendor_update_data["services"] = [
                #     {
                #         "id": str(service["_id"]),
                #         "name": service["name"],
                #         "service_image": service["service_image"],
                #         "service_image_url": service["service_image_url"],
                #     }
                #     for service in valid_services
                # ]
                updated_services = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

                # Update vendor collection with the new services
                user_vendor_update_data["services"] = updated_services

                # Update the vendor_services_collection with the updated services
                vendor_service_update_result = await vendor_services_collection.update_one(
                    {"vendor_user_id": ObjectId(id)},
                    {"$set": {"services": updated_services}},
                )

            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            if vendor_user_request.user_image:
                image_name = vendor_user_request.user_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                user_vendor_update_data["user_image"] = image_name
                user_vendor_update_data["user_image_url"] = file_url
            else:
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{vendor_user.get('user_image')}"

            # Update the user document with the new data
            result = await user_collection.update_one({"_id": ObjectId(id)}, {"$set": user_vendor_update_data})

            updated_user = await user_collection.find_one({"_id": ObjectId(id)})
            if updated_user:
                updated_user["id"] = str(updated_user.pop("_id"))
                updated_user.pop("vendor_id", "")

            return updated_user

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def delete_vendor_user_by_id(self, current_user: User, id: str):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vendor user ID")
            vendor_user = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            if vendor_user.get("created_by") != str(current_user.id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to delete this user"
                )

            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if result.deleted_count == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Failed to delete the vendor user")

            return {}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def get_vendor_user_by_id(self, current_user: User, id: str, role: str = "vendor"):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vendor user ID")
            vendor_user = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            if vendor_user.get("vendor_id") != ObjectId(current_user.vendor_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to view this user"
                )
            vendor_user["id"] = str(vendor_user.pop("_id"))
            vendor_user.pop("vendor_id", "")
            return vendor_user

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def vendor_subscription_plan(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            vendor = await vendor_collection.find_one({"user_id": current_user.id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            subscription_plan = vendor.get("manage_plan", False)

            return subscription_plan

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def create_or_upgrade_vendor_subscription(
        self, current_user: User, vendor_subscription_request: VendorSubscriptionRequest
    ):
        try:

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Fetch the vendor's details
            current_user_id = str(current_user.vendor_id)
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Fetch the new plan details
            plan_details = razorpay_client.plan.fetch(vendor_subscription_request.plan_id)
            if not plan_details:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

            # Ensure plan_details["item"] is a dictionary
            if isinstance(plan_details["item"], str):
                plan_details["item"] = json.loads(plan_details["item"])

            # Now you can safely access plan_details["item"]["amount"]
            new_plan_amount = int(plan_details["item"]["amount"])

            interval = plan_details.get("interval", 1)
            period = plan_details.get("period", "monthly").lower()

            if period not in ["daily", "weekly", "monthly", "yearly"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported interval type: {period}"
                )

            if period == "monthly":
                total_count = vendor_subscription_request.total_count * 12
            elif period == "yearly":
                total_count = vendor_subscription_request.total_count
            elif period == "weekly":
                total_count = vendor_subscription_request.total_count * 52
            elif period == "daily":
                total_count = vendor_subscription_request.total_count * 365

            razorpay_subscription_data = {
                "plan_id": vendor_subscription_request.plan_id,
                "total_count": total_count,
                "quantity": vendor_subscription_request.quantity,
                "customer_notify": True,
            }

            # Check if the vendor has an active subscription
            if vendor.get("razorpay_subscription_id"):
                # Fetch the current subscription details from Razorpay
                current_subscription_id = vendor["razorpay_subscription_id"]
                try:
                    current_subscription = razorpay_client.subscription.fetch(current_subscription_id)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to fetch current subscription details: {str(e)}",
                    )

                # Fetch the plan details for the current subscription
                try:
                    current_plan_id = current_subscription["plan_id"]
                    if isinstance(current_plan_id, dict):
                        current_plan_id = current_plan_id["id"]  # Extract the plan ID if it's a dictionary

                    current_plan_details = razorpay_client.plan.fetch(current_plan_id)

                    # Ensure current_plan_details["item"] is a dictionary
                    if isinstance(current_plan_details["item"], str):
                        current_plan_details["item"] = json.loads(current_plan_details["item"])

                    # Calculate the remaining amount from the current subscription
                    current_plan_amount = int(current_plan_details["item"]["amount"])
                    current_plan_start_date = datetime.fromtimestamp(current_subscription["start_at"])
                    current_plan_period = current_plan_details["period"].lower()

                    total_days_in_plan = PERIOD_TO_DURATION.get(current_plan_period, 30)
                    # Calculate the unused portion of the current subscription
                    current_date = datetime.now()
                    subscription_end_date = current_plan_start_date + timedelta(days=total_days_in_plan)
                    days_used = (subscription_end_date - current_date).days
                    remaining_days = (subscription_end_date - current_date).days
                    remaining_amount = (current_plan_amount / total_days_in_plan) * remaining_days

                    # Deduct the remaining amount from the new plan's cost
                    adjusted_amount = max(new_plan_amount - remaining_amount, 0)  # Ensure it doesn’t go negative
                    adjusted_amount = int(round(adjusted_amount))  # Round to the nearest integer
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to fetch or process current plan details: {str(e)}",
                    )
            else:
                adjusted_amount = int(plan_details["item"]["amount"])

            # Create a new subscription with the adjusted amount
            try:
                razorpay_subscription = razorpay_client.subscription.create(data=razorpay_subscription_data)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to create Razorpay subscription: {str(e)}",
                )

            # Create a new order for the adjusted amount
            order_data = {
                "amount": adjusted_amount,
                "currency": "INR",
                "receipt": f"sub_{razorpay_subscription['id']}",
                "notes": {
                    "subscription_id": razorpay_subscription["id"],
                    "vendor_id": str(vendor["_id"]),
                },
                "payment_capture": 1,
            }

            try:
                razorpay_order = razorpay_client.order.create(data=order_data)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to create Razorpay order: {str(e)}",
                )

            # Update the vendor's subscription details
            vendor_update_data = {
                "razorpay_order_id": razorpay_order["id"],
            }

            result = await vendor_collection.update_one({"_id": vendor["_id"]}, {"$set": vendor_update_data})
            if result.modified_count == 0:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update vendor")

            return {
                "subscription_id": razorpay_subscription["id"],
                "order_id": razorpay_order["id"],
                "amount": order_data["amount"],
                "currency": order_data["currency"],
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def verify_subscription_payment(self, current_user: User, subscription_id: str):

        try:
            # Check if the user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Fetch subscription details from Razorpay
            try:
                subscription_details = razorpay_client.subscription.fetch(subscription_id)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to fetch Razorpay subscription: {str(e)}",
                )

            # Check subscription status (case-insensitive)
            subscription_status = subscription_details.get("status", "").lower()
            is_active = subscription_status in ["active", "authenticated", "completed", "created"]

            # Fetch vendor details
            current_user_id = str(current_user.vendor_id)
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # If the subscription is active, proceed with cancellation of the existing plan and update with the new plan
            if is_active:
                # Check if the vendor has an existing subscription
                if vendor.get("razorpay_subscription_id"):
                    existing_subscription_id = vendor["razorpay_subscription_id"]
                    try:
                        # Cancel the existing subscription
                        razorpay_client.subscription.cancel(existing_subscription_id)
                    except Exception as e:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to cancel existing subscription: {str(e)}",
                        )

                # Update vendor details with the new subscription
                vendor_update_data = {
                    "razorpay_subscription_id": subscription_id,
                    "is_subscription": True,
                    "manage_plan": subscription_details.get("plan_id"),
                }
                await vendor_collection.update_one({"_id": vendor["_id"]}, {"$set": vendor_update_data})

            # Return the subscription status and details
            return {
                "subscription_id": subscription_id,
                "status": subscription_status,
                "is_active": is_active,
                "is_subscription": True,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def subscription_payment_details(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            current_user_id = str(current_user.vendor_id)
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            if not vendor.get("razorpay_subscription_id"):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")

            subscription_id = vendor.get("razorpay_subscription_id")
            subscription = razorpay_client.subscription.fetch(subscription_id)
            # statuss = subscription.get("status")
            # if statuss != "active":
            #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subscription is not active")

            plan_id = subscription.get("plan_id")
            plan_details = razorpay_client.plan.fetch(plan_id)
            plan_data = await plan_collection.find_one({"razorpay_plan_id": str(plan_id)})

            def format_timestamp(timestamp):
                return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else None

            def format_amount(amount):
                return amount / 100 if amount else 0  # Convert to rupees

            subscription_details = {
                **subscription,
                "current_start": format_timestamp(subscription.get("current_start")),
                "current_end": format_timestamp(subscription.get("current_end")),
                "start_at": format_timestamp(subscription.get("start_at")),
                "end_at": format_timestamp(subscription.get("end_at")),
                "charge_at": format_timestamp(subscription.get("charge_at")),
                "created_at": format_timestamp(subscription.get("created_at")),
            }

            # Formatting plan details
            plan_details["item"]["amount"] = format_amount(plan_details["item"].get("amount"))
            plan_details["item"]["unit_amount"] = format_amount(plan_details["item"].get("unit_amount"))
            plan_details["created_at"] = format_timestamp(plan_details.get("created_at"))
            plan_details["features"] = plan_data.get("features")
            # Return the formatted data
            return {
                "vendor": {
                    "id": str(vendor.get("_id")),
                    "name": current_user.first_name,
                    "email": current_user.email,
                    "phone": current_user.phone,
                    "business_name": vendor.get("business_name"),
                    "razorpay_subscription_id": vendor.get("razorpay_subscription_id"),
                    "is_subscription": vendor.get("is_subscription"),
                },
                "subscription_details": subscription_details,
                "plan_details": plan_details,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def get_plan_list(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            plans = await plan_collection.find({"status": "active"}).to_list(length=100)
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor_active_plan_id = str(vendor.get("manage_plan", ""))
            for plan in plans:
                plan["id"] = str(plan["_id"])
                plan_id = str(plan["razorpay_plan_id"])

                plan.pop("_id", None)
                plan["is_active_plan"] = plan_id == vendor_active_plan_id

            return plans
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def get_all_plan_list(self):
        try:
            plans = await plan_collection.find({"status": "active"}).to_list(length=100)

            for plan in plans:
                plan["id"] = str(plan["_id"])
                plan.pop("_id", None)

            return plans
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def get_plan(self, current_user: User, plan_id: str):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            # Fetch the requested plan by ID
            plan = await plan_collection.find_one({"_id": ObjectId(plan_id)})
            if not plan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

            # Get the name of the plan
            plan_name = plan.get("name")
            if not plan_name:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan name not found")

            # Fetch all plans with the same name
            plans = await plan_collection.find({"name": plan_name}).to_list(length=100)
            if not plans:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No plans found with the same name")

            # Convert _id to string for each plan
            for p in plans:
                p["id"] = str(p["_id"])
                p.pop("_id", None)

            # Fetch vendor details
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            for p in plans:
                new_plan_price = p.get("amount", 0)
                discounted_price = new_plan_price

                if "manage_plan" in vendor and vendor["manage_plan"]:
                    # Fetch current plan details
                    current_plan = await plan_collection.find_one({"razorpay_plan_id": vendor["manage_plan"]})
                    if current_plan:
                        current_plan_price = current_plan.get("amount", 0)

                        # Calculate current_plan_duration based on period
                        current_plan_period = current_plan.get("period")
                        current_plan_duration = PERIOD_TO_DURATION.get(current_plan_period, 30)

                        subscription_id = vendor.get("razorpay_subscription_id")
                        subscription = razorpay_client.subscription.fetch(subscription_id)
                        subscription_start_date = subscription.get("start_at")
                        if subscription_start_date:
                            subscription_start_date = datetime.fromtimestamp(subscription_start_date)
                            today = datetime.now()
                            subscription_end_date = subscription_start_date + timedelta(days=current_plan_duration)

                            remaining_days = (subscription_end_date - today).days
                            if remaining_days > 0:
                                # Calculate daily rate based on the current plan's price and duration
                                daily_rate = current_plan_price / current_plan_duration
                                remaining_value = daily_rate * remaining_days
                                # Deduct the remaining value from the new plan's price
                                discounted_price = max(new_plan_price - remaining_value, 0)
                # Add the calculated price to the response
                p["amount"] = discounted_price

            # Fetch active payments
            payments = await payment_collection.find({"status": "active"}).to_list(length=100)
            for payment in payments:
                payment["id"] = str(payment["_id"])
                payment.pop("_id", None)

            # Prepare the response
            response = {
                "vendor": {
                    "id": str(current_user.id),
                    "first_name": current_user.first_name,
                    "email": current_user.email,
                    "phone": current_user.phone,
                },
                "payments": payments,
                "plans": plans,  # Include all plans here
            }
            return response
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    # async def get_plan(self, request: Request, token: str, plan_id: str):
    #     try:
    #         # Get the current user
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    #         if "vendor" not in [role.value for role in current_user.roles]:
    #             raise HTTPException(
    #                 status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
    #             )

    #         # Fetch the requested plan
    #         plan = await plan_collection.find_one({"_id": ObjectId(plan_id)})
    #         if not plan:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

    #         # Convert _id to string
    #         plan["id"] = str(plan["_id"])
    #         plan.pop("_id", None)

    #         # Fetch vendor details
    #         vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
    #         if not vendor:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

    #         # Check if vendor has an active subscription
    #         amounts = plan.get("amounts", [])  # Get all amounts for the plan
    #         discounted_amounts = []  # Store discounted amounts for each period

    #         if "manage_plan" in vendor and vendor["manage_plan"]:
    #             # Fetch current plan details
    #             current_plan = await plan_collection.find_one({"razorpay_plan_id": vendor["manage_plan"]})
    #             if current_plan:
    #                 current_plan_amounts = current_plan.get("amounts", [])
    #                 current_plan_price = current_plan_amounts[0]["value"] if current_plan_amounts else 0  # Use the first amount as the base price

    #                 subscription_id = vendor.get("razorpay_subscription_id")
    #                 subscription = razorpay_client.subscription.fetch(subscription_id)
    #                 subscription_end_date = subscription.get("current_end")  # Assume this field exists
    #                 if subscription_end_date:
    #                     subscription_end_date = datetime.fromtimestamp(
    #                         subscription_end_date
    #                     )  # Convert timestamp to datetime
    #                     today = datetime.today()
    #                     remaining_days = (subscription_end_date - today).days  # Calculate remaining days

    #                     if remaining_days > 0:
    #                         # Prorate the current plan cost
    #                         daily_rate = current_plan_price / 30  # Assuming monthly plans have 30 days
    #                         remaining_value = daily_rate * remaining_days

    #                         # Deduct from each amount in the new plan
    #                         for amount_item in amounts:
    #                             new_plan_price = amount_item["value"]
    #                             discounted_price = max(new_plan_price - remaining_value, 0)  # Ensure it doesn’t go negative
    #                             discounted_amounts.append({
    #                                 "type": amount_item["type"],
    #                                 "value": discounted_price,
    #                             })
    #             else:
    #                 # If no current plan, use the original amounts
    #                 discounted_amounts = amounts
    #         else:
    #             # If no active subscription, use the original amounts
    #             discounted_amounts = amounts

    #         # Add the calculated amounts to the response
    #         plan["amounts"] = discounted_amounts

    #         # Fetch active payments
    #         payments = await payment_collection.find({"status": "active"}).to_list(length=100)
    #         for payment in payments:
    #             payment["id"] = str(payment["_id"])
    #             payment.pop("_id", None)

    #         plan["vendor"] = {
    #             "id": str(current_user.id),
    #             "first_name": current_user.first_name,
    #             "email": current_user.email,
    #             "phone": current_user.phone,
    #         }
    #         plan["payments"] = payments

    #         return plan

    #     except HTTPException as e:
    #         raise e
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    #             detail=f"An unexpected error occurred: {str(ex)}",
    #         )

    async def vendor_users_list_for_slot(
        self,
        current_user: User,
    ):
        try:
            # Check if the current user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Query to filter users with the "vendor_user" role and created by the current user
            query = {
                "roles": {"$in": ["vendor_user"]},
                "created_by": str(current_user.id),  # Match created_by with the current user's ID
            }

            # Find users matching the query
            vendor_users = await user_collection.find(query).to_list(length=100)
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")
            formatted_users = []
            for user in vendor_users:
                user["id"] = str(user.pop("_id", ""))
                user.pop("vendor_id", "")
                formatted_users.append(user)

            return {"data": formatted_users}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_dashboard_data_for_vendor(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Use current_user.id as vendor_id
            vendor = str(current_user.vendor_id)
            vendor_obj = await vendor_collection.find_one({"_id": ObjectId(vendor)})

            vendor_id = vendor_obj["_id"]
            total_bookings = await booking_collection.count_documents({"vendor_id": ObjectId(vendor_id)})

            # Bookings that are canceled
            canceled_bookings = await booking_collection.count_documents(
                {"booking_status": "cancelled", "vendor_id": ObjectId(vendor_id)}
            )
            # Bookings that are rescheduled
            reschedule_bookings = await booking_collection.count_documents(
                {"booking_status": "rescheduled", "vendor_id": ObjectId(vendor_id)}
            )

            return {
                "total_bookings": total_bookings,
                "canceled_bookings": canceled_bookings,
                "reschedule_bookings": reschedule_bookings,
            }
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def get_vendor_bookings(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Use current_user.id as vendor_id
            vendor = str(current_user.vendor_id)
            # vendor_obj = await vendor_collection.find_one({"_id": ObjectId(vendor)})

            # vendor_id = vendor_obj["_id"]
            bookings_cursor = (
                booking_collection.find(
                    {
                        "booking_status": "panding",
                        "payment_status": "paid",
                        "vendor_id": ObjectId(current_user.vendor_id),
                    }
                )
                .sort("created_at", DESCENDING)
                .limit(10)
            )
            bookings = await bookings_cursor.to_list(length=10)
            if not bookings:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No bookings found")

            booking_data = []
            for booking in bookings:
                # Fetch related data
                user = await user_collection.find_one({"_id": ObjectId(booking["user_id"])}, {"first_name": 1})
                vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
                vendor_user_name = await user_collection.find_one(
                    {"_id": ObjectId(booking["vendor_user_id"])}, {"first_name": 1}
                )
                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])}, {"name": 1})
                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])}, {"name": 1})

                booking_data.append(
                    {
                        "booking_id": str(booking["_id"]),
                        "user_name": user["first_name"] if user else None,
                        "vendor_name": vendor_user_name["first_name"] if vendor_user_name else None,
                        "category_name": category["name"] if category else None,
                        "service_name": service["name"] if service else None,
                        "booking_status": booking["booking_status"],
                        "booking_confirm": booking["booking_confirm"] if "booking_confirm" in booking else None,
                        "booking_date": booking["booking_date"],
                        "time_slot": booking["time_slot"],
                        "payment_status": booking["payment_status"] if "payment_status" in booking else None,
                        "payment_method": booking["payment_method"] if "payment_method" in booking else None,
                        "amount": booking["amount"],
                        "booking_cancel_reason": (
                            booking["booking_cancel_reason"] if "booking_cancel_reason" in booking else None
                        ),
                        "booking_order_id": booking["booking_order_id"] if "booking_order_id" in booking else None,
                        "payment_id": booking["payment_id"] if "payment_id" in booking else None,
                        "created_at": booking.get("created_at"),  # Include timestamp if needed
                    }
                )

            return {
                "total_bookings": len(booking_data),
                "bookings": booking_data,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_service(
        self,
        current_user: User,
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            service = vendor.get("services")

            return service

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def upgrade_vendor_subscription(
        self, current_user: User, sub_id: str, upgrade_subscription_request: VendorSubscriptionRequest
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            if not vendor.get("razorpay_subscription_id"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active subscription found")

            current_subscription_id = vendor["razorpay_subscription_id"]

            auth_string = f"{RAZOR_PAY_KEY_ID}:{RAZOR_PAY_KEY_SECRET}"
            basic_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Basic {basic_auth}",
            }

            razorpay_api_url = f"https://api.razorpay.com/v1/subscriptions/{current_subscription_id}"
            async with httpx.AsyncClient() as client:
                response = await client.get(razorpay_api_url, headers=headers)
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to fetch Razorpay subscription: {response.text}",
                    )
                current_subscription = response.json()
            current_plan_id = current_subscription.get("plan_id")
            current_plan_url = f"https://api.razorpay.com/v1/plans/{current_plan_id}"
            async with httpx.AsyncClient() as client:
                response = await client.get(current_plan_url, headers=headers)
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to fetch current plan details: {response.text}",
                    )
                current_plan_details = response.json()

            remaining_amount, remaining_days = calculate_remaining_amount(current_subscription, current_plan_details)

            if upgrade_subscription_request.schedule_change_at == "now":
                # For immediate change, we need to cancel the existing subscription and create a new one

                # cancel_url = f"https://api.razorpay.com/v1/subscriptions/{current_subscription_id}/cancel"
                # async with httpx.AsyncClient() as client:
                #     response = await client.post(cancel_url, headers=headers)
                #     if response.status_code != 200:
                #         raise HTTPException(
                #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                #             detail=f"Failed to cancel existing subscription: {response.text}",
                #         )

                create_data = {
                    "plan_id": upgrade_subscription_request.plan_id,
                    "quantity": upgrade_subscription_request.quantity,
                    "total_count": upgrade_subscription_request.total_count,
                    "customer_notify": 1,
                }

                create_url = "https://api.razorpay.com/v1/subscriptions"
                async with httpx.AsyncClient() as client:
                    response = await client.post(create_url, json=create_data, headers=headers)
                    if response.status_code != 200:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to create new Razorpay subscription: {response.text}",
                        )
                    updated_subscription = response.json()

                new_plan_url = f"https://api.razorpay.com/v1/plans/{upgrade_subscription_request.plan_id}"
                async with httpx.AsyncClient() as client:
                    response = await client.get(new_plan_url, headers=headers)
                    if response.status_code != 200:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to fetch new plan details: {response.text}",
                        )
                    new_plan_details = response.json()

                new_plan_amount = int(new_plan_details["item"]["amount"])
                total_amount_paid = new_plan_amount

                if total_amount_paid > remaining_amount:
                    refund_amount = total_amount_paid - remaining_amount
                    order_id = vendor.get("razorpay_order_id")
                    payment_details_url = f"https://api.razorpay.com/v1/orders/{order_id}/payments"

                    async with httpx.AsyncClient() as client:
                        response = await client.get(payment_details_url, headers=headers)
                        if response.status_code != 200:
                            raise HTTPException(
                                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"Failed to fetch payment details: {response.text}",
                            )

                        payment_data = response.json()
                        if payment_data and "items" in payment_data and len(payment_data["items"]) > 0:
                            payment_id = payment_data["items"][0]["id"]
                        else:
                            raise HTTPException(
                                status_code=status.HTTP_404_NOT_FOUND, detail="No payment found for the given order ID"
                            )

                    refund_url = f"https://api.razorpay.com/v1/payments/{payment_id}/refund"
                    refund_data = {"amount": int(refund_amount * 100)}
                    async with httpx.AsyncClient() as client:
                        response = await client.post(refund_url, json=refund_data, headers=headers)
                        if response.status_code != 200:
                            raise HTTPException(
                                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"Failed to process refund: {response.text}",
                            )

                vendor_update_data = {
                    "razorpay_subscription_id": updated_subscription["id"],
                    "manage_plan": upgrade_subscription_request.plan_id,
                    "subscription_quantity": upgrade_subscription_request.quantity,
                    "subscription_updated_at": datetime.now(),
                }

                message = "Subscription updated successfully (immediate change)"

            else:
                update_data = {
                    "plan_id": upgrade_subscription_request.plan_id,
                    "quantity": upgrade_subscription_request.quantity,
                    "remaining_count": upgrade_subscription_request.total_count,
                    "schedule_change_at": "cycle_end",
                    "customer_notify": 1,
                }

                razorpay_api_url = f"https://api.razorpay.com/v1/subscriptions/{current_subscription_id}"
                async with httpx.AsyncClient() as client:
                    response = await client.patch(razorpay_api_url, json=update_data, headers=headers)
                    if response.status_code != 200:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to update Razorpay subscription: {response.text}",
                        )
                    updated_subscription = response.json()

                vendor_update_data = {
                    "manage_plan": upgrade_subscription_request.plan_id,
                    "subscription_quantity": upgrade_subscription_request.quantity,
                    "subscription_updated_at": datetime.now(),
                }

                message = "Subscription updated successfully (effective next billing cycle)"

            result = await vendor_collection.update_one({"_id": vendor["_id"]}, {"$set": vendor_update_data})
            if result.modified_count == 0:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update vendor")

            return {
                "status": "SUCCESS",
                "message": message,
                "data": {
                    "subscription_id": updated_subscription["id"],
                    "effective_from": (
                        "immediately"
                        if upgrade_subscription_request.schedule_change_at == "now"
                        else "next billing cycle"
                    ),
                },
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def create_vendor_query(
        self,
        request: Request,
        vendor_query: VendorQuery,
        background_tasks: BackgroundTasks,
    ):
        try:
            if not vendor_query:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vendor query data")

            # Save ticket to the database
            query = await vendor_query_collection.insert_one(vendor_query.dict())
            if query:
                source = "Vendor Query Created"
                to_email = vendor_query.email
                context = {
                    "query_type": vendor_query.query_type,
                    "description": vendor_query.description,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                }
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)
                source = "New Vendor Query"
                to_email = "support@fast2book.com"
                context = {
                    "email": vendor_query.email,
                    "query_type": vendor_query.query_type,
                    "description": vendor_query.description,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                }
                background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

            vendor_data = vendor_query.dict()
            vendor_data["id"] = str(query.inserted_id)

            return vendor_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def total_booking_count(self, request: Request, current_user: User, year: int):
        try:
            if year < 2000 or year > 2100:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid year")

            start_date = f"{year}-01-01"
            end_date = f"{year + 1}-01-01"
            vendor = await vendor_collection.find_one({"_id": ObjectId(current_user.vendor_id)})
            pipeline = [
                {
                    "$match": {
                        "vendor_id": ObjectId(vendor["_id"]),
                        "payment_status": "paid",
                        "booking_date": {"$gte": start_date, "$lt": end_date},
                    }
                },
                {
                    "$group": {
                        "_id": {"$month": {"$dateFromString": {"dateString": "$booking_date"}}},
                        "booking_count": {"$sum": 1},
                    }
                },
                {"$sort": {"_id": 1}},
            ]

            monthly_counts = await booking_collection.aggregate(pipeline).to_list(None)
            month_data = {month: 0 for month in range(1, 13)}
            for entry in monthly_counts:
                month_data[entry["_id"]] = entry["booking_count"]
            result = [
                {"name": "Jan", "booking": month_data[1]},
                {"name": "Feb", "booking": month_data[2]},
                {"name": "Mar", "booking": month_data[3]},
                {"name": "Apr", "booking": month_data[4]},
                {"name": "May", "booking": month_data[5]},
                {"name": "Jun", "booking": month_data[6]},
                {"name": "Jul", "booking": month_data[7]},
                {"name": "Aug", "booking": month_data[8]},
                {"name": "Sep", "booking": month_data[9]},
                {"name": "Oct", "booking": month_data[10]},
                {"name": "Nov", "booking": month_data[11]},
                {"name": "Dec", "booking": month_data[12]},
            ]
            return result

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def create_booking_for_vendor(
        self,
        request: Request,
        current_user: User,
        user_id: str,
        slot: str,
        booking_date: str,
        service_id: str,
        category_id: str,
        vendor_user_id: Optional[str] = None,
    ):
        try:
            if not user_id or not slot or not booking_date or not service_id or not category_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid booking data")

            # Save ticket to the database
            booking_data = {
                "vendor_id": ObjectId(current_user.vendor_id),
                "service_id": ObjectId(service_id),
                "category_id": ObjectId(category_id),
                "user_id": ObjectId(user_id),
                "vendor_user_id": ObjectId(vendor_user_id) if vendor_user_id else None,
                "booking_date": booking_date,
                "slot": slot,
                "payment_status": "pending",
                "booking_status": "panding",
                "created_at": datetime.now(),
            }
            booking = await booking_collection.insert_one(booking_data)
            if booking:
                booking_data["id"] = str(booking.inserted_id)
            return booking_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def get_user_list_for_vendor(self, current_user: User):
        try:
            query = {"roles": {"$regex": "^user$", "$options": "i"}, "user_role": {"$ne": 2}}

            pipeline = [
                {"$match": query},
                {
                    "$project": {
                        "id": {"$toString": "$_id"},
                        "_id": 0,
                        "first_name": 1,
                        "last_name": 1,
                        "email": 1,
                        "user_role": 1,
                        "roles": 1,
                    }
                },
            ]

            cursor = user_collection.aggregate(pipeline)
            user_list = await cursor.to_list(length=None)

            return user_list

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
