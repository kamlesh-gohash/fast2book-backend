import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import razorpay

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    category_collection,
    services_collection,
    slots_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.slots import *
from app.v1.models.vendor import Vendor
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.utils.email import generate_otp, send_email, send_vendor_email
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


def validate_time_format(time_str: str):
    try:
        datetime.strptime(time_str, "%H:%M")
    except ValueError:
        return False
    return True


RAZOR_PAY_KEY_ID = os.getenv("RAZOR_PAY_KEY_ID")
RAZOR_PAY_KEY_SECRET = os.getenv("RAZOR_PAY_KEY_SECRET")
razorpay_client = razorpay.Client(auth=(RAZOR_PAY_KEY_ID, RAZOR_PAY_KEY_SECRET))


def create_razorpay_subaccount(vendor_data, user_data):
    """
    Creates a Razorpay subaccount for the vendor.
    """

    account_data = {
        "name": vendor_data["business_name"],
        "email": user_data["email"],
        "contact": user_data["phone"],
        "business_type": vendor_data["business_type"],
        "business_category": "services",
        "account_type": "savings",
    }

    try:

        response = razorpay_client.account.create(account_data)
        if response and isinstance(response, dict):
            account_id = response.get("id")
            account_details = razorpay_client.account.fetch(account_id)
        else:
            return {"error": "Failed to create Razorpay subaccount. Response not as expected."}

        return response

    except razorpay.errors.BadRequestError as e:
        raise HTTPException(status_code=400, detail=f"Razorpay Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create Razorpay subaccount: {str(e)}")


class VendorManager:

    async def create_vendor(self, request: Request, token: str, create_vendor_request: SignUpVendorRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            existing_user = await user_collection.find_one(
                {
                    "$or": [
                        {"email": {"$eq": create_vendor_request.email, "$nin": [None, ""]}},
                        {"phone": {"$eq": create_vendor_request.phone, "$nin": [None, ""]}},
                    ]
                }
            )

            if existing_user:
                raise HTTPException(
                    status_code=400, detail="Vendor with this email or phone already exists in the database."
                )

            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)

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

            user_data = {
                "first_name": create_vendor_request.first_name,
                "last_name": create_vendor_request.last_name,
                "email": create_vendor_request.email,
                "phone": create_vendor_request.phone,
                "gender": create_vendor_request.gender,
                "roles": create_vendor_request.roles,
                "password": hashed_password,
                "status": create_vendor_request.status,
                "is_dashboard_created": create_vendor_request.is_dashboard_created,
                # "otp": otp,
                # "otp_expiration_time": otp_expiration_time,
            }

            user_result = await user_collection.insert_one(user_data)
            # image_name = create_vendor_request.vendor_image
            # bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            # print(bucket_name, "bucket_name")
            # file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{image_name}"
            # Prepare Vendor data
            vendor_data = {
                "user_id": str(user_result.inserted_id),
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
                "status": create_vendor_request.status,
                "created_at": datetime.utcnow(),
            }
            if create_vendor_request.business_type.lower() == "individual":
                vendor_data["availability_slots"] = default_availability_slots()
            # razorpay_response = create_razorpay_subaccount(vendor_data, user_data)
            # vendor_data["razorpay_account_id"] = razorpay_response["id"]
            # Insert vendor data into the database
            vendor_result = await vendor_collection.insert_one(vendor_data)

            # Prepare response data
            response_data = {
                "first_name": create_vendor_request.first_name,
                "last_name": create_vendor_request.last_name,
                "email": create_vendor_request.email,
                "phone": create_vendor_request.phone,
                "gender": create_vendor_request.gender,
                "roles": create_vendor_request.roles,
                "password": plain_text_password,
                "status": create_vendor_request.status,
                "id": str(user_result.inserted_id),
                "vendor_data": {
                    "user_id": str(user_result.inserted_id),
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
                    "created_at": vendor_data["created_at"],
                },
            }

            # Send email to the vendor
            login_link = "http://192.168.29.173:3000/vendor-admin/sign-in"
            await send_vendor_email(create_vendor_request.email, plain_text_password, login_link)

            return {"data": response_data}

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_list(
        self, request: Request, token: str, page: int, limit: int, search: str = None, role: str = "vendor"
    ):
        try:
            # Verify current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

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
                vendor["email"] = vendor["email"].lower()

                # Fetch vendor-specific data
                vendor_details = await vendor_collection.find_one({"user_id": vendor_id})
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
                    vendor["created_at"] = vendor_details.get("created_at")

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

            # Response format
            return {
                "data": vendor_data,
                "total_items": total_vendors,
                "total_pages": total_pages,
            }

        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(ex),
            )

    async def get_vendor(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            query = {"_id": ObjectId(id), "roles": {"$in": ["vendor"]}}

            result = await user_collection.find_one(query)

            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            print(result, "result")
            result["id"] = str(result.pop("_id"))
            result["first_name"] = result["first_name"].capitalize()
            result["last_name"] = result["last_name"].capitalize()
            result["email"] = result["email"]
            result["phone"] = result["phone"]
            if result["phone"]:
                result["phone"] = result["phone"]
            else:
                result["phone"] = "Unknown"
            if result["gender"]:
                result["gender"] = result["gender"]
            else:
                result["gender"] = "Unknown"
            result["created_by"] = result.get("created_by", "Unknown")
            vendor_details = await vendor_collection.find_one({"user_id": result["id"]})
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
                result["status"] = vendor_details.get("status", "N/A")
                result["created_at"] = vendor_details.get("created_at")

            result.pop("password", None)

            return result
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_vendor(self, request: Request, token: str, id: str, update_vendor_request: UpdateVendorRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID: '{id}'")

            vendor = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            update_data = {}

            for field in [
                "first_name",
                "last_name",
                "email",
                "phone",
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
                    update_data[field] = value

            if update_vendor_request.category_id is not None:
                category_id = update_vendor_request.category_id
                category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
                if not category_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: {category_id}."
                    )
                update_data["category_id"] = category_id
                update_data["category_name"] = category_data.get("name")

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

                update_data["services"] = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update."
                )

            await user_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            result = await user_collection.find_one({"_id": ObjectId(id)})

            return {
                "id": str(result.pop("_id")),
                "first_name": result.get("first_name"),
                "last_name": result.get("last_name"),
                "email": result.get("email"),
                "phone": result.get("phone"),
                "business_type": result.get("business_type"),
                "business_details": result.get("business_details"),
                "business_address": result.get("business_address"),
                "business_name": result.get("business_name"),
                "category_id": result.get("category_id"),
                "category_name": result.get("category_name"),
                "services": result.get("services"),
                "manage_plan": result.get("manage_plan"),
                "manage_fee_and_gst": result.get("manage_fee_and_gst"),
                "manage_offer": result.get("manage_offer"),
                "status": result.get("status"),
            }

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def delete_vendor(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_service_by_category(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            allowed_roles = ["admin", "vendor"]
            user_roles = [role.value for role in current_user.roles]

            if not any(role in allowed_roles for role in user_roles) and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            services = await services_collection.find({"category_id": ObjectId(id), "status": "active"}).to_list(None)

            if not services:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No services found for this category")

            formatted_services = [
                {"id": str(service["_id"]), "name": service["name"], "status": service["status"]}
                for service in services
            ]

            return {"services": formatted_services}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_sign_in(self, vendor_request: SignInVendorRequest):
        try:
            vendor = await user_collection.find_one({"email": vendor_request.email})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            if "roles" not in vendor or "vendor" not in vendor["roles"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a vendor")
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
            vendor_data = await vendor_collection.find_one({"user_id": str(vendor["_id"])})
            if not vendor_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor details not found")

            access_token = create_access_token(data={"sub": vendor["email"]})
            refresh_token = create_refresh_token(data={"sub": vendor["email"]})
            vendor_response = {key: str(value) if key == "_id" else value for key, value in vendor.items()}
            vendor_response["id"] = vendor_response.pop("_id")
            vendor_response.pop("password", None)
            vendor_response.pop("otp", None)
            vendor_response["access_token"] = access_token
            vendor_response["refresh_token"] = refresh_token
            vendor_response["vendor_details"] = {
                "business_name": vendor_data.get("business_name"),
                "business_type": vendor_data.get("business_type"),
                "business_address": vendor_data.get("business_address"),
                "category_id": vendor_data.get("category_id"),
                "category_name": vendor_data.get("category_name"),
                "services": vendor_data.get("services"),
                "service_details": vendor_data.get("service_details"),
                "manage_plan": vendor_data.get("manage_plan"),
                "manage_fee_and_gst": vendor_data.get("manage_fee_and_gst"),
                "manage_offer": vendor_data.get("manage_offer"),
                "status": vendor_data.get("status"),
                "availability_slots": vendor_data.get("availability_slots"),
            }

            return vendor_response

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_sign_up(self, vendor_request: SignUpVendorRequest):
        try:
            existing_vendor = await user_collection.find_one({"email": vendor_request.email})
            if existing_vendor:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Vendor already exists")

            hashed_password = bcrypt.hashpw(vendor_request.password.encode("utf-8"), bcrypt.gensalt())
            vendor_request.is_dashboard_created = True
            otp = generate_otp()
            new_vendor_user = {
                "first_name": vendor_request.first_name,
                "last_name": vendor_request.last_name,
                "email": vendor_request.email,
                "otp": otp,
                "roles": vendor_request.roles,
                "password": hashed_password,
                "is_dashboard_created": vendor_request.is_dashboard_created,
            }
            result = await user_collection.insert_one(new_vendor_user)

            user_id = str(result.inserted_id)

            vendor_data = {
                "user_id": user_id,
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
                "created_at": datetime.utcnow(),
            }
            if vendor_request.business_type.lower() == "individual":
                vendor_data["availability_slots"] = default_availability_slots()

            vendor_result = await vendor_collection.insert_one(vendor_data)

            new_vendor_user["id"] = user_id
            new_vendor_user.pop("_id", None)
            new_vendor_user.pop("password", None)
            new_vendor_user.pop("otp", None)
            new_vendor_user["vendor_details"] = {
                "id": str(vendor_result.inserted_id),
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
            }
            await send_email(to_email=vendor_request.email, otp=otp)

            return new_vendor_user
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_profile(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            query = {"_id": ObjectId(current_user.id)}
            vendor = await user_collection.find_one(query)
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            user_id = ObjectId(vendor["_id"])
            vendor_data = await vendor_collection.find_one({"user_id": str(user_id)})
            # Format the vendor to include only the necessary fields (id and name)
            vendor["id"] = str(vendor.pop("_id"))
            vendor.pop("password", None)
            vendor.pop("otp", None)
            vendor["first_name"] = vendor["first_name"].capitalize()
            vendor["last_name"] = vendor["last_name"].capitalize()
            vendor["email"] = vendor["email"]
            vendor["created_by"] = vendor.get("created_by", "Unknown")
            if vendor_data:
                vendor_data["id"] = str(vendor_data.pop("_id"))
                vendor.update(vendor_data)

            return vendor
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_profile(self, request: Request, token: str, update_vendor_request: UpdateVendorRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Update user profile in user_collection
            user_query = {"_id": ObjectId(current_user.id)}
            user_data = {}

            if update_vendor_request.first_name is not None:
                user_data["first_name"] = update_vendor_request.first_name
            if update_vendor_request.last_name is not None:
                user_data["last_name"] = update_vendor_request.last_name
            if update_vendor_request.email is not None:
                user_data["email"] = update_vendor_request.email
            if update_vendor_request.phone is not None:
                user_data["phone"] = update_vendor_request.phone

            # If there are updates to user data, update user_collection
            if user_data:
                await user_collection.update_one(user_query, {"$set": user_data})

            # Check if the user exists in the user collection
            updated_user = await user_collection.find_one(user_query)
            if not updated_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # Update vendor-specific details in vendor_collection
            vendor_query = {"user_id": str(current_user.id)}  # Assuming vendor_collection has user_id as foreign key
            vendor_data = {}

            if update_vendor_request.business_type is not None:
                vendor_data["business_type"] = update_vendor_request.business_type
            if update_vendor_request.business_address is not None:
                vendor_data["business_address"] = update_vendor_request.business_address
            if update_vendor_request.business_name is not None:
                vendor_data["business_name"] = update_vendor_request.business_name
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
                vendor_data["services"] = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

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

            # If there are updates to vendor data, update vendor_collection
            if vendor_data:
                await vendor_collection.update_one(vendor_query, {"$set": vendor_data})

            # Check if the vendor exists in the vendor collection
            updated_vendor = await vendor_collection.find_one(vendor_query)
            if not updated_vendor:

                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare the response data
            response_data = {
                "user_id": str(updated_user["_id"]),
                "first_name": updated_user.get("first_name"),
                "last_name": updated_user.get("last_name"),
                "email": updated_user.get("email"),
                "phone": updated_user.get("phone"),
                "vendor_details": {
                    "business_details": updated_vendor.get("business_details"),
                    "business_name": updated_vendor.get("business_name"),
                    "business_type": updated_vendor.get("business_type"),
                    "business_address": updated_vendor.get("business_address"),
                    "category_id": updated_vendor.get("category_id"),
                    "category_name": updated_vendor.get("category_name"),
                    "services": updated_vendor.get("services"),
                    "service_details": updated_vendor.get("service_details"),
                    "manage_plan": updated_vendor.get("manage_plan"),
                    "manage_fee_and_gst": updated_vendor.get("manage_fee_and_gst"),
                    "manage_offer": updated_vendor.get("manage_offer"),
                    "availability_slots": updated_vendor.get("availability_slots"),
                    "status": updated_vendor.get("status"),
                },
            }

            return response_data

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def create_vendor_user(
        self, request: Request, token: str, vendor_user_create_request: VendorUserCreateRequest
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
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

            new_vendor_user = {
                "first_name": vendor_user_create_request.first_name,
                "last_name": vendor_user_create_request.last_name,
                "email": vendor_user_create_request.email,
                "fees": vendor_user_create_request.fees,
                "gander": vendor_user_create_request.gander,
                "phone": vendor_user_create_request.phone,
                "roles": vendor_user_create_request.roles,
                "status": vendor_user_create_request.status,
                "created_by": str(current_user.id),
                "category": vendor_user_create_request.category,
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

            result = await user_collection.insert_one(new_vendor_user)
            new_vendor_user["id"] = str(result.inserted_id)
            new_vendor_user.pop("_id", None)

            return new_vendor_user

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_users_list(self, request: Request, token: str):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the current user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Query to filter users with the "vendor_user" role and created by the current user
            query = {
                "roles": {"$in": ["vendor_user"]},
                "created_by": str(current_user.id),  # Match created_by with the current user's ID
            }

            # Find users matching the query
            vendor_users = await user_collection.find(query).to_list(None)
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")
            formatted_users = []
            for user in vendor_users:
                user["id"] = str(user.pop("_id", ""))
                formatted_users.append(user)
            return {"data": formatted_users}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def set_individual_vendor_availability(self, request: Request, token: str, slots: List[DaySlot]):
        try:
            # Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Get the vendor's current data
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare the new availability slots
            new_availability_slots = []
            for day_slot in slots:
                day_slot_data = day_slot.dict()
                for time_slot in day_slot_data.get("time_slots", []):
                    # Format start_time and end_time
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

                    # Calculate duration
                    ts = TimeSlot(**time_slot)
                    ts.calculate_duration()
                    time_slot["duration"] = ts.duration

                new_availability_slots.append(day_slot_data)

            # Replace old availability slots with new ones
            await vendor_collection.update_one(
                {"_id": vendor["_id"]}, {"$set": {"availability_slots": new_availability_slots}}
            )

            # Return updated data
            updated_vendor = await vendor_collection.find_one({"_id": vendor["_id"]})
            if updated_vendor:
                updated_vendor = serialize_mongo_document(updated_vendor)

            return updated_vendor

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_availability(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            availability_slots = vendor.get("availability_slots", [])
            return availability_slots
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_vendor_availability(self, request: Request, token: str, slots: List[DaySlot]):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def delete_vendor_availability(
        self, request: Request, token: str, day: str, start_time: Optional[str] = None
    ):
        """
        Delete vendor availability for a specific day or time slot.

        Args:
                request (Request): The HTTP request object.
                token (str): The authentication token for the current user.
                day (str): The day to delete availability for.
                start_time (Optional[str]): The specific start time of the slot to delete.

        Returns:
                dict: Updated vendor availability slots.
        """
        try:
            # Authenticate the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Ensure the user is a vendor
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Find the vendor associated with the user
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Fetch current availability slots
            availability_slots = vendor.get("availability_slots", [])
            if not availability_slots:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No availability slots found")

            # Filter availability slots
            updated_slots = []
            for slot in availability_slots:
                if slot["day"] == day:
                    if start_time:
                        if "time_slots" in slot:
                            slot["time_slots"] = [ts for ts in slot["time_slots"] if ts["start_time"] != start_time]
                            if not slot["time_slots"]:
                                continue
                    else:
                        continue
                updated_slots.append(slot)
            await vendor_collection.update_one({"_id": vendor["_id"]}, {"$set": {"availability_slots": updated_slots}})

            updated_vendor = await vendor_collection.find_one({"_id": vendor["_id"]})
            if updated_vendor:
                updated_vendor = serialize_mongo_document(updated_vendor)
                updated_vendor["id"] = str(updated_vendor.pop("_id"))

            return updated_vendor

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def add_slot_time_vendor(self, request: Request, token: str, id: str, slots: List[DaySlot]):
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
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

    async def create_vendor_slots(self, request: Request, token: str, vendor_id: str, slots: List[DaySlot]):
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
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            vendor = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor:
                user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
                if not user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
                vendor = await vendor_collection.find_one({"user_id": user["created_by"]})
                if not vendor:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
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
                {"_id": ObjectId(vendor_id)}, {"$set": {"availability_slots": new_availability_slots}}
            )
            updated_user = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if updated_user:
                updated_user = serialize_mongo_document(updated_user)
            updated_user["id"] = str(updated_user.pop("_id"))
            return updated_user

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_slots(self, request: Request, token: str, vendor_id: str):
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
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            vendor = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor:
                user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
                if not user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
                vendor = await vendor_collection.find_one({"user_id": user["created_by"]})
                if not vendor:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            business_type = vendor.get("business_type", "individual")
            if business_type == "individual":
                availability_slots = vendor.get("availability_slots", [])
                return {
                    "vendor_id": vendor["user_id"],
                    "vendor_name": vendor.get("business_name", "N/A"),
                    "business_type": business_type,
                    "availability_slots": availability_slots,
                }

            user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            parent_vendor = await vendor_collection.find_one({"user_id": user["created_by"]})
            if not parent_vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent vendor not found")

            user_slots = user.get("availability_slots", [])

            response = {
                "vendor_id": parent_vendor["user_id"],
                "vendor_name": parent_vendor.get("business_name", "N/A"),
                "vendor_user_id": str(user["_id"]),
                "vendor_user_name": f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                "business_type": business_type,
                "availability_slots": user_slots,
            }
            return response

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_list_for_slot(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Ensure the user is a super admin
            if current_user.user_role != 2:  # Assuming role `2` is for super admin
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

                # Fetch vendor-specific data in parallel using asyncio.gather
                vendor_details = await vendor_collection.find_one({"user_id": vendor_id})
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

                # Remove sensitive information
                vendor.pop("password", None)
                vendor.pop("otp", None)

                vendor_data.append(vendor)

            return {
                "data": vendor_data,
            }

        except Exception as ex:
            # Log the error for debugging and re-raise with a 500 status
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def vendor_user_list_for_slot(self, request: Request, token: str, vendor_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            if not ObjectId.is_valid(vendor_id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID")
            vendor_details = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor_details:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            if vendor_details.get("business_type") != "business":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor's business type is not 'business'"
                )
            users = await user_collection.find({"created_by": vendor_id}).to_list(None)
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
        self, request: Request, token: str, id: str, vendor_user_request: VendorUserUpdateRequest, role: str = "vendor"
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
            update_data = {key: value for key, value in vendor_user_request.dict().items() if value is not None}
            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            result = await user_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})
            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="No changes were made to the vendor user"
                )
            updated_user = await user_collection.find_one({"_id": ObjectId(id)})
            if updated_user:
                updated_user["id"] = str(updated_user.pop("_id"))
            return {"data": updated_user}

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def delete_vendor_user_by_id(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

    async def get_vendor_user_by_id(self, request: Request, token: str, id: str, role: str = "vendor"):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
                    status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to view this user"
                )
            vendor_user["id"] = str(vendor_user.pop("_id"))
            return vendor_user

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )
