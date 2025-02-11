import base64
import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import razorpay
import requests

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from dateutil.relativedelta import relativedelta

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    category_collection,
    payment_collection,
    plan_collection,
    services_collection,
    slots_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.slots import *
from app.v1.models.vendor import Vendor
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
            if create_vendor_request.business_type.lower() == "individual":
                user_data["availability_slots"] = default_availability_slots()
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
                "fees": create_vendor_request.fees,
                "status": create_vendor_request.status,
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
            # razorpay_api_url = "https://api.razorpay.com/v1/contacts"
            # api_key = "rzp_test_wQ89Kb3cFIAsHE"  # Replace with your Razorpay API key
            # api_secret = "ycpwHlxyJPUYv8w2BZwIL4XF"  # Replace with your Razorpay API secret
            # auth_string = f"{api_key}:{api_secret}"
            # auth_bytes = auth_string.encode("ascii")
            # base64_auth = base64.b64encode(auth_bytes).decode("ascii")

            # headers = {
            #     "Content-Type": "application/json",
            #     "Authorization": f"Basic {base64_auth}"
            # }

            # contact_data = {
            #     "name": create_vendor_request.first_name,
            #     "email": create_vendor_request.email,
            #     "contact": create_vendor_request.phone,
            #     "type": "vendor",
            #     "reference_id": str(vendor_result.inserted_id),
            #     "notes": {
            #         "vendor_id": str(vendor_result.inserted_id)
            #     }
            # }

            # response = requests.post(razorpay_api_url, json=contact_data, headers=headers)
            # print(response, 'response')
            # if response.status_code != 201:
            #     print(response.json(), 'response')
            #     raise HTTPException(status_code=response.status_code, detail=response.json())

            # contact = response.json()
            # print(contact, 'contact')

            # # Create a fund account using Razorpay Payouts API
            # fund_account_url = "https://api.razorpay.com/v1/fund_accounts"
            # fund_account_data = {
            #     "contact_id": contact["id"],

            #     "account_type": "bank_account",
            #     "bank_account": {
            #         "name": "Gaurav Kumar",
            #         "ifsc": create_vendor_request.ifsc,
            #         "account_number": create_vendor_request.bank_account_number
            #     }
            # }

            # response = requests.post(fund_account_url, json=fund_account_data, headers=headers)
            # if response.status_code != 201:
            #     raise HTTPException(status_code=response.status_code, detail=response.json())

            # fund_account = response.json()
            # print(fund_account, 'fund_account')
            #     sub_account = razorpay_client.account.create({
            #     "email": create_vendor_request.email,
            #     "phone": create_vendor_request.phone,
            #     "legal_business_name":create_vendor_request.business_name,
            #     "business_type":"partnership",
            #     "profile": {
            #     "category": "healthcare",
            #     "subcategory": "clinic",
            #     "addresses": {
            #         "operation": {
            #             "street1": "507, Koramangala 6th block",
            #             "street2": "Kormanagala",
            #             "city": "Bengaluru",
            #             "state": "Karnataka",
            #             "postal_code": 560047,
            #             "country": "IN"
            #         },
            #         "registered": {
            #             "street1": "507, Koramangala 1st block",
            #             "street2": "MG Road",
            #             "city": "Bengaluru",
            #             "state": "Karnataka",
            #             "postal_code": 560034,
            #             "country": "IN"
            #         }
            #         },
            #     },
            #     "type": "route",  # Required for routing payments
            #     "contact_name":create_vendor_request.first_name,

            # })
            #     print(sub_account, "sub_account")
            #     vendor_data["razorpay_account_id"] = sub_account["id"]
            #     await vendor_collection.update_one(
            #         {"_id": vendor_result.inserted_id},
            #         {"$set": {"razorpay_account_id": sub_account["id"]}},
            #     )
            #     stakeholder = razorpay_client.stakeholder.create(sub_account["id"], {
            #         "name": create_vendor_request.first_name + " " + create_vendor_request.last_name,
            #         "email": create_vendor_request.email,
            #         "phone": {
            #         "primary": create_vendor_request.phone,
            #         "secondary": "9000090000"
            #     },
            #         "relationship": {
            #             "director": True,
            #             "executive": True
            #         },
            #         "notes": {
            #             "role": "Vendor"
            #         }
            #     })

            #     print(stakeholder, "stakeholder")

            # Add bank account details for the sub-account
            # bank_account = razorpay_client.bank_account.create(sub_account["id"], {
            #     "account_number": create_vendor_request.bank_account_number,  # Pass bank account number from request
            #     "ifsc_code": create_vendor_request.ifsc,  # Pass IFSC code from request
            #     "name": create_vendor_request.first_name,  # Pass account holder name from request
            #     "account_type": create_vendor_request.account_type,  # Can be "bank_account" or "current"
            # })
            # razorpay_api_url = f"https://api.razorpay.com/v1/accounts/{sub_account['id']}/stakeholders/{stakeholder['id']}/bank_accounts"
            # print(razorpay_api_url, "razorpay_api_url")

            # # Encode API key and secret for Basic Auth
            # api_key = os.getenv("RAZOR_PAY_KEY_ID")  # Replace with your Razorpay API key
            # api_secret = os.getenv("RAZOR_PAY_KEY_SECRET")  # Replace with your Razorpay API secret
            # auth_string = f"{api_key}:{api_secret}"
            # auth_bytes = auth_string.encode("ascii")
            # base64_auth = base64.b64encode(auth_bytes).decode("ascii")

            # headers = {
            #     "Content-Type": "application/json",
            #     "Authorization": f"Basic {base64_auth}"  # Use your Razorpay API key and secret
            # }
            # print(headers, 'headers')

            # bank_account_data = {
            #     "account_number": create_vendor_request.bank_account_number,  # Pass bank account number from request
            #     "ifsc_code": create_vendor_request.ifsc,  # Pass IFSC code from request
            #     "name": create_vendor_request.first_name,  # Pass account holder name from request
            #     "account_type": create_vendor_request.account_type,  # Can be "bank_account" or "current"
            # }
            # print(bank_account_data, 'bank_account_data')

            # response = requests.post(razorpay_api_url, json=bank_account_data, headers=headers)
            # print(response, 'response')
            # if response.status_code != 201:
            #     print(response.json())
            #     raise HTTPException(status_code=response.status_code, detail=response.json())

            # bank_account = response.json()
            # print(bank_account, "bank_account")

            #     razorpay_api_url = f"https://api.razorpay.com/v1/accounts/{sub_account['id']}/bank_account"

            #     # Get API credentials
            #     api_key = os.getenv("RAZOR_PAY_KEY_ID")
            #     api_secret = os.getenv("RAZOR_PAY_KEY_SECRET")

            #     # Create Basic Auth header
            #     auth_string = f"{api_key}:{api_secret}"
            #     auth_bytes = auth_string.encode("ascii")
            #     base64_auth = base64.b64encode(auth_bytes).decode("ascii")

            #     headers = {
            #         "Content-Type": "application/json",
            #         "Authorization": f"Basic {base64_auth}"
            #     }

            #     bank_account_data = {
            #         "account_number": create_vendor_request.bank_account_number,
            #         "ifsc_code": create_vendor_request.ifsc,  # Note: changed from 'ifsc' to 'ifsc_code'
            #         "name": create_vendor_request.first_name,
            #         "account_type": create_vendor_request.account_type.lower(),
            #     }

            #     print("Bank Account Request Data:", bank_account_data)  # Debug print
            #     print("Request URL:", razorpay_api_url)  # Debug print

            #     response = requests.post(razorpay_api_url, json=bank_account_data, headers=headers)

            #     if response.status_code not in [200, 201]:
            #         print(f"Bank account creation failed: {response.text}")
            #         raise HTTPException(
            #             status_code=status.HTTP_400_BAD_REQUEST,
            #             detail=f"Failed to create bank account: {response.text}"
            #         )

            #     bank_account = response.json()
            #     print("Bank Account Response:", bank_account)

            #     print(bank_account, "bank_account")
            #     route = razorpay_client.route.create({
            #     "account_id": sub_account["id"],
            #     "bank_account_id": bank_account["id"],  # Link the bank account to the route
            #     "payments": {
            #         "criteria": [
            #             {
            #                 "payment_method": "all",
            #                 "settlement_type": "instant",
            #                 "split": {
            #                     "unit": "percent",
            #                     "value": 100 - float(create_vendor_request.fees)
            #                 }
            #             }
            #         ]
            #     },
            #     "settlements": {
            #         "auto": True,
            #         "bank_account_id": bank_account["id"]
            #     }
            # })
            #     print(route, "route")
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
                    "fees": create_vendor_request.fees,
                    # "razorpay_account_id": sub_account["id"],
                    "created_at": vendor_data["created_at"],
                    "location": (
                        create_vendor_request.location.dict() if create_vendor_request.location else None
                    ),  # Add location
                    "specialization": create_vendor_request.specialization,  # Add specialization
                },
            }

            # Send email to the vendor
            login_link = "http://192.168.29.173:3000/vendor-admin/sign-in"
            source = "Vednor Create"
            context = {
                "password": plain_text_password,
                "login_link": login_link,
            }
            to_email = create_vendor_request.email
            await send_vendor_email(to_email, source, context)

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
                    vendor["location"] = vendor_details.get("location")
                    vendor["specialization"] = vendor_details.get("specialization")
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
                result["fees"] = vendor_details.get("fees", [])
                result["manage_plan"] = vendor_details.get("manage_plan", False)
                result["manage_fee_and_gst"] = vendor_details.get("manage_fee_and_gst", False)
                result["manage_offer"] = vendor_details.get("manage_offer", False)
                result["is_payment_verified"] = vendor_details.get("is_payment_verified", False)
                result["status"] = vendor_details.get("status", "N/A")
                # if not result.get("location"):
                result["location"] = vendor_details.get("location")
                result["specialization"] = vendor_details.get("specialization")
                result["created_at"] = vendor_details.get("created_at")

            result.pop("password", None)

            return result
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_vendor(self, request: Request, token: str, id: str, update_vendor_request: UpdateVendorRequest):
        try:
            # Authenticate and authorize the user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Validate the vendor ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID: '{id}'")

            # Fetch the vendor from the user collection
            vendor = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare update data for user collection
            user_update_data = {}
            for field in ["first_name", "last_name", "email", "phone", "gender"]:
                value = getattr(update_vendor_request, field, None)
                if value is not None:
                    user_update_data[field] = value

            # Prepare update data for vendor collection
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

            # Handle category update
            if update_vendor_request.category_id is not None:
                category_id = update_vendor_request.category_id
                category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
                if not category_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: {category_id}."
                    )
                vendor_update_data["category_id"] = category_id
                vendor_update_data["category_name"] = category_data.get("name")

            # Handle fees update
            if update_vendor_request.fees is not None:
                vendor_update_data["fees"] = update_vendor_request.fees

            # Handle services update
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

                vendor_update_data["services"] = [
                    {
                        "id": str(service["_id"]),
                        "name": service["name"],
                        "service_image": service["service_image"],
                        "service_image_url": service["service_image_url"],
                    }
                    for service in valid_services
                ]

            # Handle specialization update
            if update_vendor_request.specialization is not None:
                vendor_update_data["specialization"] = update_vendor_request.specialization

            # Handle location update
            if update_vendor_request.location is not None:
                vendor_update_data["location"] = update_vendor_request.location.dict()

            # Check if there are any updates to perform
            if not user_update_data and not vendor_update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update."
                )

            # Update user collection with user details
            if user_update_data:
                await user_collection.update_one({"_id": ObjectId(id)}, {"$set": user_update_data})

            # Update vendor collection with business details
            if vendor_update_data:
                # Use the `user_id` to find and update the existing vendor document
                await vendor_collection.update_one(
                    {"user_id": id},  # Use `user_id` to find the correct document
                    {"$set": vendor_update_data},
                    upsert=True,  # Create a new document if it doesn't exist
                )

            # Fetch updated vendor details
            updated_vendor = await vendor_collection.find_one({"user_id": id})
            updated_user = await user_collection.find_one({"_id": ObjectId(id)})

            # Return the combined response
            return {
                "id": str(updated_user.pop("_id")),
                "first_name": updated_user.get("first_name"),
                "last_name": updated_user.get("last_name"),
                "email": updated_user.get("email"),
                "phone": updated_user.get("phone"),
                "gender": updated_user.get("gender"),
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
                "specialization": updated_vendor.get("specialization"),
                "fees": updated_vendor.get("fees"),
                "status": updated_vendor.get("status"),
            }

        except Exception as ex:
            print(ex, "ex")
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
            # Search user by email or phone
            query = {"$or": [{"email": vendor_request.email}, {"phone": vendor_request.phone}]}
            vendor = await user_collection.find_one(query)

            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            if "roles" not in vendor or "vendor" not in vendor["roles"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a vendor")

            if vendor_request.is_login_with_otp:
                otp = generate_otp()
                otp_expires = datetime.utcnow() + timedelta(minutes=10)
                await user_collection.update_one(
                    {"_id": vendor["_id"]}, {"$set": {"otp": otp, "otp_expires": otp_expires}}
                )

                if vendor.get("email"):
                    # Send OTP to email
                    source = "Login with OTP"
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

            vendor_data = await vendor_collection.find_one({"user_id": str(vendor["_id"])})
            if not vendor_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor details not found")

            subscription = vendor_data.get("is_subscription")
            access_token = create_access_token(data={"sub": vendor["email"] or vendor["phone"]})
            refresh_token = create_refresh_token(data={"sub": vendor["email"] or vendor["phone"]})

            vendor_response = {key: str(value) if key == "_id" else value for key, value in vendor.items()}
            vendor_response["id"] = vendor_response.pop("_id")
            vendor_response.pop("password", None)
            vendor_response.pop("otp", None)
            vendor_response["is_subscription"] = subscription
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

    # async def vendor_sign_up(self, vendor_request: SignUpVendorRequest):
    #     try:
    #         existing_vendor = await user_collection.find_one({"email": vendor_request.email})
    #         if existing_vendor:
    #             raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Vendor already exists")

    #         hashed_password = bcrypt.hashpw(vendor_request.password.encode("utf-8"), bcrypt.gensalt())
    #         vendor_request.is_dashboard_created = True
    #         otp = generate_otp()

    #         new_vendor_user = {
    #             "first_name": vendor_request.first_name,
    #             "last_name": vendor_request.last_name,
    #             "email": vendor_request.email,
    #             "otp": otp,
    #             "otp_expires": datetime.utcnow() + timedelta(minutes=10),
    #             "roles": vendor_request.roles,
    #             "password": hashed_password,
    #             "is_dashboard_created": vendor_request.is_dashboard_created,
    #         }
    #         if vendor_request.business_type.lower() == "individual":
    #             new_vendor_user["availability_slots"] = default_availability_slots()
    #         result = await user_collection.insert_one(new_vendor_user)

    #         user_id = str(result.inserted_id)

    #         vendor_data = {
    #             "user_id": user_id,
    #             "business_name": vendor_request.business_name,
    #             "business_type": vendor_request.business_type,
    #             "status": vendor_request.status,
    #             "is_subscription": False,
    #             "created_at": datetime.utcnow(),
    #         }

    #         vendor_result = await vendor_collection.insert_one(vendor_data)

    #         new_vendor_user["id"] = user_id
    #         new_vendor_user.pop("_id", None)
    #         new_vendor_user.pop("password", None)
    #         new_vendor_user.pop("otp", None)
    #         new_vendor_user["vendor_details"] = {
    #             "id": str(vendor_result.inserted_id),
    #             "business_name": vendor_request.business_name,
    #             "business_type": vendor_request.business_type,
    #             "status": vendor_request.status,
    #         }
    #         source = "Activation_code"
    #         context = {"otp": otp}
    #         to_email = vendor_request.email
    #         await send_email(to_email, source, context)

    #         return new_vendor_user
    #     except Exception as ex:
    #         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
    async def vendor_sign_up(self, vendor_request: SignUpVendorRequest):
        try:
            existing_vendor = None

            # Check if user exists based on email or phone
            if vendor_request.email:
                existing_vendor = await user_collection.find_one({"email": vendor_request.email})
            elif vendor_request.phone:
                existing_vendor = await user_collection.find_one({"phone": vendor_request.phone})

            if existing_vendor:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Vendor already exists")

            hashed_password = bcrypt.hashpw(vendor_request.password.encode("utf-8"), bcrypt.gensalt())
            vendor_request.is_dashboard_created = True
            otp = generate_otp()

            new_vendor_user = {
                "first_name": vendor_request.first_name,
                "last_name": vendor_request.last_name,
                "email": vendor_request.email,  # May be None
                "phone": vendor_request.phone,  # May be None
                "otp": otp,
                "otp_expires": datetime.utcnow() + timedelta(minutes=10),
                "roles": vendor_request.roles,
                "password": hashed_password,
                "is_dashboard_created": vendor_request.is_dashboard_created,
            }

            if vendor_request.business_type.lower() == "individual":
                new_vendor_user["availability_slots"] = default_availability_slots()

            result = await user_collection.insert_one(new_vendor_user)
            user_id = str(result.inserted_id)

            vendor_data = {
                "user_id": user_id,
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
                "is_subscription": False,
                "created_at": datetime.utcnow(),
            }

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

            # Send OTP based on whether user signed up with email or phone
            if vendor_request.email:
                source = "Activation_code"
                context = {"otp": otp}
                to_email = vendor_request.email
                await send_email(to_email, source, context)
            elif vendor_request.phone:
                to_phone = vendor_request.phone
                expiry_minutes = 10
                await send_sms_on_phone(to_phone, otp, expiry_minutes)  # Implement send_sms function

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
            if vendor["phone"]:
                vendor["phone"] = vendor["phone"] or ""
            if vendor["email"]:
                vendor["email"] = vendor["email"] or ""

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
            customer_id = updated_vendor.get("razorpay_customer_id")
            if not customer_id:
                customer_data = {
                    "name": current_user.first_name + " " + current_user.last_name,
                    "email": current_user.email,
                    "contact": current_user.phone,  # Assuming phone is available
                }
                razorpay_customer = razorpay_client.customer.create(data=customer_data)
                customer_id = razorpay_customer["id"]
                await vendor_collection.update_one(vendor_query, {"$set": {"razorpay_customer_id": customer_id}})

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

    async def vendor_users_list(
        self,
        request: Request,
        token: str,
        page: int,
        limit: int,
        search: str = None,
    ):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the current user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Query to filter users with the "vendor_user" role and created by the current user
            skip = max((page - 1) * limit, 0)
            query = {
                "roles": {"$in": ["vendor_user"]},
                "created_by": str(current_user.id),  # Match created_by with the current user's ID
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

            # Find users matching the query
            vendor_users = await user_collection.find(query).skip(skip).limit(limit).to_list(length=limit)
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")
            formatted_users = []
            for user in vendor_users:
                user["id"] = str(user.pop("_id", ""))
                formatted_users.append(user)
            total_users = await user_collection.count_documents(query)
            total_pages = (total_users + limit - 1) // limit
            return {"data": formatted_users, "total_items": total_users, "total_pages": total_pages}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def set_individual_vendor_availability(
        self, request: Request, token: str, slots: List[DaySlot], vendor_user_id: Optional[str] = None
    ):
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
            if vendor_user_id:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
                if vendor_user["created_by"] != str(current_user.id):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
                    {"_id": ObjectId(vendor_user_id)}, {"$set": {"availability_slots": new_availability_slots}}
                )

                # Return updated data
                updated_vendor = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not updated_vendor:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
                updated_vendor["id"] = str(updated_vendor.pop("_id", ""))

                return updated_vendor

            # Prepare the new availability slots
            new_availability_slots = []
            # for day_slot in slots:
            #     day_slot_data = day_slot.dict()
            # for time_slot in day_slot_data.get("time_slots", []):
            #     # Format start_time and end_time
            #     time_slot["start_time"] = (
            #         time_slot["start_time"].strftime("%H:%M")
            #         if isinstance(time_slot["start_time"], time)
            #         else time_slot["start_time"]
            #     )
            #     time_slot["end_time"] = (
            #         time_slot["end_time"].strftime("%H:%M")
            #         if isinstance(time_slot["end_time"], time)
            #         else time_slot["end_time"]
            #     )

            # Calculate duration
            # ts = TimeSlot(**time_slot)
            # ts.calculate_duration()
            # time_slot["duration"] = ts.duration
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
                {"_id": ObjectId(vendor["user_id"])}, {"$set": {"availability_slots": new_availability_slots}}
            )

            # Return updated data

            updated_vendor = await user_collection.find_one({"_id": ObjectId(vendor["user_id"])})
            if not updated_vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            updated_vendor["id"] = str(updated_vendor.pop("_id", ""))

            return updated_vendor

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_vendor_availability(self, request: Request, token: str, vendor_user_id: str = None):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            if vendor_user_id:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
                availability_slots = vendor_user.get("availability_slots", [])
                return availability_slots
            vendor = await vendor_collection.find_one({"user_id": str(current_user.id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor_user = await user_collection.find_one({"_id": ObjectId(vendor["user_id"])})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            availability_slots = vendor_user.get("availability_slots", [])
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

            user_data = await user_collection.find_one({"_id": ObjectId(vendor_id)})
            if not user_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            vendor = await vendor_collection.find_one({"user_id": vendor_id})
            if not vendor:
                user = await user_collection.find_one({"_id": ObjectId(vendor_id), "roles": "vendor_user"})
                if not user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

                # Get the parent vendor
                vendor = await vendor_collection.find_one({"user_id": user["created_by"]})
                if not vendor:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent vendor not found")

            availability_slots = user_data.get("availability_slots", [])
            business_type = vendor.get("business_type", "individual")
            if business_type == "individual":
                availability_slots = user_data.get("availability_slots", [])
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

    async def vendor_subscription_plan(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

    async def create_vendor_subscription(
        self, request: Request, token: str, vendor_subscription_request: VendorSubscriptionRequest
    ):
        try:
            # Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            current_user_id = str(current_user.id)
            vendor = await vendor_collection.find_one({"user_id": current_user_id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            plan_details = razorpay_client.plan.fetch(vendor_subscription_request.plan_id)
            interval_count = plan_details.get("interval", 1)
            period = plan_details.get("period", "monthly")
            period_to_relativedelta = {
                "daily": "days",
                "weekly": "weeks",
                "monthly": "months",
                "yearly": "years",
            }
            if period not in period_to_relativedelta:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported interval type: {period}"
                )

            start_at = datetime.now()
            relativedelta_key = period_to_relativedelta[period]
            expire_at = start_at + relativedelta(
                **{relativedelta_key: interval_count * vendor_subscription_request.total_count}
            )
            expire_by_unix = int(expire_at.timestamp())
            customer_id = vendor["razorpay_customer_id"]
            razorpay_subscription_data = {
                "plan_id": vendor_subscription_request.plan_id,
                "total_count": vendor_subscription_request.total_count,
                "quantity": vendor_subscription_request.quantity,
                "expire_by": expire_by_unix,
                "customer_notify": True,
                "customer_id": customer_id,
            }
            try:
                razorpay_subscription = razorpay_client.subscription.create(data=razorpay_subscription_data)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to create Razorpay subscription: {str(e)}",
                )

            vendor_update_data = {
                "manage_plan": vendor_subscription_request.plan_id,
                "razorpay_subscription_id": razorpay_subscription["id"],
                "start_at": start_at,
                "expire_by": expire_at,
            }
            result = await vendor_collection.update_one({"_id": vendor["_id"]}, {"$set": vendor_update_data})
            if result.modified_count == 0:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update vendor")
            razorpay_subscription = razorpay_client.subscription.fetch("sub_PpC2d9zqEYcoV1")

            return {
                "subscription_id": razorpay_subscription["id"],
                "subscription_url": razorpay_subscription["short_url"],
                "start_at": start_at,
                "expire_by": expire_at,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def subscription_payment(self, request: Request, token: str, subscription_id: str):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            subscription = await razorpay_client.subscription.fetch(subscription_id)
            plan_id = subscription.get("plan_id")
            plan_details = await razorpay_client.plan.fetch(plan_id)
            amount = plan_details.get("amount")

            if not amount:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Amount not found in plan details")

            order_data = {
                "amount": amount,
                "currency": "INR",
                "payment_capture": 1,
                "receipt": subscription_id,
                "notes": {
                    "subscription_id": subscription_id,
                },
            }

            order = await razorpay_client.order.create(data=order_data)
            if not order or "id" not in order:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create order")

            return {
                "message": "Order created successfully",
                "order_id": order["id"],
                "amount": amount,
                "currency": "INR",
                "subscription_id": subscription_id,
                "order_url": f"https://rzp.io/i/{order['id']}",
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def get_plan_list(self, request: Request, token: str):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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

    async def get_plan(self, request: Request, token: str, plan_id: str):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            print(current_user)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            plan = await plan_collection.find_one({"_id": ObjectId(plan_id)})
            if not plan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

            plan["id"] = str(plan["_id"])
            plan.pop("_id", None)

            payments = await payment_collection.find({"status": "active"}).to_list(length=100)

            for payment in payments:
                payment["id"] = str(payment["_id"])
                payment.pop("_id", None)
            plan["vendor"] = {
                "id": str(current_user.id),
                "first_name": current_user.first_name,
                "email": current_user.email,
            }
            plan["payments"] = payments

            return plan
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    async def vendor_users_list_for_slot(self, request: Request, token: str):
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
            vendor_users = await user_collection.find(query).to_list(length=100)
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")
            formatted_users = []
            for user in vendor_users:
                user["id"] = str(user.pop("_id", ""))
                formatted_users.append(user)

            return {"data": formatted_users}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
