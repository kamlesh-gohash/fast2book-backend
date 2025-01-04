import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, category_collection, services_collection, user_collection, vendor_collection
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.utils.email import generate_otp, send_email, send_vendor_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class VendorManager:
    async def create_vendor(self, request: Request, token: str, create_vendor_request: VendorCreateRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Check if a user with the given email or phone already exists
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
                    status_code=404, detail="Vendor with this email or phone already exists in the database."
                )

            # Generate OTP and expiration time
            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)

            # Validate Category
            category_id = create_vendor_request.category_id
            category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category_data:
                raise HTTPException(status_code=400, detail=f"Invalid category ID: {category_id}.")

            # Ensure services is a list and process it correctly
            services = create_vendor_request.services
            if not isinstance(services, list):
                services = [services]  # Wrap single service in a list

            # Extract service IDs
            service_ids = [
                ObjectId(service.id) if isinstance(service, Service) else ObjectId(service["id"])
                for service in services
            ]

            # Fetch only active services matching the category and IDs
            query = {
                "category_id": ObjectId(category_id),
                "_id": {"$in": service_ids},
                "status": "active",  # Filter only active services
            }
            valid_services = await services_collection.find(query).to_list(None)

            # Validate if all provided services are valid
            if len(valid_services) != len(service_ids):
                raise HTTPException(
                    status_code=400, detail="One or more services are invalid for the selected category."
                )

            # Prepare User data (including category_id and services)
            create_vendor_request_dict = create_vendor_request.dict()
            # create_vendor_request_dict["otp"] = otp
            # create_vendor_request_dict["otp_expires"] = otp_expiration_time
            create_vendor_request.password = hashpw(create_vendor_request.password.encode("utf-8"), gensalt()).decode(
                "utf-8"
            )

            # Add services details to the data being saved
            create_vendor_request_dict["services"] = [
                {"id": str(service["_id"]), "name": service["name"]} for service in valid_services
            ]

            # Insert user data into the database
            result = await user_collection.insert_one(create_vendor_request_dict)

            # Prepare Response
            create_vendor_request_dict["id"] = str(result.inserted_id)
            create_vendor_request_dict["category_name"] = category_data.get("name")  # Add category name for reference
            create_vendor_request_dict["created_by"] = current_user.email
            create_vendor_request_dict.pop("password", None)
            create_vendor_request_dict.pop("_id", None)
            # reset_link = f"http://localhost:3000/reset-password/{str(result.inserted_id)}"
            # Send email to the vendor
            # await send_vendor_email(create_vendor_request.email, create_vendor_request.password, reset_link)

            return {"data": create_vendor_request_dict}

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_list(
        self, request: Request, token: str, page: int, limit: int, search: str = None, role: str = "vendor"
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

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
            # Fetch paginated results
            result = await user_collection.find(query).skip(skip).limit(limit).to_list(length=limit)

            # Format vendor data
            vendor_data = []
            for vendor in result:
                vendor["id"] = str(vendor.pop("_id"))
                vendor["first_name"] = vendor["first_name"].capitalize()
                vendor["last_name"] = vendor["last_name"].capitalize()
                vendor["email"] = vendor["email"].lower()
                vendor["roles"] = vendor["roles"]
                vendor["created_by"] = vendor.get("created_by", "Unknown")
                vendor.pop("password", None)
                category_id = vendor.get("category_id")
                if category_id:
                    category = await category_collection.find_one({"_id": ObjectId(category_id)})
                    vendor["category_name"] = category.get("name") if category else "Unknown"
                else:
                    vendor["category_name"] = "Unknown"
                vendor_data.append(vendor)

            # Fetch total count for the query
            total_vendors = await user_collection.count_documents(query)
            total_pages = (total_vendors + limit - 1) // limit

            return {"data": vendor_data, "total_items": total_vendors, "total_pages": total_pages}
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
            # Query for vendor role and the specific user id
            query = {"_id": ObjectId(id), "roles": {"$in": ["vendor"]}}

            # Find the vendor by id and role
            result = await user_collection.find_one(query)

            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Convert _id to string and format other fields
            result["id"] = str(result.pop("_id"))
            result["first_name"] = result["first_name"].capitalize()
            result["last_name"] = result["last_name"].capitalize()
            result["email"] = result["email"]
            result["phone"] = result["phone"]
            result["created_by"] = result.get("created_by", "Unknown")  # Avoid .get() for strings
            category_id = result.get("category_id")
            if category_id:
                category = await category_collection.find_one({"_id": ObjectId(category_id)})
                result["category_name"] = category.get("name") if category else "Unknown"
            else:
                result["category_name"] = "Unknown"
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

            # Validate vendor ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID: '{id}'")

            # Check if the vendor exists
            vendor = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare update data
            update_data = {}

            # Update basic fields
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

            # Process category
            if update_vendor_request.category_id is not None:
                category_id = update_vendor_request.category_id
                category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
                if not category_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid category ID: {category_id}."
                    )
                update_data["category_id"] = category_id
                update_data["category_name"] = category_data.get("name")

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
                    "category_id": ObjectId(update_vendor_request.category_id or vendor.get("category_id")),
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
                update_data["services"] = [
                    {"id": str(service["_id"]), "name": service["name"]} for service in valid_services
                ]

            # Check if update_data is empty
            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update."
                )

            # Update the vendor in the database
            await user_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            # Fetch the updated vendor data
            result = await user_collection.find_one({"_id": ObjectId(id)})

            # Prepare response
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

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            # Query to get all active services for the given category_id
            services = await services_collection.find({"category_id": ObjectId(id), "status": "active"}).to_list(None)

            if not services:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No services found for this category")

            # Format the services to include only the necessary fields (id and name)
            formatted_services = [
                {"id": str(service["_id"]), "name": service["name"], "status": service["status"]}
                for service in services
            ]

            return {"services": formatted_services}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_sign_in(self, vendor_request: SignInVendorRequest):
        try:
            # Check if vendor exists
            vendor = await user_collection.find_one({"email": vendor_request.email})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Check if the user role is "vendor"
            if "roles" not in vendor or "vendor" not in vendor["roles"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a vendor")
            stored_password_hash = vendor.get("password")
            if not stored_password_hash:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored password hash not found."
                )
            # Check if the entered password matches the stored hashed password
            if not bcrypt.checkpw(
                vendor_request.password.encode("utf-8"),
                stored_password_hash.encode("utf-8") if isinstance(stored_password_hash, str) else stored_password_hash,
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
            access_token = create_access_token(data={"sub": vendor["email"]})
            refresh_token = create_refresh_token(data={"sub": vendor["email"]})

            # Prepare response
            vendor_response = {key: str(value) if key == "_id" else value for key, value in vendor.items()}
            vendor_response["id"] = vendor_response.pop("_id")
            vendor_response.pop("password", None)
            vendor_response["access_token"] = access_token
            vendor_response["refresh_token"] = refresh_token

            # Return vendor data if all checks pass
            return vendor_response
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_sign_up(self, vendor_request: SignUpVendorRequest):
        try:
            # Check if vendor already exists
            existing_vendor = await user_collection.find_one({"email": vendor_request.email})
            if existing_vendor:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Vendor already exists")

            # Create new vendor
            hashed_password = bcrypt.hashpw(vendor_request.password.encode("utf-8"), bcrypt.gensalt())
            new_vendor = {
                "first_name": vendor_request.first_name,
                "last_name": vendor_request.last_name,
                "email": vendor_request.email,
                "business_name": vendor_request.business_name,
                "business_type": vendor_request.business_type,
                "status": vendor_request.status,
                "roles": vendor_request.roles,
                "password": hashed_password,
            }
            result = await user_collection.insert_one(new_vendor)
            new_vendor["id"] = str(result.inserted_id)  # Add `id` field
            new_vendor.pop("_id", None)
            new_vendor.pop("password", None)
            return new_vendor
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

            # Format the vendor to include only the necessary fields (id and name)
            vendor["id"] = str(vendor.pop("_id"))
            vendor.pop("password", None)

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

            query = {"_id": ObjectId(current_user.id)}
            vendor = await user_collection.find_one(query)
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            update_data = {}
            if update_vendor_request.first_name is not None:
                update_data["first_name"] = update_vendor_request.first_name
            if update_vendor_request.last_name is not None:
                update_data["last_name"] = update_vendor_request.last_name
            if update_vendor_request.email is not None:
                update_data["email"] = update_vendor_request.email
            if update_vendor_request.phone is not None:
                update_data["phone"] = update_vendor_request.phone
            if update_vendor_request.business_type is not None:
                update_data["business_type"] = update_vendor_request.business_type
            if update_vendor_request.business_details is not None:
                update_data["business_details"] = update_vendor_request.business_details
            if update_vendor_request.business_address is not None:
                update_data["business_address"] = update_vendor_request.business_address
            if update_vendor_request.business_name is not None:
                update_data["business_name"] = update_vendor_request.business_name
            if update_vendor_request.category_id is not None:
                update_data["category_id"] = update_vendor_request.category_id
            if update_vendor_request.category_name is not None:
                update_data["category_name"] = update_vendor_request.category_name
            if update_vendor_request.services is not None:
                update_data["services"] = update_vendor_request.services
            if update_vendor_request.service_details is not None:
                update_data["service_details"] = update_vendor_request.service_details
            if update_vendor_request.manage_plan is not None:
                update_data["manage_plan"] = update_vendor_request.manage_plan
            if update_vendor_request.manage_fee_and_gst is not None:
                update_data["manage_fee_and_gst"] = update_vendor_request.manage_fee_and_gst
            if update_vendor_request.manage_offer is not None:
                update_data["manage_offer"] = update_vendor_request.manage_offer
            if update_vendor_request.status is not None:
                update_data["status"] = update_vendor_request.status
            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            await user_collection.update_one(query, {"$set": update_data})
            # Update the vendor
            result = await user_collection.find_one({"_id": ObjectId(current_user.id)})
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
                "service_details": result.get("service_details"),
                "manage_plan": result.get("manage_plan"),
                "manage_fee_and_gst": result.get("manage_fee_and_gst"),
                "manage_offer": result.get("manage_offer"),
                "status": result.get("status"),
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def create_vendor_user(
        self, request: Request, token: str, vendor_user_create_request: VendorUserCreateRequest
    ):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            print(current_user, "current_user")
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the current user has the "vendor" role
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Check if the vendor's business type is "business"
            # business_type = current_user.get("business_type")  # Ensure you await if this is an async method
            # if not business_type:
            #     raise HTTPException(
            #         status_code=status.HTTP_400_BAD_REQUEST,
            #         detail="Business type not specified for the current user."
            #     )
            # if business_type != "business":
            #     raise HTTPException(
            #         status_code=status.HTTP_403_FORBIDDEN,
            #         detail="Only vendors with a business type of 'business' can create vendor users."
            #     )

            # Validate the vendor user creation request
            if (
                not vendor_user_create_request.first_name
                or not vendor_user_create_request.last_name
                or not vendor_user_create_request.email
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="First name, last name, and email are required for vendor user creation.",
                )

            # Check if the vendor user already exists
            query = {"email": vendor_user_create_request.email}
            existing_vendor_user = await user_collection.find_one(query)
            if existing_vendor_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="A user with the provided email already exists."
                )
            vendor_user_create_request.created_by = current_user.id
            # Prepare new vendor user data
            new_vendor_user = {
                "first_name": vendor_user_create_request.first_name,
                "last_name": vendor_user_create_request.last_name,
                "email": vendor_user_create_request.email,
                "phone": vendor_user_create_request.phone,
                "roles": vendor_user_create_request.roles,
                "status": vendor_user_create_request.status,
            }

            # Insert the new vendor user into the database
            result = await user_collection.insert_one(new_vendor_user)
            new_vendor_user["id"] = str(result.inserted_id)  # Add `id` field
            new_vendor_user.pop("_id", None)
            new_vendor_user["created_by"] = str(current_user.id)

            # Return the created vendor user
            return new_vendor_user
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_users_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Query for vendor role and filter by the created_by field to ensure we only return users created by the current vendor
            query = {"created_by": str(current_user.id), "roles": {"$in": ["vendor_user"]}}
            print(query, "query")
            # Find users who were created by the current vendor
            vendor_users = await user_collection.find(query).to_list(None)
            print(vendor_users, "vendor_users")
            # If no vendor users are found, return an error
            if not vendor_users:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor users found")

            # Format the result to exclude "_id" field and return it as a list
            formatted_users = []
            for user in vendor_users:
                user["_id"] = str(user["_id"])  # Convert ObjectId to string
                formatted_users.append(user)

            return formatted_users
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
