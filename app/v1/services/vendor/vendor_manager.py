import random
from app.v1.models import User
from app.v1.models import vendor_collection
from app.v1.models import user_collection
from app.v1.models import category_collection
from app.v1.models import services_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body,Query
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from bcrypt import hashpw, gensalt
from app.v1.schemas.vendor.vendor_auth import VendorCreateRequest,UpdateVendorRequest,Service

class VendorManager:
    async def create_vendor(self, create_vendor_request: VendorCreateRequest):
        try:
            # Check if a user with the given email or phone already exists
            existing_user = await user_collection.find_one(
                {
                    "$or": [
                        {"email": {"$eq": create_vendor_request.email, "$nin": [None, ""]}},
                        {"phone": {"$eq": create_vendor_request.phone, "$nin": [None, ""]}}
                    ]
                }
            )

            if existing_user:
                raise HTTPException(
                    status_code=404,
                    detail="Vendor with this email or phone already exists in the database."
                )

            # Generate OTP and expiration time
            otp = generate_otp()
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)

            # Validate Category
            category_id = create_vendor_request.category_id
            category_data = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category_data:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid category ID: {category_id}."
                )

            # Ensure services is a list and process it correctly
            services = create_vendor_request.services
            if not isinstance(services, list):
                services = [services]  # Wrap single service in a list

            # Extract service IDs
            service_ids = [ObjectId(service.id) if isinstance(service, Service) else ObjectId(service["id"]) for service in services]

            # Fetch only active services matching the category and IDs
            query = {
                "category_id": ObjectId(category_id),
                "_id": {"$in": service_ids},
                "status": "active"  # Filter only active services
            }
            valid_services = await services_collection.find(query).to_list(None)

            # Validate if all provided services are valid
            if len(valid_services) != len(service_ids):
                raise HTTPException(
                    status_code=400,
                    detail="One or more services are invalid for the selected category."
                )

            # Prepare User data (including category_id and services)
            create_vendor_request_dict = create_vendor_request.dict()
            # create_vendor_request_dict["otp"] = otp
            # create_vendor_request_dict["otp_expires"] = otp_expiration_time
            create_vendor_request.password = hashpw(create_vendor_request.password.encode('utf-8'), gensalt()).decode('utf-8') 

            # Add services details to the data being saved
            create_vendor_request_dict["services"] = [
                {"id": str(service["_id"]), "name": service["name"]} for service in valid_services
            ]

            # Insert user data into the database
            result = await user_collection.insert_one(create_vendor_request_dict)

            # Prepare Response
            create_vendor_request_dict["id"] = str(result.inserted_id)
            create_vendor_request_dict["category_name"] = category_data.get("name")  # Add category name for reference
            del create_vendor_request_dict["password"]
            del create_vendor_request_dict["_id"]
            return {"data": create_vendor_request_dict}

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(ex)
            )
    async def vendor_list(self, page: int, limit: int,search: str = None, role: str = "vendor"):
        try:
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}."
                )

            skip = max((page - 1) * limit, 0)
            query = {"roles": {"$regex": "^vendor$", "$options": "i"}}

            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Search term cannot be empty"
                    )
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"first_name": search_regex},
                    {"last_name": search_regex},
                    {"email": search_regex},
                    {"phone": search_regex}
                ]
            # Fetch paginated results
            result = await user_collection.find(query).skip(skip).limit(limit).to_list(length=limit)

            # Format vendor data
            vendor_data = []
            for vendor in result:
                vendor["id"] = str(vendor.pop("_id"))
                vendor["name"] = vendor["name"].capitalize()
                vendor["email"] = vendor["email"].lower()
                vendor["phone"] = vendor["phone"].lower()
                vendor["roles"] = vendor["roles"]
                vendor.pop("password", None)
                vendor_data.append(vendor)

            # Fetch total count for the query
            total_vendors = await user_collection.count_documents(query)
            total_pages = (total_vendors + limit - 1) // limit

            return {
                "vendors": vendor_data,
                "total_items": total_vendors,
                "total_pages": total_pages
            }
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(ex),
            )
    async def get_vendor(self, id: str):
        try:
            # Query for vendor role and the specific user id
            query = {"_id": ObjectId(id), "roles": {"$in": ["vendor"]}}

            # Find the vendor by id and role
            result = await user_collection.find_one(query)
            
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            
            # Convert _id to string and format other fields
            result["_id"] = str(result.pop("_id"))
            result["name"] = result["name"].capitalize()
            result["email"] = result["email"].lower()
            result["phone"] = result["phone"].lower()
            result.pop("password", None)
            
            return result
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
        
    async def update_vendor(self, id: str, update_vendor_request: UpdateVendorRequest):
        try:
            # Validate vendor ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid vendor ID: '{id}'")

            # Check if the vendor exists
            vendor = await user_collection.find_one({"_id": ObjectId(id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Prepare update data
            update_data = {}
            if update_vendor_request.first_name is not None:
                update_data["first_name"] = update_vendor_request.first_name
            if update_vendor_request.last_name is not None:
                update_data["last_name"] = update_vendor_request.last_name
            if update_vendor_request.email is not None:
                update_data["email"] = update_vendor_request.email
            if update_vendor_request.phone is not None:
                update_data["phone"] = update_vendor_request.phone
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

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid fields provided for update"
                )    
            await user_collection.update_one(
                {"_id": ObjectId(id)},
                {"$set": update_data}
            )

            # Update the vendor
            result = await user_collection.find_one({"_id": ObjectId(id)})

            return {
                "id": str(result.pop("_id")),
                "first_name": result.get("first_name"),
                "last_name": result.get("last_name"),
                "email": result.get("email"),
                "phone": result.get("phone"),
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
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))  
        
    async def delete_vendor(self, id: str):
        try:
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex)) 

    async def get_service_by_category(self, id: str):
        try:
            # Query to get all active services for the given category_id
            services = await services_collection.find({"category_id": ObjectId(id), "status": "active"}).to_list(None)

            if not services:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No services found for this category")

            # Format the services to include only the necessary fields (id and name)
            formatted_services = [
                {"id": str(service["_id"]), "name": service["name"], "status": service["status"]} for service in services
            ]

            return {"services": formatted_services}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))