import random
from app.v1.models import User
from app.v1.models import vendor_collection
from app.v1.models import user_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body,Query
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from bcrypt import hashpw, gensalt
from app.v1.schemas.vendor.vendor_auth import VendorCreateRequest,UpdateVendorRequest


class VendorManager:
    async def create_vendor(self, create_vendor_request: User):
        try:
            # User registration logic
            existing_user = await user_collection.find_one(
                {"$or": [{"email": {"$eq": create_vendor_request.email, "$nin": [None, ""]}}, {"phone": {"$eq": create_vendor_request.phone, "$nin": [None, ""]}}]}
            )

            if existing_user:
                raise HTTPException(status_code=404, detail="Vendor with this email or phone already exists in the database.")

            otp = generate_otp()

            # if create_vendor_request.email:
            #     to_email = create_vendor_request.email
            #     await send_email(to_email, otp)
            # if create_vendor_request.phone:
            #     to_phone = create_vendor_request.phone
                # await send_sms(to_phone, otp)  # Uncomment this line when implementing SMS functionality
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            # create_vendor_request.otp = otp
            # create_vendor_request.otp_expires = otp_expiration_time
            create_vendor_request.password = hashpw(create_vendor_request.password.encode('utf-8'), gensalt()).decode('utf-8') 
            create_vendor_request_dict = create_vendor_request.dict()
            result = await user_collection.insert_one(create_vendor_request_dict)
            create_vendor_request_dict["_id"] = str(result.inserted_id) 
            del create_vendor_request_dict["password"]
            return create_vendor_request_dict

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

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
                vendor["_id"] = str(vendor["_id"])
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
                "total_vendors": total_vendors,
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
            result["_id"] = str(result["_id"])
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
                "id": str(result["_id"]),
                "first_name": result.get("first_name"),
                "last_name": result.get("last_name"),
                "email": result.get("email"),
                "phone": result.get("phone"),
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