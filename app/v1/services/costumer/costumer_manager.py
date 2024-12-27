import random
from app.v1.models.user import User
from app.v1.models import user_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt
# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body,Path
from typing import Optional
from datetime import datetime, timedelta
from bcrypt import hashpw, gensalt
from app.v1.schemas.costumer.costumer import UpdateCostumerRequest
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token

class CostumerManager:

    async def create_costumer(self, create_costumer_request: User):
        try:
            # User registration logic
            existing_user = await user_collection.find_one(
                {"$or": [{"email": {"$eq": create_costumer_request.email, "$nin": [None, ""]}}, {"phone": {"$eq": create_costumer_request.phone, "$nin": [None, ""]}}]}
            )

            if existing_user:
                raise HTTPException(status_code=404, detail="Costumer with this email or phone already exists in the database.")

            otp = generate_otp()

            # if create_costumer_request.email:
            #     to_email = create_costumer_request.email
            #     await send_email(to_email, otp)
            # if create_costumer_request.phone:
            #     to_phone = create_costumer_request.phone
                # await send_sms(to_phone, otp)  # Uncomment this line when implementing SMS functionality
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            # create_costumer_request.otp = otp
            # create_costumer_request.otp_expiration_time = otp_expiration_time
            # create_costumer_request.password = hashpw(create_costumer_request.password.encode('utf-8'), gensalt()).decode('utf-8') 
            create_costumer_request_dict = create_costumer_request.dict()
            result = await user_collection.insert_one(create_costumer_request_dict)
            create_costumer_request_dict["id"] = str(result.inserted_id)  # Add `id`
            del create_costumer_request_dict["_id"]
            return create_costumer_request_dict
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


    async def costumer_list(self, page: int, limit: int, search: str = None, role: str = "user"):
        try:
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}."
                )

            skip = max((page - 1) * limit, 0)
            query = {"roles": {"$regex": "^user$", "$options": "i"}}

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

            # Fields to include in the result
            projection = {
                "id": 1,
                "first_name": 1,
                "last_name": 1,
                "email": 1,
                "phone": 1,
                "roles": 1,
                "gender": 1,
                "status": 1,
                "created_at": 1,
                "costumer_address": 1,
                "costumer_details": 1
            }

            # Fetch paginated results
            result = await user_collection.find(query, projection).skip(skip).limit(limit).to_list(length=limit)

            # Format costumer data
            costumer_data = []
            for costumer in result:
                costumer["id"] = str(costumer.pop("_id"))  # Convert ObjectId to string
                costumer["first_name"] = costumer["first_name"].capitalize()
                costumer["last_name"] = costumer["last_name"].capitalize()
                costumer["email"] = costumer["email"].lower()
                costumer_data.append(costumer)

            # Fetch total count for the query
            total_costumers = await user_collection.count_documents(query)

            # Calculate total pages
            total_pages = (total_costumers + limit - 1) // limit

            return {
                "data": costumer_data,
                "total_items": total_costumers,
                "total_pages": total_pages
            }
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_costumer(self, id: str):
        try:
            # Query for costumer role and the specific user id
            query = {"_id": ObjectId(id), "roles": {"$in": ["user"]}}

            # Find the costumer by id and role
            result = await user_collection.find_one(query)
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
            
            # Convert _id to string and format other fields
            result["id"] = str(result.pop("_id"))
            result["first_name"] = result["first_name"].capitalize()
            result["last_name"] = result["last_name"].capitalize()
            result["email"] = result["email"].lower()
            result["phone"] = result["phone"].lower()
            result["gender"] = result["gender"]
            result.pop("password", None)
            
            return result
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
        
    async def update_costumer(self, id: str, update_costumer_request: UpdateCostumerRequest):
        try:
            # Validate costumer ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid costumer ID: '{id}'")

            # Check if the costumer exists
            costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")

            # Prepare update data
            update_data = {}
            if update_costumer_request.first_name is not None:
                update_data["first_name"] = update_costumer_request.first_name
            if update_costumer_request.last_name is not None:
                update_data["last_name"] = update_costumer_request.last_name
            if update_costumer_request.email is not None:
                update_data["email"] = update_costumer_request.email
            if update_costumer_request.phone is not None:
                update_data["phone"] = update_costumer_request.phone
            if update_costumer_request.status is not None:
                update_data["status"] = update_costumer_request.status
            if update_costumer_request.gender is not None:
                update_data["gender"] = update_costumer_request.gender
            if update_costumer_request.costumer_address is not None:
                update_data["costumer_address"] = update_costumer_request.costumer_address
            if update_costumer_request.costumer_details is not None:
                update_data["costumer_details"] = update_costumer_request.costumer_details
            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid fields provided for update"
                )    
            await user_collection.update_one(
                {"_id": ObjectId(id)},
                {"$set": update_data}
            )

            # Fetch updated costumer data
            updated_costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not updated_costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")

            # Convert _id to string and format other fields
            updated_costumer["id"] = str(updated_costumer.pop("_id"))
            updated_costumer["first_name"] = updated_costumer["first_name"].capitalize()
            updated_costumer["last_name"] = updated_costumer["last_name"].capitalize()
            updated_costumer["email"] = updated_costumer["email"].lower()
            updated_costumer["phone"] = updated_costumer["phone"].lower()
            updated_costumer["gender"] = updated_costumer["gender"].capitalize()
            updated_costumer["status"] = updated_costumer["status"]
            updated_costumer["costumer_address"] = updated_costumer["costumer_address"]
            updated_costumer["costumer_details"] = updated_costumer["costumer_details"]
            updated_costumer.pop("password", None)

            return updated_costumer
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e)
            )    

    async def delete_costumer(self, id: str):
        try:
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))    
