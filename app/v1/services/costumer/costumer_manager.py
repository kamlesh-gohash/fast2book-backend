import os
import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import pytz

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Path, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import user_collection
from app.v1.models.user import DEFAULT_NOTIFICATION_PREFERENCES, User
from app.v1.schemas.costumer.costumer import UpdateCostumerRequest
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class CostumerManager:

    async def create_customer(self, request: Request, token: str, create_costumer_request: User):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # User registration logic
            existing_user = await user_collection.find_one(
                {
                    "$or": [
                        {"email": {"$eq": create_costumer_request.email, "$nin": [None, ""]}},
                        {"phone": {"$eq": create_costumer_request.phone, "$nin": [None, ""]}},
                    ]
                }
            )

            if existing_user:
                raise HTTPException(
                    status_code=404, detail="customer with this email or phone already exists in the database."
                )
            email = create_costumer_request.email.lower()
            create_costumer_request.email = email
            otp = generate_otp()

            # if create_costumer_request.email:
            #     to_email = create_costumer_request.email
            #     await send_email(to_email, otp)
            # if create_costumer_request.phone:
            #     to_phone = create_costumer_request.phone
            # await send_sms(to_phone, otp)  # Uncomment this line when implementing SMS functionality
            otp_expiration_time = datetime.utcnow() + timedelta(minutes=10)
            # create_costumer_request.otp = otp
            # # create_costumer_request.otp_expiration_time = otp_expiration_time
            plain_password = create_costumer_request.password

            # Hash the password before saving
            hashed_password = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
            create_costumer_request.password = hashed_password
            create_costumer_request.phone = (
                int(create_costumer_request.phone) if create_costumer_request.phone else None
            )
            file_url = None
            if create_costumer_request.user_image:
                image_name = create_costumer_request.user_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                create_costumer_request.user_image = create_costumer_request.user_image
                create_costumer_request.user_image_url = file_url
            # create_costumer_request.password = hashpw(create_costumer_request.password.encode('utf-8'), gensalt()).decode('utf-8')
            # print(create_costumer_request.password, 'create_costumer_request.password')
            create_costumer_request_dict = create_costumer_request.dict()
            create_costumer_request_dict["created_at"] = datetime.utcnow()
            create_costumer_request_dict["is_active"] = True
            create_costumer_request_dict["notification_settings"] = DEFAULT_NOTIFICATION_PREFERENCES

            result = await user_collection.insert_one(create_costumer_request_dict)
            create_costumer_request_dict["id"] = str(result.inserted_id)  # Add `id`

            del create_costumer_request_dict["_id"]
            sign_in_link = f"http://localhost:3000/sign-in"
            source = "Account created"

            context = {"password": plain_password, "sign_in_link": sign_in_link}
            to_email = create_costumer_request.email
            await send_email(to_email, source, context)
            return create_costumer_request_dict
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def customer_list(
        self,
        request: Request,
        token: str,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
        role: str = "user",
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            skip = max((page - 1) * limit, 0)
            query = {"roles": {"$regex": "^user$", "$options": "i"}, "user_role": {"$ne": 2}}

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
                statuss = statuss.strip()
                if not statuss:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status cannot be empty")
                status_regex = {"$regex": statuss, "$options": "i"}
                query["status"] = status_regex

            # Fields to include in the result
            projection = {
                "id": 1,
                "first_name": 1,
                "last_name": 1,
                "email": 1,
                "phone": 1,
                "roles": 1,
                "gender": 1,
                "user_image": 1,
                "user_image_url": 1,
                "status": 1,
                "created_at": 1,
                "costumer_address": 1,
                "costumer_details": 1,
                "created_at": 1,
            }

            # Fetch paginated results
            result = await user_collection.find(query, projection).skip(skip).limit(limit).to_list(length=limit)
            # Format costumer data
            costumer_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")  # IST timezone

            for costumer in result:
                costumer["id"] = str(costumer.pop("_id"))
                costumer["first_name"] = costumer.get("first_name", "").capitalize()
                costumer["last_name"] = costumer.get("last_name", "").capitalize()
                costumer["email"] = costumer.get("email", "")
                costumer["phone"] = costumer.get("phone", "")
                created_at = costumer.get("created_at")
                # if isinstance(created_at, datetime):
                #     costumer["created_at"] = created_at.isoformat()
                # else:
                #     costumer["created_at"] = str(created_at)
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    costumer["created_at"] = created_at_ist.isoformat()
                else:
                    costumer["created_at"] = str(created_at)
                costumer_data.append(costumer)

            # Fetch total count for the query
            total_costumers = await user_collection.count_documents(query)

            # Calculate total pages
            total_pages = (total_costumers + limit - 1) // limit

            return {"data": costumer_data, "total_items": total_costumers, "total_pages": total_pages}
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def get_customer(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Query for customer role and the specific user id
            query = {"_id": ObjectId(id), "roles": {"$in": ["user"]}}

            # Fields to include in the result
            projection = {
                "first_name": 1,
                "last_name": 1,
                "email": 1,
                "phone": 1,
                "gender": 1,
                "status": 1,
                "user_image": 1,
                "user_image_url": 1,
                "costumer_address": 1,  # Include customer address
                "costumer_details": 1,
                "created_at": 1,
                "password": 1,
            }

            # Find the customer by id and role
            result = await user_collection.find_one(query, projection)

            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

            # Convert _id to string and format other fields
            result["id"] = str(result.pop("_id"))
            result["first_name"] = result["first_name"].capitalize()
            result["last_name"] = result["last_name"].capitalize()
            result["email"] = result["email"]
            result["phone"] = result["phone"]
            result["gender"] = result["gender"]
            result["status"] = result["status"]

            # Format created_at field
            created_at = result.get("created_at")
            # if isinstance(created_at, datetime):
            #     result["created_at"] = created_at.isoformat()  # Convert datetime to ISO 8601 string
            # else:
            #     result["created_at"] = str(created_at)
            if isinstance(created_at, datetime):
                created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC

                ist_timezone = pytz.timezone("Asia/Kolkata")
                created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                result["created_at"] = created_at_ist.isoformat()
            else:
                result["created_at"] = str(created_at)

            # Include customer address if it exists
            result["costumer_address"] = result.get("costumer_address", None)
            result["costumer_details"] = result.get("costumer_details", None)
            # result.pop("password", None)

            return result
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_customer(
        self, request: Request, token: str, id: str, update_costumer_request: UpdateCostumerRequest
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            # Validate costumer ID
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid costumer ID: '{id}'")

            # Check if the costumer exists
            costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
            # Prepare update data
            update_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            # Update image if provided
            if update_costumer_request.user_image:
                image_name = update_costumer_request.user_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                update_data["user_image"] = image_name
                update_data["user_image_url"] = file_url
            else:
                file_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{costumer.get('user_image')}"
                )

            if update_costumer_request.first_name is not None:
                update_data["first_name"] = update_costumer_request.first_name
            if update_costumer_request.last_name is not None:
                update_data["last_name"] = update_costumer_request.last_name
            if update_costumer_request.email is not None:
                email = update_costumer_request.email.lower()
                user_with_email = await User.find_one(User.email == email)
                if user_with_email and str(user_with_email.id) != id:  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this email"
                    )
                update_data["email"] = email
            if update_costumer_request.phone is not None:
                user_with_phone = await User.find_one(User.phone == update_costumer_request.phone)
                if user_with_phone and str(user_with_phone.id) != id:  # Ensure it's not the same user
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists with this phone"
                    )
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
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            await user_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            # Fetch updated costumer data
            updated_costumer = await user_collection.find_one({"_id": ObjectId(id)})
            if not updated_costumer:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")

            response_data = {
                "id": str(updated_costumer.get("_id")),
                "first_name": updated_costumer.get("first_name", "").capitalize(),
                "last_name": updated_costumer.get("last_name", "").capitalize(),
                "email": updated_costumer.get("email", ""),
                "phone": updated_costumer.get("phone", ""),
                "gender": updated_costumer.get("gender", ""),
                "status": updated_costumer.get("status", ""),
                "user_image": updated_costumer.get("user_image", ""),
                "user_image_url": file_url,
                "costumer_address": updated_costumer.get(
                    "costumer_address", ""
                ),  # Default to empty string if not present
                "costumer_details": updated_costumer.get(
                    "costumer_details", ""
                ),  # Default to empty string if not present
                "created_at": str(updated_costumer.get("created_at")),
                "password": updated_costumer.get("password", ""),
            }

            # Remove sensitive fields like 'password' if they exist
            response_data.pop("password", None)

            return response_data
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def delete_customer(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            result = await user_collection.delete_one({"_id": ObjectId(id)})
            if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
