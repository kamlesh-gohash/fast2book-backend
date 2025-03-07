import base64
import random

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import bcrypt
import pytz
import razorpay
import requests

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from dateutil.relativedelta import relativedelta

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status
from pymongo import ASCENDING, DESCENDING

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, video_collection
from app.v1.models.slots import *
from app.v1.models.video import *
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.schemas.video.video_auth import *
from app.v1.utils.email import *
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class VideoManager:
    async def upload_video(
        self,
        request: Request,
        token: str,
        video_data: VideoUploadRequest,
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            thumbnail_image_url = None
            if video_data.thumbnail_image:
                thumbnail_image = video_data.thumbnail_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                thumbnail_image_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{thumbnail_image}"
                )

            video_file_url = None
            if video_data.video_file:
                video_file = video_data.video_file
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                video_file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{video_file}"
            video_data_dict = {
                "name": video_data.name,
                "description": video_data.description,
                "video_url": video_data.video_url,
                "thumbnail_image": video_data.thumbnail_image,
                "thumbnail_image_url": thumbnail_image_url,
                "tags": video_data.tags,
                "videoType": video_data.videoType,
                "video_file": video_data.video_file,
                "video_file_url": video_file_url,
                "created_at": datetime.utcnow(),
                "status": StatusEnum.Active,
            }
            result = await video_collection.insert_one(video_data_dict)

            inserted_document = await video_collection.find_one({"_id": result.inserted_id})

            # Convert ObjectId to string for JSON serialization
            if inserted_document and "_id" in inserted_document:
                inserted_document["_id"] = str(inserted_document["_id"])

            # Return the entire inserted document
            return inserted_document

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_video_list(self, request: Request, token: str, page: int, limit: int, search: str, statuss: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )
            skip = max((page - 1) * limit, 0)
            query = {}

            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"name": search_regex},
                    {"description": search_regex},
                    {"tags": search_regex},
                ]

            if statuss:
                query["status"] = statuss
            videos = await video_collection.find(query).sort("created_at", DESCENDING).to_list(length=None)
            response_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")
            for video in videos:
                video["id"] = str(video["_id"])
                video.pop("_id")
                created_at = video.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    video["created_at"] = created_at_ist.isoformat()
                else:
                    video["created_at"] = str(created_at)
                response_data.append(video)
            total_video = await video_collection.count_documents(query)
            total_pages = (total_video + limit - 1) // limit
            return {
                "data": response_data,
                "total_items": total_video,
                "total_pages": total_pages,
            }
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_video(self, request: Request, token: str, video_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            video = await video_collection.find_one({"_id": ObjectId(video_id)})
            if not video:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Video not found")
            video["id"] = str(video["_id"])
            video.pop("_id", None)
            return video
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def update_video(self, request: Request, token: str, video_id: str, video_data: VideoUpdateRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            video = await video_collection.find_one({"_id": ObjectId(video_id)})
            if not video:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Video not found")
            update_data = {}
            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            if video_data.name is not None:
                update_data["name"] = video_data.name
            if video_data.description is not None:
                update_data["description"] = video_data.description
            if video_data.tags is not None:
                update_data["tags"] = video_data.tags
            if video_data.status is not None:
                update_data["status"] = video_data.status
            if video_data.video_file:
                video_file = video_data.video_file
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                video_file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{video_file}"
                update_data["video_file"] = video_file
                update_data["video_file_url"] = video_file_url
            if video_data.thumbnail_image:
                thumbnail_image = video_data.thumbnail_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                thumbnail_image_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{thumbnail_image}"
                )
                update_data["thumbnail_image"] = thumbnail_image
                update_data["thumbnail_image_url"] = thumbnail_image_url
            if video_data.video_url:
                update_data["video_url"] = video_data.video_url
            if video_data.videoType:
                update_data["videoType"] = video_data.videoType
            await video_collection.update_one({"_id": ObjectId(video_id)}, {"$set": update_data})
            update_video_data = await video_collection.find_one({"_id": ObjectId(video_id)})
            update_video_data.pop("_id", None)
            return update_video_data
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def delete_video(
        self,
        request: Request,
        token: str,
        video_id: str,
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            result = video_collection.delete_one({"_id": ObjectId(video_id)})

            return {"data": None}
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_video_for_user(
        self,
        request: Request,
    ):
        try:

            videos = await video_collection.find().to_list(length=None)
            for video in videos:
                video["_id"] = str(video["_id"])
            return videos
        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
