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

            video = Video(
                name=video_data.name,
                description=video_data.description,
                video_url=video_data.video_url,
                thumbnail_image=video_data.thumbnail_image,
                thumbnail_image_url=thumbnail_image_url,
                tags=video_data.tags,
                videoType=video_data.videoType,
                video_file=video_data.video_file,
                video_file_url=video_file_url,
            )

            result = await video_collection.insert_one(video.dict())
            return {"_id": str(result.inserted_id)}

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_video_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

        except HTTPException as ex:
            raise ex
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
