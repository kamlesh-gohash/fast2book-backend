import base64
import os
import random

from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional

import bcrypt
import pytz
import requests

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, File, HTTPException, Path, UploadFile, status
from PIL import Image

from app.v1.models import notification_collection
from app.v1.models.notification import Notification
from app.v1.models.user import User
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class NotificationManager:

    async def notification_list(self, current_user: User):
        try:
            notifications = (
                await notification_collection.find({"user_id": ObjectId(current_user.id)})
                .sort("created_at", -1)
                .to_list(length=None)
            )

            for notification in notifications:
                notification["id"] = str(notification["_id"])
                notification.pop("_id", None)
                notification.pop("user_id", None)
            return notifications

        except Exception as e:
            raise e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to fetch list of blogs: {str(e)}"
            )
