import random

from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    User,
    category_collection,
    permission_collection,
    services_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.slots import *
from app.v1.models.vendor import Vendor
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.utils.email import generate_otp, send_email, send_vendor_email


class PermissionManager:

    async def permission_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            permission_list = await permission_collection.find().to_list(length=100)
            return {"data": permission_list}

        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
