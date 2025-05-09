from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder

from app.v1.middleware.auth import get_current_user
from app.v1.models import User, permission_collection, user_collection
from app.v1.models.permission import *
from app.v1.models.slots import *
from app.v1.schemas.vendor.vendor_auth import *


class OfferManager:
    pass
