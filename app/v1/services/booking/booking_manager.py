import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, status

from app.v1.models import User, super_admin_booking_collection, user_collection
from app.v1.schemas.superuser.superuser_auth import *
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class BookingManager:
    pass
