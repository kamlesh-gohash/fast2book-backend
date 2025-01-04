import random
from app.v1.models import User
from app.v1.models import user_collection
from app.v1.models import super_admin_booking_collection
from app.v1.utils.email import send_email, generate_otp
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
import bcrypt

# from app.v1.utils.token import generate_jwt_token
from fastapi import HTTPException, status, Body
from typing import Optional
from datetime import datetime, timedelta
from app.v1.utils.token import get_oauth_tokens, create_access_token, create_refresh_token
from bcrypt import hashpw, gensalt
from app.v1.schemas.superuser.superuser_auth import *


class BookingManager:
    pass
