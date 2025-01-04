from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_category_manager, get_subscription_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import services
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.services import BookingManager, CategoryManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()
