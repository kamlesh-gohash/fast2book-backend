from fastapi import APIRouter, Depends, HTTPException, status, Path, Query, Request
from app.v1.dependencies import get_subscription_manager
from app.v1.dependencies import get_category_manager
from app.v1.services import BookingManager
from app.v1.services import CategoryManager
from app.v1.models import services
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.middleware.auth import get_token_from_header

router = APIRouter()
