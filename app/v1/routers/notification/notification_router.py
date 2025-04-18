from typing import Any, Dict

import razorpay
import razorpay.errors

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Form,
    HTTPException,
    Path,
    Query,
    Request,
    UploadFile,
    status,
)

from app.v1.dependencies import *
from app.v1.middleware.auth import get_current_user, get_token_from_header
from app.v1.models import (
    booking_collection,
    category_collection,
    notification_collection,
    services,
    services_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.booking import *
from app.v1.schemas.booking.booking import *
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.services import NotificationManager
from app.v1.utils.email import send_email
from app.v1.utils.notification import send_push_notification
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


razorpay_client = razorpay.Client(auth=(os.getenv("RAZOR_PAY_KEY_ID"), os.getenv("RAZOR_PAY_KEY_SECRET")))


router = APIRouter()


@router.get("/notification-list", status_code=status.HTTP_200_OK)
async def notification_list(
    current_user: User = Depends(get_current_user),
    notification_manager: NotificationManager = Depends(get_notification_manager),
):
    try:
        result = await notification_manager.notification_list(current_user=current_user)

        return success({"message": "Notification List found successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
