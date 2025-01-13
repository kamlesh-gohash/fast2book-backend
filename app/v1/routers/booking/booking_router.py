from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import *
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import services
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.services import BookingManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/appointment-slot", status_code=status.HTTP_200_OK)
async def appointment_time(
    request: Request,
    token: str = Depends(get_token_from_header),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.appointment_time(request=request, token=token)

        return success({"message": "Appointment Time found successfully", "data": result})

    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
