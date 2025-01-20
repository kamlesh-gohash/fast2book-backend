from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import *
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import services
from app.v1.models.booking import *
from app.v1.schemas.booking.booking import *
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


@router.post("/user-book-appointment", status_code=status.HTTP_200_OK)
async def book_appointment(
    request: Request,
    booking_request: CreateBookingRequest,
    token: str = Depends(get_token_from_header),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        validation_result = booking_request.validate()
        if validation_result:
            return validation_result

        print(booking_request, "booking_request")
        result = await booking_manager.book_appointment(request=request, token=token, booking_request=booking_request)

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


@router.get("/user-booking-list-for-vendor", status_code=status.HTTP_200_OK)
async def user_booking_list_for_vendor(
    request: Request,
    token: str = Depends(get_token_from_header),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_list_for_vendor(request=request, token=token)

        return success({"message": "User Booking List found successfully", "data": result})

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


@router.put("/vendor-update-booking/{id}", status_code=status.HTTP_200_OK)
async def update_booking_status(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.vendor_update_booking(request=request, token=token, id=id)

        return success({"message": "User Booking updated successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-get-booking/{id}", status_code=status.HTTP_200_OK)
async def vendor_get_booking(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.vendor_get_booking(request=request, token=token, id=id)

        return success({"message": "User Booking found successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
