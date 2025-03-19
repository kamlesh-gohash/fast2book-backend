import razorpay
import razorpay.errors

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import *
from app.v1.middleware.auth import get_current_user, get_token_from_header
from app.v1.models import booking_collection, services, user_collection
from app.v1.models.booking import *
from app.v1.schemas.booking.booking import *
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.services import BookingManager
from app.v1.utils.email import send_email
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


razorpay_client = razorpay.Client(auth=(os.getenv("RAZOR_PAY_KEY_ID"), os.getenv("RAZOR_PAY_KEY_SECRET")))


router = APIRouter()


@router.post("/appointment-slot", status_code=status.HTTP_200_OK)
async def appointment_time(
    current_user: User = Depends(get_current_user),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.appointment_time(current_user=current_user)

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


@router.get("/user-book-appointment", status_code=status.HTTP_200_OK)
async def book_appointment(
    booking_date: str = Query(..., description="Booking date in YYYY-MM-DD format"),
    slot: str = Query(..., description="Time slot in 'HH:MM - HH:MM' format"),
    vendor_id: str = Query(..., description="Vendor ID"),
    service_id: str = Query(..., description="Service ID"),
    vendor_user_id: Optional[str] = Query(None, description="Vendor User ID (optional)"),
    current_user: User = Depends(get_current_user),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        # Call the booking manager to fetch and return the required data
        result = await booking_manager.book_appointment(
            current_user=current_user,
            booking_date=booking_date,
            slot=slot,
            vendor_id=vendor_id,
            service_id=service_id,
            vendor_user_id=vendor_user_id,
        )

        return success({"message": "Booking details fetched successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/checkout/{id}", status_code=status.HTTP_200_OK)
async def user_booking_checkout(
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    # payment_method: str = Form(...),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_checkout(current_user=current_user, id=id)
        return success({"message": "boking detail found successfully", "data": result})

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
    current_user: User = Depends(get_current_user),
    search: str = Query(None, description="Search query"),
    start_date: str = Query(None, description="Start date for filtering bookings (format: YYYY-MM-DD HH:MM:SS)"),
    end_date: str = Query(None, description="End date for filtering bookings (format: YYYY-MM-DD HH:MM:SS)"),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_list_for_vendor(
            current_user=current_user, search=search, start_date=start_date, end_date=end_date
        )

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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.vendor_update_booking(current_user=current_user, id=id)

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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.vendor_get_booking(current_user=current_user, id=id)

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


@router.get("/user-booking-list", status_code=status.HTTP_200_OK)
async def user_booking_list(
    current_user: User = Depends(get_current_user),
    status_filter: str = Query(None, description="Filter past bookings by status (completed/cancelled)"),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        # Validate status filter if provided
        if status_filter and status_filter.lower() not in ["completed", "cancelled"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status filter. Must be either 'completed' or 'cancelled'",
            )

        result = await booking_manager.user_booking_list(current_user=current_user, status_filter=status_filter)

        return success({"message": "User Booking List found successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/cancel-booking/{id}", status_code=status.HTTP_200_OK)
async def cancel_booking(
    cancel_request: CancelBookingRequest,
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.cancel_booking(current_user=current_user, id=id, cancel_request=cancel_request)

        return success({"message": "User Booking cancelled successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/user-booking-list-for-admin", status_code=status.HTTP_200_OK)
async def user_booking_list_for_admin(
    current_user: User = Depends(get_current_user),
    search: str = Query(None, description="Search query"),
    start_date: str = Query(None, description="Start date for filtering bookings (format: YYYY-MM-DD HH:MM:SS)"),
    end_date: str = Query(None, description="End date for filtering bookings (format: YYYY-MM-DD HH:MM:SS)"),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_list_for_admin(
            current_user=current_user, search=search, start_date=start_date, end_date=end_date
        )

        return success({"message": "User Booking List found successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-user-booking-for-admin/{id}", status_code=status.HTTP_200_OK)
async def get_user_booking_for_admin(
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.get_user_booking_for_admin(current_user=current_user, id=id)

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


@router.post("/booking-payment", status_code=status.HTTP_200_OK)
async def booking_payment(
    current_user: User = Depends(get_current_user),
    booking_data: CreateBookingRequest = Body(...),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.booking_payment(
            current_user=current_user,
            vendor_id=booking_data.vendor_id,
            slot=booking_data.time_slot,
            booking_date=booking_data.booking_date,
            service_id=booking_data.service_id,
            category_id=booking_data.category_id,
            vendor_user_id=booking_data.vendor_user_id,
        )

        return success({"message": "Payment initiated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/verify-payment", status_code=status.HTTP_200_OK)
async def verify_payment(request: Request, payload: dict):

    try:
        razorpay_order_id = payload["razorpay_order_id"]
        razorpay_payment_id = payload["razorpay_payment_id"]
        razorpay_signature = payload["razorpay_signature"]
        order_id = payload["order_id"]
        params = {"razorpay_order_id": razorpay_order_id, "razorpay_payment_id": razorpay_payment_id}
        razorpay_client.utility.verify_payment_signature({**params, "razorpay_signature": razorpay_signature})
        payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
        payment_status = payment_details.get("status")
        payment_method = payment_details.get("method")

        if payment_status != "captured":
            await booking_collection.update_one(
                {"_id": ObjectId(order_id)},
                {
                    "$set": {
                        "payment_status": "failed",
                        "booking_status": "pending",
                        "payment_method": payment_method,
                        "failure_reason": payment_details.get("error_description", "Payment failed"),
                    }
                },
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment failed")

        await booking_collection.update_one(
            {"_id": ObjectId(order_id)},
            {
                "$set": {
                    "payment_status": "paid",
                    "booking_status": "panding",
                    "booking_confirm": True,
                    "payment_method": payment_method,
                    "payment_id": razorpay_payment_id,
                }
            },
        )
        updated_booking = await booking_collection.find_one({"_id": ObjectId(order_id)})
        if not updated_booking:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

        user_id = updated_booking.get("user_id")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User ID not found in booking")

        # Fetch user data to check notification settings
        user_data = await user_collection.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Check if booking confirmation notifications are enabled
        notification_settings = user_data.get("notification_settings", {})
        if notification_settings.get("booking_confirmation", True):  # Default to True if not set
            # Prepare email context
            source = "Payment Success"
            context = {
                "name": payment_details.get("name"),
                "email": payment_details.get("email"),
                "order_id": order_id,
                "payment_id": razorpay_payment_id,
                "payment_method": payment_method,
                "amount": payment_details.get("amount") / 100,
            }

            # Send email
            await send_email(to_email=payment_details.get("email"), source=source, context=context)

        return success({"message": "Payment verification successful"})
    except razorpay.errors.SignatureVerificationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payment signature")
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
        )


@router.get("/user-booking-view/{id}", status_code=status.HTTP_200_OK)
async def user_booking_view(
    current_user: User = Depends(get_current_user),
    id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_view(current_user=current_user, id=id)

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


@router.get("/user-booking-update-request/{booking_id}", status_code=status.HTTP_200_OK)
async def user_booking_update_request(
    booking_id: str = Path(..., min_length=1, max_length=100),
    date: str = Query(..., description="Date in YYYY-MM-DD format"),
    current_user: User = Depends(get_current_user),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_update_request(
            current_user=current_user, booking_id=booking_id, date=date
        )
        return success({"message": "Vendor slots retrieved successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/user-booking-reschedule/{booking_id}", status_code=status.HTTP_200_OK)
async def user_booking_reschedule(
    reason_for_reschulding: ResuldlinBookingRequest,
    current_user: User = Depends(get_current_user),
    booking_id: str = Path(..., min_length=1, max_length=100),
    booking_manager: BookingManager = Depends(get_booking_manager),
):
    try:
        result = await booking_manager.user_booking_resulding(
            current_user=current_user,
            reason_for_reschulding=reason_for_reschulding,
            booking_id=booking_id,
        )
        return success({"message": "Booking rescheduled successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
