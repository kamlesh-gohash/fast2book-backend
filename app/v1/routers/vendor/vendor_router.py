import hashlib
import hmac
import json

from typing import Callable, Type

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies import get_vendor_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User, vendor_collection
from app.v1.schemas.slots.slots import *
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.services import VendorManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


async def update_subscription_payment_details(
    subscription_id: str, payment_id: str, amount: int, currency: str, status: str
):
    print(
        subscription_id, payment_id, amount, currency, status, "subscription_id, payment_id, amount, currency, status"
    )
    """
    Update the subscription payment details in the database.
    """
    # Update the subscription details in your database
    await vendor_collection.update_one(
        {"razorpay_subscription_id": subscription_id},
        {
            "$set": {
                "is_subscription": True,
            }
        },
    )


async def cancel_subscription(subscription_id: str):
    print(subscription_id, "subscription_id")
    """
    Handle subscription cancellation.
    """
    # Update the subscription status in your database
    await vendor_collection.update_one(
        {"razorpay_subscription_id": subscription_id}, {"$set": {"is_subscription": False}}
    )


async def handle_payment_failure(subscription_id: str, payment_id: str):
    print(subscription_id, payment_id, "subscription_id, payment_id")
    """
    Handle payment failure.
    """
    # Update the payment status in your database
    await vendor_collection.update_one(
        {"razorpay_subscription_id": subscription_id}, {"$set": {"last_payment_status": "failed"}}
    )


# Custom function to handle validation errors
def validate_request_data(schema: Type[BaseModel]) -> Callable:
    def validator(data: dict):
        try:
            return schema(**data)  # Return the validated model instance
        except ValidationError as e:
            # Extract field errors
            errors = [{"field": err["loc"][-1], "message": err["msg"]} for err in e.errors()]
            missing_fields = [err["field"] for err in errors if err["message"] == "field required"]
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Invalid Data, Validation Failed",
                    "errors": errors,
                    "missing_fields": missing_fields,  # Return missing fields
                },
            )

    return validator


@router.post("/create-vendor", status_code=status.HTTP_201_CREATED)
async def create_vendor(
    request: Request,
    create_vendor_request: dict = Depends(validate_request_data(SignUpVendorRequest)),
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # User registration logic
        result = await vendor_manager.create_vendor(
            request=request, token=token, create_vendor_request=create_vendor_request
        )
        return success({"message": "Vendor created successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-list", status_code=status.HTTP_200_OK)
async def vendor_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter vendors by name, email, or phone"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_list(request=request, token=token, page=page, limit=limit, search=search)
        return success({"message": "Vendor List found successfully", "data": result})
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


@router.get("/get-vendor/{id}", status_code=status.HTTP_200_OK)
async def get_vendor(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor(request=request, token=token, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
        return success({"message": "Vendor found successfully", "data": result})
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


@router.put("/update-vendor/{id}", status_code=status.HTTP_200_OK)
async def update_vendor(
    request: Request,
    update_vendor_request: UpdateVendorRequest,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the vendor to update"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = update_vendor_request.validate()
    if validation_result:
        return validation_result
    if not (
        update_vendor_request.first_name
        or update_vendor_request.last_name
        or update_vendor_request.email
        or update_vendor_request.phone
        or update_vendor_request.business_address
        or update_vendor_request.business_details
        or update_vendor_request.status
        or update_vendor_request.business_name
        or update_vendor_request.category_id
        or update_vendor_request.category_name
        or update_vendor_request.services
        or update_vendor_request.location
        or update_vendor_request.specialization
        or update_vendor_request.fees
        or update_vendor_request.manage_plan
        or update_vendor_request.manage_fee_and_gst
        or update_vendor_request.manage_offer
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one field must be provided")
    try:
        result = await vendor_manager.update_vendor(
            request=request, token=token, id=id, update_vendor_request=update_vendor_request
        )
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
        return success({"message": "Vendor updated successfully", "data": result})
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


@router.delete("/delete-vendor/{id}", status_code=status.HTTP_200_OK)
async def delete_vendor(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the vendor to delete"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.delete_vendor(request=request, token=token, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
        return success({"message": "Vendor deleted successfully", "data": result})
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


@router.get("/get-service-by-category/{id}", status_code=status.HTTP_200_OK)
async def get_service_by_category(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_service_by_category(request=request, token=token, id=id)
        return success({"message": "Service found successfully", "data": result})
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


@router.post("/sign-in", status_code=status.HTTP_200_OK)
async def vendor_sign_in(
    vendor_request: SignInVendorRequest,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.vendor_sign_in(vendor_request)
        return success({"message": "Vendor sign in successfully", "data": result})
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


@router.post("/sign-up", status_code=status.HTTP_201_CREATED)
async def vendor_sign_up(
    vendor_request: SignUpVendorRequest,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.vendor_sign_up(vendor_request)
        return success({"message": "Vendor sign up successfully", "data": result})
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


@router.get("/vendor-profile", status_code=status.HTTP_200_OK)
async def vendor_profile(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_profile(request=request, token=token)
        return success({"message": "Vendor profile found successfully", "data": result})
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


@router.put("/update-profile", status_code=status.HTTP_200_OK)
async def update_profile(
    request: Request,
    update_vendor_request: UpdateVendorRequest,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = update_vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.update_profile(
            request=request, token=token, update_vendor_request=update_vendor_request
        )
        return success({"message": "Vendor profile updated successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        print(ex, "ex")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-vendor-user", status_code=status.HTTP_201_CREATED)
async def create_vendor_user(
    request: Request,
    vendor_user_create_request: VendorUserCreateRequest,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_user_create_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.create_vendor_user(
            request=request, token=token, vendor_user_create_request=vendor_user_create_request
        )
        return success({"message": "Vendor user created successfully", "data": result})
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


@router.get("/vendor-users-list", status_code=status.HTTP_200_OK)
async def vendor_users_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: Optional[str] = Query(None, description="Search query"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_users_list(
            request=request, token=token, page=page, limit=limit, search=search
        )
        return success({"message": "Vendor users list found successfully", "data": result})
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


@router.post("/add-slot-time", status_code=status.HTTP_201_CREATED)
async def add_slot_time(
    request: Request,
    slot_request: SlotRequest,  # Updated to use the new model
    token: str = Depends(get_token_from_header),
    vendor_user_id: Optional[str] = None,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.set_individual_vendor_availability(
            request=request, token=token, slots=slot_request.slots, vendor_user_id=vendor_user_id
        )
        return success({"message": "Slot time added successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-availability", status_code=status.HTTP_200_OK)
async def get_vendor_availability(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_user_id: str = None,  # New optional parameter
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_availability(
            request=request, token=token, vendor_user_id=vendor_user_id
        )
        return success({"message": "Vendor availability found successfully", "data": result})
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


@router.put("/update-vendor-availability", status_code=status.HTTP_201_CREATED)
async def update_vendor_availability(
    request: Request,
    slot_request: SlotRequest,  # Updated to use the new model
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.update_vendor_availability(
            request=request, token=token, slots=slot_request.slots  # Pass the list of slots
        )
        return success({"message": "Vendor availability updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-vendor-availability", status_code=status.HTTP_200_OK)
async def delete_vendor_availability(
    request: Request,
    token: str = Depends(get_token_from_header),
    day: str = Query(..., description="Day to delete slots for, e.g., 'Monday'"),
    start_time: Optional[str] = Query(None, description="Start time of the specific slot to delete (ISO 8601 format)"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    """
    Delete vendor availability for a specific day or time slot.

    Args:
        day (str): The day for which availability should be deleted.
        start_time (Optional[str]): The specific start time of the slot to delete.

    Returns:
        dict: Response indicating success or failure.
    """
    try:
        result = await vendor_manager.delete_vendor_availability(
            request=request, token=token, day=day, start_time=start_time
        )
        return success({"message": "Vendor availability deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/add-slot-time-vendor/{id}", status_code=status.HTTP_201_CREATED)
async def add_slot_time_vendor(
    request: Request,
    slot_request: SlotRequest,  # Updated to use the new model
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the vendor user to add slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.add_slot_time_vendor(
            request=request, token=token, id=id, slots=slot_request.slots  # Pass the list of slots
        )
        return success({"message": "Slot time added successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
        )


@router.post("/change-passowrd-vendor", status_code=status.HTTP_200_OK)
async def change_password_vendor(
    change_password_request: ChangePasswordRequest,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = change_password_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.change_password_vendor(
            email=change_password_request.email,
            old_password=change_password_request.old_password,
            new_password=change_password_request.new_password,
        )
        return success({"message": "Password changed successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/vendor-slots/{vendor_id}", status_code=status.HTTP_200_OK)
async def create_vendor_slots(
    request: Request,
    slot_request: SlotRequest,
    token: str = Depends(get_token_from_header),
    vendor_id: str = Path(..., title="The ID of the vendor to create slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.create_vendor_slots(
            request=request, token=token, vendor_id=vendor_id, slots=slot_request.slots
        )
        return success({"message": "Slots created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-slots-list/{vendor_id}", status_code=status.HTTP_200_OK)
async def get_vendor_slots(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_id: str = Path(..., title="The ID of the vendor to get slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.get_vendor_slots(request=request, token=token, vendor_id=vendor_id)
        return success({"message": "Slots retrieved successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-list-for-slot", status_code=status.HTTP_200_OK)
async def vendor_list_for_slot(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.vendor_list_for_slot(request=request, token=token)
        return success({"message": "Vendor list retrieved successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-user-list-for-slot/{vendor_id}", status_code=status.HTTP_200_OK)
async def vendor_user_list_for_slot(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_id=str,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.vendor_user_list_for_slot(request=request, token=token, vendor_id=vendor_id)
        return success({"message": "Vendor list retrieved successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-vendor-user/{id}", status_code=status.HTTP_200_OK)
async def update_vendor_user(
    id: str,
    request: Request,
    vendor_user_request: VendorUserUpdateRequest,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
    token: str = Depends(get_token_from_header),
):
    try:
        result = await vendor_manager.update_vendor_user_by_id(
            request=request, token=token, id=id, vendor_user_request=vendor_user_request
        )
        return success({"message": "Vendor user updated successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as e:
        return failure({"message": str(e)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-vendor-user/{id}", status_code=status.HTTP_200_OK)
async def delete_vendor_user(
    request: Request,
    id: str,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.delete_vendor_user_by_id(request=request, token=token, id=id)
        return success({"message": "Vendor user deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-user/{id}", status_code=status.HTTP_200_OK)
async def get_vendor_user(
    request: Request,
    id: str,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_user_by_id(request=request, token=token, id=id)
        return success({"message": "vendor user found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-subscription-plan", status_code=status.HTTP_200_OK)
async def vendor_subscription_plan(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_subscription_plan(request=request, token=token)
        return success({"message": "vendor subscription plan found successfully", "data": result})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-vendor-subscription", status_code=status.HTTP_200_OK)
async def create_vendor_subscription(
    request: Request,
    vendor_subscription_request: VendorSubscriptionRequest,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.create_vendor_subscription(
            request=request, token=token, vendor_subscription_request=vendor_subscription_request
        )
        return success({"message": "Vendor subscription created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        print(ex, "ex")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/verify-subscription-payment/{subscription_id}", status_code=status.HTTP_200_OK)
async def verify_subscription_payment(
    request: Request,
    subscription_id: str,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to vendor manager for processing
        result = await vendor_manager.verify_subscription_payment(
            request=request, token=token, subscription_id=subscription_id
        )
        return success({"message": "Subscription payment verified successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        print(ex, "ex")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-subscription-payment-detail", status_code=status.HTTP_200_OK)
async def subscription_payment_details(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.subscription_payment_details(request=request, token=token)
        return success({"message": "subscription payment details found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-plan-list", status_code=status.HTTP_200_OK)
async def get_plan_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_plan_list(request=request, token=token)
        return success({"message": "plan list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-plan/{plan_id}", status_code=status.HTTP_200_OK)
async def get_plan(
    request: Request,
    plan_id: str,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_plan(request=request, token=token, plan_id=plan_id)
        return success({"message": "plan found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-users-list-for-slot", status_code=status.HTTP_200_OK)
async def vendor_users_list_for_slot(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_users_list_for_slot(request=request, token=token)
        return success({"message": "Vendor users list found successfully", "data": result})
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


@router.get("/vednor-dashboard", status_code=status.HTTP_200_OK)
async def get_dashboard_data_for_vendor(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_dashboard_data_for_vendor(request=request, token=token)
        return success({"message": "Dashboard details", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-bookings", status_code=status.HTTP_200_OK)
async def get_vendor_bookings(
    request: Request,
    token: str = Depends(get_token_from_header),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_bookings(request=request, token=token)
        return success({"message": "Dashboard details", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
