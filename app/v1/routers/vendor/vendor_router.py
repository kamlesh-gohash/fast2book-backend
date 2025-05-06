import hashlib
import hmac
import json

from typing import Callable, Type

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies import get_vendor_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User, vendor_collection
from app.v1.models.booking import *
from app.v1.models.vendor_query import VendorQuery
from app.v1.schemas.booking.booking import *
from app.v1.schemas.slots.slots import *
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.services import VendorManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


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
    background_tasks: BackgroundTasks,
    create_vendor_request: dict = Depends(validate_request_data(SignUpVendorRequest)),
    current_user: User = Depends(get_current_user),
    _permission: None = has_permission("vendor-management", "addVendor"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # User registration logic
        result = await vendor_manager.create_vendor(
            current_user=current_user, create_vendor_request=create_vendor_request, background_tasks=background_tasks
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
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter vendors by name, email, or phone"),
    _permission: None = has_permission("vendor-management", "List"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await vendor_manager.vendor_list(
            current_user=current_user, request=request, page=page, limit=limit, search=search, statuss=statuss
        )
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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor(current_user=current_user, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
        return success({"message": "Vendor detail found successfully", "data": result})
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
    update_vendor_request: UpdateVendorRequest,
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the vendor to update"),
    _permission: None = has_permission("vendor-management", "editVendor"),
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
            current_user=current_user, id=id, update_vendor_request=update_vendor_request
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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the vendor to delete"),
    _permission: None = has_permission("vendor-management", "deleteVendor"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.delete_vendor(current_user=current_user, id=id)
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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_service_by_category(current_user=current_user, id=id)
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
    background_tasks: BackgroundTasks,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.vendor_sign_in(vendor_request, background_tasks)
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
    background_tasks: BackgroundTasks,
    vendor_request: SignUpVendorRequest,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.vendor_sign_up(vendor_request, background_tasks)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:

        result = await vendor_manager.vendor_profile(current_user=current_user)
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
    update_vendor_request: UpdateVendorRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = update_vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.update_profile(
            current_user=current_user, update_vendor_request=update_vendor_request
        )
        return success({"message": "Vendor profile updated successfully", "data": result})
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


@router.post("/create-vendor-user", status_code=status.HTTP_201_CREATED)
async def create_vendor_user(
    vendor_user_create_request: VendorUserCreateRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_user_create_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await vendor_manager.create_vendor_user(
            current_user=current_user, vendor_user_create_request=vendor_user_create_request
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
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: Optional[str] = Query(None, description="Search query"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_users_list(
            current_user=current_user, page=page, limit=limit, search=search
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
    slot_request: SlotRequest,
    current_user: User = Depends(get_current_user),
    vendor_user_id: Optional[str] = None,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.set_individual_vendor_availability(
            current_user=current_user, slots=slot_request.slots, vendor_user_id=vendor_user_id
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
    current_user: User = Depends(get_current_user),
    vendor_user_id: str = None,  # New optional parameter
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_availability(current_user=current_user, vendor_user_id=vendor_user_id)
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
    slot_request: SlotRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.update_vendor_availability(
            current_user=current_user, slots=slot_request.slots  # Pass the list of slots
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


@router.post("/add-slot-time-vendor/{id}", status_code=status.HTTP_201_CREATED)
async def add_slot_time_vendor(
    slot_request: SlotRequest,  # Updated to use the new model
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the vendor user to add slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.add_slot_time_vendor(
            current_user=current_user, id=id, slots=slot_request.slots  # Pass the list of slots
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
    slot_request: SlotRequest,
    current_user: User = Depends(get_current_user),
    vendor_id: str = Path(..., title="The ID of the vendor to create slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.create_vendor_slots(
            current_user=current_user, vendor_id=vendor_id, slots=slot_request.slots
        )
        return success({"message": "Slots Updated successfully", "data": result})
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
    current_user: User = Depends(get_current_user),
    vendor_id: str = Path(..., title="The ID of the vendor to get slots for"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.get_vendor_slots(current_user=current_user, vendor_id=vendor_id)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.vendor_list_for_slot(current_user=current_user)
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
    current_user: User = Depends(get_current_user),
    vendor_id=str,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.vendor_user_list_for_slot(current_user=current_user, vendor_id=vendor_id)
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
    vendor_user_request: VendorUserUpdateRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.update_vendor_user_by_id(
            current_user=current_user, id=id, vendor_user_request=vendor_user_request
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
    id: str,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.delete_vendor_user_by_id(current_user=current_user, id=id)
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
    id: str,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_user_by_id(current_user=current_user, id=id)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_subscription_plan(current_user=current_user)
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
    vendor_subscription_request: VendorSubscriptionRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to user manager for processing
        result = await vendor_manager.create_or_upgrade_vendor_subscription(
            current_user=current_user, vendor_subscription_request=vendor_subscription_request
        )
        return success({"message": "Vendor subscription created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/verify-subscription-payment/{subscription_id}", status_code=status.HTTP_200_OK)
async def verify_subscription_payment(
    subscription_id: str,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to vendor manager for processing
        result = await vendor_manager.verify_subscription_payment(
            current_user=current_user, subscription_id=subscription_id
        )
        return success({"message": "Subscription payment verified successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/vendor-subscription-payment-detail", status_code=status.HTTP_200_OK)
async def subscription_payment_details(
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.subscription_payment_details(current_user=current_user)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_plan_list(current_user=current_user)
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


@router.get("/get-all-plans", status_code=status.HTTP_200_OK)
async def get_all_plans(
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_all_plan_list()
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
    plan_id: str,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_plan(current_user=current_user, plan_id=plan_id)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_users_list_for_slot(current_user=current_user)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_dashboard_data_for_vendor(current_user=current_user)
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
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_bookings(current_user=current_user)
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


@router.get("/get-vendor-service", status_code=status.HTTP_200_OK)
async def get_vendor_service(
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_service(current_user=current_user)
        return success({"message": "Vendor services", "data": result})
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


@router.patch("/upgrade-vendor-subscription/{sub_id}", status_code=status.HTTP_200_OK)
async def upgrade_vendor_subscription(
    sub_id: str,
    upgrade_subscription_request: VendorSubscriptionRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        # Pass data to vendor manager for processing
        result = await vendor_manager.upgrade_vendor_subscription(
            current_user=current_user, sub_id=sub_id, upgrade_subscription_request=upgrade_subscription_request
        )
        return success({"message": "Vendor subscription upgraded successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-vendor-query", status_code=status.HTTP_200_OK)
async def create_vendor_query(
    request: Request,
    vendor_query: VendorQuery,
    background_tasks: BackgroundTasks,
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.create_vendor_query(
            request=request, background_tasks=background_tasks, vendor_query=vendor_query
        )
        return success({"message": "Vendor query created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/total-booking-of-vendor", status_code=status.HTTP_200_OK)
async def total_booking_count(
    year: int,  # Add year as a query parameter
    request: Request,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.total_booking_count(request=request, current_user=current_user, year=year)
        return success({"message": f"Total bookings for year {year}", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-booking-for-vendor", status_code=status.HTTP_200_OK)
async def create_booking_for_vendor(
    request: Request,
    booking_data: CreateBookingRequest = Body(...),
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.create_booking_for_vendor(
            request=request,
            current_user=current_user,
            user_id=booking_data.user_id,
            slot=booking_data.time_slot,
            booking_date=booking_data.booking_date,
            service_id=booking_data.service_id,
            category_id=booking_data.category_id,
            vendor_user_id=booking_data.vendor_user_id,
        )
        return success({"message": "Booking created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-user-list-for-vendor", status_code=status.HTTP_200_OK)
async def get_user_list_for_vendor(
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_user_list_for_vendor(current_user=current_user)
        return success({"message": "User list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/complate-booking/{booking_id}", status_code=status.HTTP_200_OK)
async def complate_booking(
    booking_id: str,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.complate_booking(current_user=current_user, booking_id=booking_id)
        return success({"message": "Booking completed successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/add-vendor-account", status_code=status.HTTP_200_OK)
async def add_vendor_account(
    request: Request,
    vendor_data: AddVendorAccountRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.add_vendor_account(
            request=request, current_user=current_user, vendor_data=vendor_data
        )
        return success({"message": "Vendor account added successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)

    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/update-vendor-account", status_code=status.HTTP_200_OK)
async def update_vendor_account(
    request: Request,
    vendor_data: AddVendorAccountRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.update_vendor_account(
            request=request, current_user=current_user, vendor_data=vendor_data
        )
        return success({"message": "Vendor account updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/business-categories", status_code=status.HTTP_200_OK)
async def get_business_categories(
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    """Retrieve all business categories and their sub-categories."""
    try:
        result = await vendor_manager.get_business_categories(current_user=current_user)
        return success({"message": "Business categories found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)

    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/add-vendor-account-by-admin/{vendor_id}", status_code=status.HTTP_200_OK)
async def add_vendor_account_by_admin(
    request: Request,
    vendor_id: str,
    vendor_data: AddVendorAccountRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.add_vendor_account_by_admin(
            request=request, current_user=current_user, vendor_id=vendor_id, vendor_data=vendor_data
        )
        return success({"message": "Vendor account added successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)

    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/update-vendor-account-by-admin/{vendor_id}", status_code=status.HTTP_200_OK)
async def update_vendor_account_by_admin(
    request: Request,
    vendor_id: str,
    vendor_data: AddVendorAccountRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.update_vendor_account_by_admin(
            request=request, current_user=current_user, vendor_id=vendor_id, vendor_data=vendor_data
        )
        return success({"message": "Vendor account updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-bank-account", status_code=status.HTTP_200_OK)
async def get_vendor_bank_account(
    request: Request,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor_bank_account(request=request, current_user=current_user)
        return success({"message": "Vendor bank account found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class RefundRequest(BaseModel):
    refund_type: str  # "full" or "partial"
    refund_percentage: float | None = None  # Required if refund_type is "partial"


@router.post("/refund-request/{booking_id}", status_code=status.HTTP_200_OK)
async def refund_request(
    request: Request,
    booking_id: str,
    refund_data: RefundRequest,
    current_user: User = Depends(get_current_user),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.refund_request(
            request=request, current_user=current_user, booking_id=booking_id, refund_data=refund_data
        )
        return success({"message": "Refund request sent successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
