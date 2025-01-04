from fastapi import APIRouter, Depends, HTTPException, status, Path, Query, Request
from app.v1.dependencies import get_vendor_manager
from app.v1.services import VendorManager
from app.v1.models import User
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.vendor.vendor_auth import *
from app.v1.middleware.auth import get_token_from_header
from pydantic import ValidationError
from typing import Callable, Type
from fastapi.responses import JSONResponse

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
            return HTTPException(
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
    create_vendor_request: dict = Depends(validate_request_data(VendorCreateRequest)),
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
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.vendor_users_list(request=request, token=token)
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
