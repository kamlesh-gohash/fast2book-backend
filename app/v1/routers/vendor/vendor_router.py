from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
from app.v1.dependencies import get_vendor_manager
from app.v1.services import VendorManager
from app.v1.models import User
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.vendor.vendor_auth import VendorCreateRequest,VendorListRequest,GetVendorRequest,UpdateVendorRequest,DeleteVendorRequest

router = APIRouter()

@router.post("/create-vendor", status_code=status.HTTP_201_CREATED)
async def create_vendor(create_vendor_request: VendorCreateRequest, vendor_manager: VendorManager = Depends(get_vendor_manager)):
    validation_result = create_vendor_request.validate()
    if validation_result:
        return validation_result
    try:
        # User registration logic
        result = await vendor_manager.create_vendor(create_vendor_request)
        return success({"message": "Vendor created successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/vendor-list", status_code=status.HTTP_200_OK)
async def vendor_list(page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter vendors by name, email, or phone"),
    vendor_manager: VendorManager = Depends(get_vendor_manager)):
    try:    
        result = await vendor_manager.vendor_list(page, limit,search)
        return success({"message":"Vendor List found successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/get-vendor/{id}", status_code=status.HTTP_200_OK)
async def get_vendor(
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_vendor(id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vendor not found"
            )
        return success({"message":"Vendor found successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)    
    
@router.put("/update-vendor/{id}", status_code=status.HTTP_200_OK)
async def update_vendor(
    vendor_request: UpdateVendorRequest,
    id: str = Path(..., title="The ID of the vendor to update"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    validation_result = vendor_request.validate()
    if validation_result:
        return validation_result
    if not (vendor_request.first_name or vendor_request.last_name or vendor_request.email or vendor_request.phone or vendor_request.business_address or vendor_request.business_details or vendor_request.business_name or vendor_request.category_id or vendor_request.category_name or vendor_request.services or vendor_request.manage_plan or vendor_request.manage_fee_and_gst or vendor_request.manage_offer):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field must be provided"
        )
    try:
        result = await vendor_manager.update_vendor(id, vendor_request)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vendor not found"
            )
        return success({"message":"Vendor updated successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@router.delete("/delete-vendor/{id}", status_code=status.HTTP_200_OK)
async def delete_vendor(
    id: str = Path(..., title="The ID of the vendor to delete"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.delete_vendor(id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vendor not found"
            )
        return success({"message":"Vendor deleted successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/get-service-by-category/{id}", status_code=status.HTTP_200_OK)
async def get_service_by_category(
    id: str = Path(..., title="The ID of the vendor to retrieve"),
    vendor_manager: VendorManager = Depends(get_vendor_manager),
):
    try:
        result = await vendor_manager.get_service_by_category(id)
        return success({"message":"Service found successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
