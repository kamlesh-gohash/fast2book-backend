from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_rating_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.schemas.category.category import *
from app.v1.schemas.rating.rating import *
from app.v1.services import RatingManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/vendor-rating", status_code=status.HTTP_200_OK)
async def vendor_rating(
    current_user: User = Depends(get_current_user),
    vendor_rating: Rating = Body(...),
    rating_manager: RatingManager = Depends(get_rating_manager),
):
    try:
        result = await rating_manager.vendor_rating(current_user=current_user, vendor_rating=vendor_rating)
        return success({"message": "Thank you for rating", "data": result})
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


@router.get("/get-vendor-rating/{vendor_id}", status_code=status.HTTP_200_OK)
async def get_vendor_rating(
    current_user: User = Depends(get_current_user),
    vendor_id: str = Path(..., title="The ID of the vendor to get rating for"),
    rating_manager: RatingManager = Depends(get_rating_manager),
):
    try:
        result = await rating_manager.get_vendor_rating(current_user=current_user, vendor_id=vendor_id)
        return success({"message": "Vendor rating", "data": result})
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


@router.get("/get-rating-for-vendor", status_code=status.HTTP_200_OK)
async def get_rating_list_for_vendor(
    current_user: User = Depends(get_current_user),
    vendor_id: Optional[str] = Query(None, description="Vendor ID (required for business type vendors)"),
    rating_manager: RatingManager = Depends(get_rating_manager),
):
    try:
        result = await rating_manager.get_rating_list_for_vendor(current_user=current_user, vendor_id=vendor_id)
        return success({"message": "Vendor rating", "data": result})
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
