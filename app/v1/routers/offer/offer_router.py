# routes.py
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import get_offer_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.models.user import StatusEnum
from app.v1.schemas.offer.offer import CreateOfferRequest, CreateVendorOffer, UpdateOfferRequest, UpdateVendorOffer
from app.v1.services.offer.offer_manager import OfferManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/create-offer", status_code=status.HTTP_200_OK)
async def create_offer(
    offer_request: CreateOfferRequest,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:

        # validation_result = offer_request.validate()
        # if validation_result:
        #     raise HTTPException(status_code=400, detail=validation_result["message"])
        result = await offer_manager.create_offer(current_user=current_user, offer_request=offer_request)
        return success({"message": "Offer created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-offer", status_code=status.HTTP_200_OK)
async def get_offers(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter vendors by name, email, or phone"),
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await offer_manager.get_offers(
            current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
        )
        return success({"message": "Offers fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-offer/{offer_id}", status_code=status.HTTP_200_OK)
async def get_offer(
    offer_id: str,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.get_offer(offer_id=offer_id, current_user=current_user)
        return success({"message": "Offer fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-offer/{offer_id}", status_code=status.HTTP_200_OK)
async def update_offer(
    offer_id: str,
    offer_request: UpdateOfferRequest,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        validation_result = offer_request.validate()
        if validation_result:
            raise HTTPException(status_code=400, detail=validation_result["message"])
        result = await offer_manager.update_offer(
            offer_id=offer_id, offer_request=offer_request, current_user=current_user
        )
        return success({"message": "Offer updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-offer/{offer_id}", status_code=status.HTTP_200_OK)
async def delete_offer(
    offer_id: str,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.delete_offer(offer_id=offer_id, current_user=current_user)
        return success({"message": "Offer deleted successfully", "data": None})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-all-offer", status_code=status.HTTP_200_OK)
async def get_all_offer(
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.get_all_offer(current_user=current_user)
        return success({"message": "All offers fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/vendor-offer-create", status_code=status.HTTP_200_OK)
async def vendor_offer_create(
    vendor_offer_request: CreateVendorOffer,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.vendor_offer_create(
            vendor_offer_request=vendor_offer_request, current_user=current_user
        )
        return success({"message": "Vendor offer created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-offer-list", status_code=status.HTTP_200_OK)
async def get_vendor_offer_list(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: Optional[str] = Query(None, description="Search term to filter offers by display_text or issuer"),
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await offer_manager.get_vendor_offer_list(
            current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
        )
        return success({"message": "Vendor offer list fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-offer/{vendor_offer_id}", status_code=status.HTTP_200_OK)
async def get_vendor_offer(
    vendor_offer_id: str,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.get_vendor_offer(vendor_offer_id=vendor_offer_id, current_user=current_user)
        return success({"message": "Vendor offer fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-vendor-offer/{vendor_offer_id}", status_code=status.HTTP_200_OK)
async def update_vendor_offer(
    vendor_offer_id: str,
    vendor_offer_request: UpdateVendorOffer,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.update_vendor_offer(
            vendor_offer_id=vendor_offer_id, vendor_offer_request=vendor_offer_request, current_user=current_user
        )
        return success({"message": "Vendor offer updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-vendor-offer/{vendor_offer_id}", status_code=status.HTTP_200_OK)
async def delete_vendor_offer(
    vendor_offer_id: str,
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.delete_vendor_offer(vendor_offer_id=vendor_offer_id, current_user=current_user)
        return success({"message": "Vendor offer deleted successfully", "data": None})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
