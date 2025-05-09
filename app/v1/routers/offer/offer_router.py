# routes.py
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import get_offer_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.models.user import StatusEnum
from app.v1.services.offer.offer_manager import OfferManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/create-offer", status_code=status.HTTP_200_OK)
async def create_offer(
    offer_request: dict,
    token: str = Depends(get_token_from_header),
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.create_offer(token=token, offer_request=offer_request)
        return success({"message": "Offer created successfully", "data": result})
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


@router.get("/get-offer", status_code=status.HTTP_200_OK)
async def get_offers(
    token: str = Depends(get_token_from_header),
    current_user: User = Depends(get_current_user),
    offer_manager: OfferManager = Depends(get_offer_manager),
):
    try:
        result = await offer_manager.get_offers(token=token)
        return success({"message": "Offers fetched successfully", "data": result})
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
