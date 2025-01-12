# routes.py
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import get_payment_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models.payment import PaymentType
from app.v1.models.user import StatusEnum
from app.v1.schemas.payment_type.payment_type import UpdatePaymentRequest
from app.v1.services.payment.payment_manager import PaymentManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.get("/payment-type-list", status_code=status.HTTP_200_OK)
async def payment(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    payment_manager: PaymentManager = Depends(get_payment_manager),
):
    try:
        result = await payment_manager.payment_type_list(request=request, token=token, page=page, limit=limit)
        return success({"message": "Payment List found successfully", "data": result})
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


@router.put("/update-payment/{id}", status_code=status.HTTP_200_OK)
async def update_payment(
    request: Request,
    update_payment_request: UpdatePaymentRequest,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the payment to retrieve"),
    payment_manager: PaymentManager = Depends(get_payment_manager),
):
    try:
        result = await payment_manager.update_payment(
            request=request, token=token, id=id, update_payment_request=update_payment_request
        )
        return success({"message": "Payment List found successfully", "data": result})
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
