# routes.py
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import get_payment_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.models.payment import PaymentType
from app.v1.models.user import StatusEnum
from app.v1.schemas.payment_type.payment_type import UpdatePaymentRequest
from app.v1.services.payment.payment_manager import PaymentManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


@router.get("/payment-type-list", status_code=status.HTTP_200_OK)
async def payment(
    request: Request,
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term for name or category_name"),
    _permission: None = has_permission("permissions-management", "List"),
    payment_manager: PaymentManager = Depends(get_payment_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await payment_manager.payment_type_list(
            request=request, current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
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


@router.put("/update-payment/{id}", status_code=status.HTTP_200_OK)
async def update_payment(
    update_payment_request: UpdatePaymentRequest,
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the payment to retrieve"),
    _permission: None = has_permission("permissions-management", "editPermissions"),
    payment_manager: PaymentManager = Depends(get_payment_manager),
):
    try:
        result = await payment_manager.update_payment(
            current_user=current_user, id=id, update_payment_request=update_payment_request
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
