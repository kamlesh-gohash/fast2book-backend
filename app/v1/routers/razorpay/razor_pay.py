import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.v1.dependencies import get_razor_pay_manager, get_user_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User, UserToken
from app.v1.models.services import *
from app.v1.models.support import Support
from app.v1.schemas.user.auth import *
from app.v1.services import UserManager
from app.v1.services.razorpay.razor_pay_manager import RazorPayManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.token import *


router = APIRouter()

# @router.post("/refund", status_code=status.HTTP_200_OK)
# async def refund(
#     request: Request,
#     token: str = Depends(get_token_from_header),
#     support_manager: RazorPayManager = Depends(get_razor_pay_manager),
# ):
#     try:
#         result = await support_manager.refund(request=request, token=token)
#         return success({"message": "Refund successfully", "data": result})
#     except HTTPException as http_ex:
#         # Explicitly handle HTTPException and return its response
#         return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
#     except ValueError as ex:
#         return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
#     except Exception as ex:
#         return internal_server_error(
#             {"message": "An unexpected error occurred", "error": str(ex)},
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#         )
