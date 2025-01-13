from typing import Callable, Type

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies import get_permission_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User
from app.v1.services import PermissionManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.get("/permission-list", status_code=status.HTTP_200_OK)
async def permission_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    permission_manager: PermissionManager = Depends(get_permission_manager),
):
    try:
        result = await permission_manager.permission_list(request=request, token=token)
        return success({"message": "Permission list found successfully", "data": result})
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


# @router.put("/update-permission", status_code=status.HTTP_200_OK)
# async def update_permission(
#     request: Request,
#     update_permission_request: UpdatePermissionRequest,
#     token: str = Depends(get_token_from_header),
#     permission_manager: PermissionManager = Depends(get_permission_manager),
# ):
#     try:
#         result = await permission_manager.update_permission(request=request, token=token, update_permission_request=update_permission_request)
#         return success({"message": "Permission updated successfully", "data": result})
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
