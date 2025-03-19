from typing import Callable, Type

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies import get_permission_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.models.permission import PermissionAssignRequest
from app.v1.services import PermissionManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


@router.get("/admin-list", status_code=status.HTTP_200_OK)
async def admin_list(
    current_user: User = Depends(get_current_user),
    permission_manager: PermissionManager = Depends(get_permission_manager),
):
    try:
        result = await permission_manager.admin_list(current_user=current_user)
        return success({"message": "Admin list found successfully", "data": result})
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


@router.get("/permission-list", status_code=status.HTTP_200_OK)
async def permission_list(
    current_user: User = Depends(get_current_user),
    _permission: None = has_permission("permissions-management", "List"),
    permission_manager: PermissionManager = Depends(get_permission_manager),
):
    try:
        result = await permission_manager.permission_list(current_user=current_user)
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


# @router.post("/assign-permission/{admin_id}",status_code=status.HTTP_200_OK)
# async def assign_permission(
#     request:Request,
#     permission_assign:PermissionAssignRequest,
#     token: str = Depends(get_token_from_header),
#     admin_id: str = Path(..., title="The ID of the admin to assign permissions"),
#     permission_manager: PermissionManager = Depends(get_permission_manager),

# ):
#     try:
#         result = await permission_manager.assign_permission(request=request,token=token,admin_id=admin_id,permission_assign=permission_assign)
#         return success({"message":"Permission assign successfully", "data":result})
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


@router.get("/get-permission/{admin_id}", status_code=status.HTTP_200_OK)
async def get_permission(
    current_user: User = Depends(get_current_user),
    admin_id: str = Path(..., title="The ID of the admin to get permissions"),
    permission_manager: PermissionManager = Depends(get_permission_manager),
):
    try:
        result = await permission_manager.get_permission_by_adminid(current_user=current_user, admin_id=admin_id)
        return success({"message": "Permission get successfully", "data": result})
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


@router.put("/update-permission/{admin_id}", status_code=status.HTTP_200_OK)
async def update_permission(
    current_user: User = Depends(get_current_user),
    admin_id: str = Path(..., title="The ID of the admin to update permissions"),
    updates: dict = Body(..., title="Updates for the admin's permissions"),
    _permission: None = has_permission("permissions-management", "editPermissions"),
    permission_manager: PermissionManager = Depends(get_permission_manager),
):
    try:
        result = await permission_manager.update_permission(
            current_user=current_user, admin_id=admin_id, updates=updates
        )
        return success({"message": "Permission update successfully", "data": result})
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
