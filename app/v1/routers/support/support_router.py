# routes.py
from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status

from app.v1.dependencies import get_support_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.services.support.support_manager import SupportManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.get("/support-list", status_code=status.HTTP_200_OK)
async def support_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    support_manager: SupportManager = Depends(get_support_manager),
):
    try:
        result = await support_manager.support_list(request=request, token=token, page=page, limit=limit)
        return success({"message": "Support List found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/support-detail/{support_id}", status_code=status.HTTP_200_OK)
async def support_detail(
    request: Request,
    token: str = Depends(get_token_from_header),
    support_id: str = Path(..., title="The ID of the support to get detail for"),
    support_manager: SupportManager = Depends(get_support_manager),
):
    try:
        # Pass data to user manager for processing
        result = await support_manager.support_detail(request=request, token=token, support_id=support_id)
        return success({"message": "Support detail retrieved successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/reply-support/{support_id}", status_code=status.HTTP_200_OK)
async def reply_support(
    request: Request,
    reply_data: dict,
    token: str = Depends(get_token_from_header),
    support_id: str = Path(..., title="The ID of the support ticket to reply to"),
    support_manager: SupportManager = Depends(get_support_manager),
):
    try:
        result = await support_manager.reply_support(
            request=request,
            token=token,
            support_id=support_id,
            reply=reply_data.get("reply"),
        )
        return success({"message": "Support ticket replied successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
