# routes.py
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, Request, Path
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.middleware.auth import get_token_from_header
from app.v1.services.support.support_manager import SupportManager
from app.v1.dependencies import get_support_manager

router = APIRouter()


@router.get("/support-list", status_code=status.HTTP_200_OK)
async def support_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    support_manager: SupportManager = Depends(get_support_manager),
):
    try:
        result = await support_manager.support_list(request=request, token=token)
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
