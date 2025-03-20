import hashlib
import hmac
import json

from typing import Callable, Type

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies.video_manager import get_video_manager
from app.v1.middleware.auth import get_current_user, get_token_from_header
from app.v1.models.video import *
from app.v1.schemas.slots.slots import *
from app.v1.schemas.video.video_auth import *
from app.v1.services import VideoManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/upload-video", status_code=status.HTTP_201_CREATED)
async def upload_video(
    video_data: VideoUploadRequest,
    current_user: User = Depends(get_current_user),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.upload_video(
            current_user=current_user,
            video_data=video_data,
        )
        return success({"message": "Video uploaded successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-video-list", status_code=status.HTTP_200_OK)
async def get_video_list(
    request: Request,
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter vendors by name, email, or phone"),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await video_manager.get_video_list(
            request=request, current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
        )
        return success({"message": "Video list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-video/{video_id}", status_code=status.HTTP_200_OK)
async def get_video(
    video_id: str,
    current_user: User = Depends(get_current_user),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.get_video(current_user=current_user, video_id=video_id)
        return success({"message": "Video found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-video/{video_id}", status_code=status.HTTP_200_OK)
async def update_video(
    video_id: str,
    video_data: VideoUpdateRequest,
    current_user: User = Depends(get_current_user),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.update_video(current_user=current_user, video_id=video_id, video_data=video_data)
        return success({"message": "Video updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-video/{video_id}", status_code=status.HTTP_200_OK)
async def delete_video(
    video_id: str,
    current_user: User = Depends(get_current_user),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.delete_video(current_user=current_user, video_id=video_id)
        return success({"message": "Video deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-video-for-user", status_code=status.HTTP_200_OK)
async def get_video_for_user(
    request: Request,
    category: Optional[str] = Query(None, description="Filter videos by category"),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.get_video_for_user(request=request, category=category)
        return success({"message": "Video found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
