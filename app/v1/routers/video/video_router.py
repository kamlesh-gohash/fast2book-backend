import hashlib
import hmac
import json

from typing import Callable, Type

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.v1.dependencies.video_manager import get_video_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models.video import *
from app.v1.schemas.slots.slots import *
from app.v1.schemas.video.video_auth import *
from app.v1.services import VideoManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/upload-video", status_code=status.HTTP_201_CREATED)
async def upload_video(
    request: Request,
    video_data: VideoUploadRequest,
    token: str = Depends(get_token_from_header),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        # Debugging: Print the received video_data
        print("Received video_data:", video_data.dict())

        # Call the video manager to handle the upload
        result = await video_manager.upload_video(
            request=request,
            token=token,
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
    token: str = Depends(get_token_from_header),
    video_manager: VideoManager = Depends(get_video_manager),
):
    try:
        result = await video_manager.get_video_list(request=request, token=token)
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
