# routes.py
import os
import time

from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.s3 import upload_to_s3


router = APIRouter()


@router.post("/upload-file/{type}", status_code=status.HTTP_201_CREATED)
async def upload_file(
    type: str,
    files: List[UploadFile] = File(...),
):
    try:
        """Handles file uploads to S3 based on type."""
        folder_mapping = {
            "1": "services",
            "2": "vendors",
            "3": "blog",
            "4": "costumers",
        }

        folder_name = folder_mapping.get(type, "other")
        bucket_name = os.getenv("AWS_S3_BUCKET_NAME")

        if not bucket_name:
            raise HTTPException(status_code=500, detail="Bucket name is not configured.")

        allowed_extensions = [".jpg", ".jpeg", ".png", ".pdf", ".webp", ".mp4", ".avi", ".mkv"]

        uploaded_files = []

        for file in files:
            try:
                result = upload_to_s3(file, folder_name, allowed_extensions, bucket_name)
                uploaded_files.append(result)
            except HTTPException as e:
                raise e

        if uploaded_files:
            return success({"message": "Files uploaded successfully.", "data": {"files": uploaded_files}})
        else:
            return failure({"message": "No files were uploaded.", "data": None}, status_code=403)

    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
