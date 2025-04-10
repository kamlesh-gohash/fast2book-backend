# routes.py
import os
import time
import urllib.parse

from typing import List

import boto3

from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.v1.models import (
    blog_collection,
    services_collection,
    user_collection,
    vendor_collection,
    vendor_query_collection,
    vendor_ratings_collection,
    vendor_services_collection,
    video_collection,
)
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.s3 import upload_to_s3


router = APIRouter()


@router.post("/upload-file/{type}", status_code=status.HTTP_201_CREATED)
async def upload_file(
    type: str,
    files: List[UploadFile] = File(..., max_length=5 * 1024 * 1024),
):
    try:
        """Handles file uploads to S3 based on type."""
        folder_mapping = {
            "1": "services",
            "2": "vendors",
            "3": "blog",
            "4": "users",
            "5": "thumbnails",
            "6": "video",
            "7": "other",
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


@router.delete("/delete-file/{filename:path}", status_code=status.HTTP_200_OK)
async def delete_file(filename: str):
    """
    Deletes a file from S3 based on the provided filename (S3 object key) and updates related database fields.
    """
    try:
        decoded_filename = urllib.parse.unquote(filename)
        bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
        if not bucket_name:
            raise HTTPException(status_code=500, detail="Bucket name is not configured.")
        file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{decoded_filename}"

        # Initialize the S3 client
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_S3_REGION"),
        )

        # Check if the file exists in S3
        try:
            s3_client.head_object(Bucket=bucket_name, Key=decoded_filename)
        except s3_client.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                raise HTTPException(status_code=404, detail=f"File '{decoded_filename}' not found in S3 bucket.")
            raise HTTPException(status_code=500, detail=f"Error checking file existence: {str(e)}")

        # Delete the file from S3
        s3_client.delete_object(Bucket=bucket_name, Key=decoded_filename)

        folder_name = decoded_filename.split("/")[0]  # e.g., 'services', 'users', 'vendors', etc.

        # Map folder names to collections and fields where the URL might be stored
        collection_field_mapping = {
            "services": [
                (services_collection, [("service_image_url", file_url), ("service_image", decoded_filename)]),
                (
                    vendor_services_collection,
                    [("services.service_image_url", file_url), ("services.service_image", decoded_filename)],
                ),
            ],
            "users": [(user_collection, [("user_image_url", file_url), ("user_image", decoded_filename)])],
            "blog": [(blog_collection, [("blog_image_url", file_url), ("blog_image", decoded_filename)])],
            "video": [
                (
                    video_collection,
                    [
                        ("video_file_url", file_url),
                        ("video_file", decoded_filename),
                        ("thumbnail_image_url", file_url),
                        ("thumbnail_image", decoded_filename),
                    ],
                )
            ],
        }

        collections_to_update = collection_field_mapping.get(folder_name, [])
        for collection, fields in collections_to_update:
            for field_name, match_value in fields:
                if "services" in field_name:  # Handle array fields in vendor_services_collection
                    # Use arrayFilters to target specific elements in the services array
                    await collection.update_many(
                        {"services.service_image_url": match_value},  # Match documents with the URL in the array
                        {"$set": {"services.$[elem].service_image_url": None}},
                        array_filters=[{"elem.service_image_url": match_value}],
                    )
                    await collection.update_many(
                        {"services.service_image": match_value},  # Match documents with the filename in the array
                        {"$set": {"services.$[elem].service_image": None}},
                        array_filters=[{"elem.service_image": match_value}],
                    )
                else:  # Handle non-array fields
                    await collection.update_many({field_name: match_value}, {"$set": {field_name: None}})

        return success({"message": f"File deleted successfully and URL removed from database.", "data": None})

    except Exception as ex:
        print(ex, "ex")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
