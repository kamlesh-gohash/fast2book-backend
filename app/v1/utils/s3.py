# utils.py
import time
import random
import string
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from fastapi import HTTPException
from typing import List
import os


def generate_random_string(length: int = 5) -> str:
    """Generates a random alphanumeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def upload_to_s3(file, folder_name: str, allowed_extensions: List[str], bucket_name: str):
    """Uploads a file to AWS S3."""
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Invalid file type.")

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION"),
    )

    try:
        random_string = generate_random_string()
        filename = f"{folder_name}/{int(time.time())}{random_string}{ext}"
        s3_client.upload_fileobj(file.file, bucket_name, filename, ExtraArgs={"ContentType": file.content_type})
        file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{filename}"
        return {"filename": filename, "imageUrl": file_url}
    except (NoCredentialsError, PartialCredentialsError) as e:
        raise HTTPException(status_code=500, detail="S3 credentials are missing or invalid.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file to S3: {str(e)}")
