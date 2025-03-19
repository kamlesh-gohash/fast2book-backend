import base64
import os
import random

from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional

import bcrypt
import pytz
import requests

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, File, HTTPException, Path, UploadFile, status
from PIL import Image

from app.v1.models import blog_collection
from app.v1.models.blog import Blog
from app.v1.schemas.costumer.costumer import UpdateCostumerRequest
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


class BlogManager:
    async def create_blog(self, create_blog_request: Blog) -> dict:
        try:
            blog_data = create_blog_request.dict()
            print(blog_data, "blog_data")
            file_url = None
            if create_blog_request.blog_image:
                image_name = create_blog_request.blog_image
                bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"

            # Insert the blog data into the database
            blog_data["blog_image_url"] = file_url
            blog_data["blog_image"] = image_name
            result = await blog_collection.insert_one(blog_data)
            blog_data["_id"] = str(result.inserted_id)

            # Format the response
            blog_data["id"] = str(blog_data["_id"])
            blog_data.pop("_id")
            # Return the inserted blog data
            return blog_data
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create blog: {str(e)}"
            )

    async def blog_list(self, page: int = 1, limit: int = 10, search: str = None, statuss: str = None) -> dict:
        """
        Get list of all active categories.
        """
        try:
            # Fetch all active categories
            skip = (page - 1) * limit
            query = {}  # Start with an empty query

            # If there's a search term, modify the query to search by name or category_name
            if search:
                search_regex = {"$regex": search, "$options": "i"}  # Case-insensitive search
                query["$or"] = [
                    {"title": search_regex},  # Search by category name (if the category is loaded)
                ]
            if statuss:
                query["status"] = statuss
            active_blogs = await blog_collection.find(query).skip(skip).limit(limit).to_list(length=100)

            # Format the response with category name, status, and created_at
            blog_data = []
            ist_timezone = pytz.timezone("Asia/Kolkata")  # IST timezone
            for blog in active_blogs:
                # Convert created_at and updated_at to IST
                created_at = blog.get("created_at")
                updated_at = blog.get("updated_at")

                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    blog["created_at"] = created_at_ist.isoformat()
                else:
                    blog["created_at"] = str(created_at)

                if isinstance(updated_at, datetime):
                    updated_at_utc = updated_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    updated_at_ist = updated_at_utc.astimezone(ist_timezone)  # Convert to IST
                    blog["updated_at"] = updated_at_ist.isoformat()
                else:
                    blog["updated_at"] = str(updated_at)

                blog_data.append(
                    {
                        "id": str(blog["_id"]),
                        "title": blog["title"],
                        "content": blog["content"],
                        "blog_url": blog["blog_url"],
                        "blog_image": blog["blog_image"],
                        "blog_image_url": blog["blog_image_url"],
                        "author_name": blog["author_name"],
                        "category": blog["category"],
                        "tags": blog["tags"],
                        "status": blog["status"],
                        "created_at": blog["created_at"],
                        "updated_at": blog["updated_at"],
                    }
                )
            total_blogs = await blog_collection.count_documents({})
            total_pages = (total_blogs + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": blog_data,
                "paginator": {
                    "itemCount": total_blogs,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }
        except Exception as e:
            raise e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to fetch list of blogs: {str(e)}"
            )

    async def get_blog_by_id(self, id: str) -> dict:
        try:
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid blog ID: '{id}'")

            # Check if the blog exists
            existing_blog = await blog_collection.find_one({"_id": ObjectId(id)})
            if not existing_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            # Format the result
            blog_data = {
                "id": str(existing_blog["_id"]),
                "title": existing_blog["title"],
                "content": existing_blog["content"],
                "blog_url": existing_blog["blog_url"],
                "blog_image": existing_blog["blog_image"],
                "blog_image_url": existing_blog["blog_image_url"],
                "author_name": existing_blog["author_name"],
                "category": existing_blog["category"],
                "tags": existing_blog["tags"],
                "status": existing_blog["status"],
                "created_at": existing_blog["created_at"],
                "updated_at": existing_blog["updated_at"],
            }
            return blog_data
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_blog_by_id(self, id: str, blog_request: Blog) -> dict:
        try:
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid blog ID: '{id}'")

            existing_blog = await blog_collection.find_one({"_id": ObjectId(id)})
            if not existing_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            update_data = {}

            # Debugging fields

            bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            if blog_request.category:
                if not isinstance(blog_request.category, str):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid category format: {blog_request.category}",
                    )
                update_data["category"] = blog_request.category
            if blog_request.blog_image:
                image_name = blog_request.blog_image
                file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{image_name}"
                update_data["blog_image"] = image_name
                update_data["blog_image_url"] = file_url
            else:
                file_url = (
                    f"https://{bucket_name}.s3.{os.getenv('AWS_S3_REGION')}.amazonaws.com/{blog_request.blog_image}"
                )

            if blog_request.tags:
                # Ensure that tags are a list of strings
                if not isinstance(blog_request.tags, list) or not all(
                    isinstance(tag, str) for tag in blog_request.tags
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid tags format: {blog_request.tags}. Tags should be a list of strings.",
                    )
                update_data["tags"] = blog_request.tags
            if blog_request.title:
                update_data["title"] = blog_request.title
            if blog_request.content:
                update_data["content"] = blog_request.content
            if blog_request.author_name:
                update_data["author_name"] = blog_request.author_name
            if blog_request.status:
                update_data["status"] = blog_request.status
            if blog_request.blog_url:
                update_data["blog_url"] = blog_request.blog_url
            if blog_request.blog_image_url:
                update_data["blog_image_url"] = blog_request.blog_image_url

            update_data["updated_at"] = datetime.utcnow()
            if blog_request.status:
                update_data["status"] = blog_request.status
            updated_blog = await blog_collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=True,
            )

            if not updated_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            return {
                "id": str(updated_blog["_id"]),
                "title": updated_blog["title"],
                "content": updated_blog["content"],
                "blog_url": updated_blog["blog_url"],
                "blog_image": updated_blog["blog_image"],
                "blog_image_url": updated_blog["blog_image_url"],
                "author_name": updated_blog["author_name"],
                "category": updated_blog["category"],
                "tags": updated_blog["tags"],
                "status": updated_blog["status"],
                "created_at": updated_blog["created_at"],
                "updated_at": updated_blog["updated_at"],
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update blog: {str(e)}"
            )

    async def delete_blog_by_id(self, id: str) -> dict:
        try:
            # Convert the string ID to ObjectId and validate it
            if not ObjectId.is_valid(id):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid blog ID: '{id}'")

            # Check if the category exists
            existing_blog = await blog_collection.find_one({"_id": ObjectId(id)})
            if not existing_blog:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            # Perform the deletion of the category
            result = await blog_collection.delete_one({"_id": ObjectId(id)})
            if result.deleted_count == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Blog with ID '{id}' not found")

            return {"data": None}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
