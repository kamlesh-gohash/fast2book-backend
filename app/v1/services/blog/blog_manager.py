import base64
import os
import random

from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional

import bcrypt

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
            # image_name = create_blog_request.blog_image
            # bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
            # file_url = f"https://{bucket_name}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{image_name}"

            # Insert the blog data into the database
            result = await blog_collection.insert_one(blog_data)
            blog_data["_id"] = str(result.inserted_id)

            # Return the inserted blog data
            return blog_data
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create blog: {str(e)}"
            )

    async def blog_list(self, page: int = 1, limit: int = 10, search: str = None) -> dict:
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
            active_blogs = await blog_collection.find(query).skip(skip).limit(limit).to_list(length=100)

            # Format the response with category name, status, and created_at
            blog_data = [
                {
                    "id": str(blog["_id"]),
                    "title": blog["title"],
                    "content": blog["content"],
                    "blog_url": blog["blog_url"],
                    "author_name": blog["author_name"],
                    "category": blog["category"],
                    "tags": blog["tags"],
                    "status": blog["status"],
                    "created_at": blog["created_at"],
                    "updated_at": blog["updated_at"],
                }
                for blog in active_blogs
            ]
            total_blogs = await blog_collection.count_documents({})
            total_pages = (total_blogs + limit - 1) // limit
            # Return the formatted response
            return {"data": blog_data, "total_pages": total_pages, "total_items": total_blogs}
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

            if blog_request.category:
                if not isinstance(blog_request.category, str):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid category format: {blog_request.category}",
                    )
                update_data["category"] = blog_request.category

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
            update_data["title"] = blog_request.title
            update_data["content"] = blog_request.content
            update_data["author_name"] = blog_request.author_name
            update_data["updated_at"] = datetime.utcnow()
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
