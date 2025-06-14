from enum import Enum
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field
from slugify import slugify

from app.v1.dependencies import get_blog_manager
from app.v1.middleware.auth import check_permission
from app.v1.models import Blog
from app.v1.services import BlogManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


@router.post("/create-blog", status_code=status.HTTP_201_CREATED)
async def create_blog(
    create_blog_request: Blog,
    _permission: None = has_permission("blog-management", "addBlog"),
    blog_manager: BlogManager = Depends(get_blog_manager),
):
    try:
        if not create_blog_request.blog_url and create_blog_request.title:
            create_blog_request.blog_url = slugify(create_blog_request.title)
        elif not create_blog_request.title:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Blog title is required.")

        result = await blog_manager.create_blog(create_blog_request)
        return success({"message": "Blog created successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=validation_error(str(e)))
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/blog-list", status_code=status.HTTP_200_OK)
async def blog_list(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter categories by name or category name"),
    _permission: None = has_permission("blog-management", "List"),
    blog_manager: BlogManager = Depends(get_blog_manager),
):
    # validation_result = category_list_request.validate()
    # if validation_result:
    #     return validation_result
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await blog_manager.blog_list(page, limit, search, statuss)
        return success({"message": "Blog List found successfully", "data": result})
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


@router.get("/get-blog/{id}", status_code=status.HTTP_200_OK)
async def get_blog(
    id: str = Path(..., title="The ID of the blog to retrieve"),
    blog_manager: BlogManager = Depends(get_blog_manager),
):
    try:
        # Call the BlogManager to retrieve the blog by id
        result = await blog_manager.get_blog_by_id(id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blog not found")

        return success({"message": "Blog found successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=validation_error(str(e)))
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class StatusEnum(str, Enum):
    Active = "active"
    Inactive = "inactive"
    Draft = "draft"


class BlogRequest(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    blog_url: Optional[str] = None
    # image: Optional[str] = None
    blog_image: Optional[str] = None
    blog_image_url: Optional[str] = None
    author_name: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    status: StatusEnum = Field(default=StatusEnum.Active)


@router.put("/update-blog/{id}", status_code=status.HTTP_200_OK)
async def update_blog(
    id: str,
    blog_request: BlogRequest,
    _permission: None = has_permission("blog-management", "editBlog"),
    blog_manager: BlogManager = Depends(get_blog_manager),
):
    try:
        result = await blog_manager.update_blog_by_id(id, blog_request)
        return success({"message": "Blog updated successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as e:
        return failure({"message": str(e)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-blog/{id}", status_code=status.HTTP_200_OK)
async def delete_blog(
    id: str = Path(..., title="The ID of the blog to delete"),
    _permission: None = has_permission("blog-management", "deleteBlog"),
    blog_manager: BlogManager = Depends(get_blog_manager),
):
    try:
        # Call the BlogManager to delete the blog by id
        result = await blog_manager.delete_blog_by_id(id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blog not found")

        return success({"message": "Blog deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
