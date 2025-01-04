from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_category_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User
from app.v1.schemas.category.category import *
from app.v1.services import CategoryManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/create-category", status_code=status.HTTP_200_OK)
async def create_category(
    request: Request,
    category_request: CreateCategoryRequest,
    token: str = Depends(get_token_from_header),
    category_manager: CategoryManager = Depends(get_category_manager),
):
    validation_result = category_request.validate()
    if validation_result:
        return validation_result
    try:
        # Superuser sign-in logic
        result = await category_manager.create_category(request=request, token=token, category_request=category_request)

        return success({"message": "Category Created successfully", "data": result})
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


@router.get("/category-list", status_code=status.HTTP_200_OK)
async def category_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter categories by name or category name"),
    category_manager: CategoryManager = Depends(get_category_manager),
):
    # validation_result = category_list_request.validate()
    # if validation_result:
    #     return validation_result
    try:
        result = await category_manager.category_list(
            request=request, token=token, page=page, limit=limit, search=search
        )
        return success({"message": "Category List found successfully", "data": result})
    except HTTPException as http_ex:

        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-category/{id}", status_code=status.HTTP_200_OK)
async def get_category(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the category to retrieve"),
    category_manager: CategoryManager = Depends(get_category_manager),
):
    try:
        # Call the CategoryManager to retrieve the category by id
        result = await category_manager.get_category_by_id(request=request, token=token, id=id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

        return success({"message": "Category found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-category/{id}", status_code=status.HTTP_200_OK)
async def update_category(
    request: Request,
    category_request: UpdateCategoryRequest,  # Required parameter
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the category to update"),  # Default parameter
    category_manager: CategoryManager = Depends(get_category_manager),
):
    validation_result = category_request.validate()
    if validation_result:
        return validation_result

    # Check if at least one field is provided
    if not (category_request.name or category_request.status):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="At least one field (name or status) must be provided"
        )

    try:
        # Call the CategoryManager to update the category by id
        result = await category_manager.update_category_by_id(
            request=request, token=token, id=id, category_request=category_request
        )

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

        return success({"message": "Category updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-category/{id}", status_code=status.HTTP_200_OK)
async def delete_category(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the category to delete"),
    category_manager: CategoryManager = Depends(get_category_manager),
):
    try:
        # Call the CategoryManager to delete the category by id
        result = await category_manager.delete_category_by_id(request=request, token=token, id=id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

        return success({"message": "Category deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
