from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_costumer_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User
from app.v1.schemas.costumer.costumer import CostumerCreateRequest, UpdateCostumerRequest
from app.v1.services import CostumerManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


# Register a new user (POST request)


@router.post("/create-costumer", status_code=status.HTTP_201_CREATED)
async def register_customer(
    request: Request,
    costumer_create_request: CostumerCreateRequest,
    token: str = Depends(get_token_from_header),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    validation_result = costumer_create_request.validate()
    if validation_result:
        return validation_result
    try:
        # User registration logic
        result = await costumer_manager.create_customer(
            request=request, token=token, create_costumer_request=costumer_create_request
        )
        return success({"message": "customer created successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/costumer-list", status_code=status.HTTP_200_OK)
async def customer_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter costumers by name, email, or phone"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    try:
        result = await costumer_manager.customer_list(
            request=request, token=token, page=page, limit=limit, search=search
        )
        return success({"message": "customer List found successfully", "data": result})
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


@router.get("/get-costumer/{id}", status_code=status.HTTP_200_OK)
async def get_customer(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the costumer to retrieve"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    try:
        result = await costumer_manager.get_customer(request=request, token=token, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
        return success({"message": "customer found successfully", "data": result})
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


@router.put("/update-costumer/{id}", status_code=status.HTTP_200_OK)
async def update_customer(
    request: Request,
    update_costumer_request: UpdateCostumerRequest,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the costumer to update"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    validation_result = update_costumer_request.validate()
    if validation_result:
        return validation_result
    if not (
        update_costumer_request.first_name
        or update_costumer_request.last_name
        or update_costumer_request.email
        or update_costumer_request.phone
        or update_costumer_request.status
        or update_costumer_request.gender
        or update_costumer_request.costumer_address
        or update_costumer_request.costumer_details,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (first_name ,last_name ,email, status, gender or phone) must be provided",
        )
    try:
        result = await costumer_manager.update_customer(
            request=request, token=token, id=id, update_costumer_request=update_costumer_request
        )
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
        return success({"message": "customer updated successfully", "data": result})
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


@router.delete("/delete-costumer/{id}", status_code=status.HTTP_200_OK)
async def delete_customer(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the costumer to delete"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    try:
        result = await costumer_manager.delete_customer(request=request, token=token, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
        return success({"message": "customer deleted successfully", "data": result})
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
