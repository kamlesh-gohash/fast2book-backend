from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
from app.v1.dependencies import get_costumer_manager
from app.v1.services import CostumerManager
from app.v1.models import User
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.costumer.costumer import CostumerCreateRequest, UpdateCostumerRequest

router = APIRouter()


# Register a new user (POST request)

@router.post("/create-costumer", status_code=status.HTTP_201_CREATED)
async def register_costumer(costumer_create_request: CostumerCreateRequest, costumer_manager: CostumerManager = Depends(get_costumer_manager)):
    validation_result = costumer_create_request.validate()
    if validation_result:
        return validation_result
    try:
        # User registration logic
        result = await costumer_manager.create_costumer(costumer_create_request)
        return success({"message": "Costumer created successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/costumer-list", status_code=status.HTTP_200_OK)
async def costumer_list(page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter costumers by name, email, or phone"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager)):
    try:    
        result = await costumer_manager.costumer_list(page, limit,search)
        return success({"message":"Costumer List found successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)    

@router.get("/get-costumer/{id}", status_code=status.HTTP_200_OK)
async def get_costumer(
    id: str = Path(..., title="The ID of the costumer to retrieve"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    try:
        result = await costumer_manager.get_costumer(id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Costumer not found"
            )
        return success({"message":"Costumer found successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)  

@router.put("/update-costumer/{id}", status_code=status.HTTP_200_OK)
async def update_costumer(
    costumer_request: UpdateCostumerRequest,
    id: str = Path(..., title="The ID of the costumer to update"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    validation_result = costumer_request.validate()
    if validation_result:
        return validation_result
    if not (costumer_request.first_name or costumer_request.last_name or costumer_request.email or costumer_request.phone):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (first_name ,last_name ,email or phone) must be provided"
        )
    try:
        result = await costumer_manager.update_costumer(id, costumer_request)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Costumer not found"
            )
        return success({"message":"Costumer updated successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@router.delete("/delete-costumer/{id}", status_code=status.HTTP_200_OK)
async def delete_costumer(
    id: str = Path(..., title="The ID of the costumer to delete"),
    costumer_manager: CostumerManager = Depends(get_costumer_manager),
):
    try:
        result = await costumer_manager.delete_costumer(id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Costumer not found"
            )
        return success({"message":"Costumer deleted successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
