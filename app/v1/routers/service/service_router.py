from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
from app.v1.dependencies import get_services_manager
from app.v1.dependencies import get_category_manager
from app.v1.services import ServicesManager
from app.v1.services import CategoryManager
from app.v1.models import services
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.service.service import CreateServiceRequest,UpdateServiceRequest,DeleteServiceRequest

router = APIRouter()


@router.post("/create-service", status_code=status.HTTP_200_OK)
async def create_service(
    service_request: CreateServiceRequest,
    service_manager: "ServicesManager" = Depends(lambda: ServicesManager())
):
    # Validate the service request
    validation_result = service_request.validate()
    if validation_result:
        return validation_result

    try:
        # Convert category_id to ObjectId
        service_request.to_object_id()

        # Create the service
        result = await service_manager.service_create(service_request)
        return success({"message": "Service Created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/service-list", status_code=status.HTTP_200_OK)
async def service_list(page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter services by name or category name"),
    service_manager: "ServicesManager" = Depends(get_services_manager)):
    try:
        result = await service_manager.service_list(page, limit,search)
        return success({"message": "Service List found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.get("/get-service/{id}", status_code=status.HTTP_200_OK)
async def get_service(
    id: str = Path(..., title="The ID of the service to retrieve"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    try:
        # Call the ServiceManager to retrieve the service by id
        result = await service_manager.service_get(id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found"
            )

        return success({"message": "Service found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.put("/update-service/{id}", status_code=status.HTTP_200_OK)
async def update_service(
    service_request: UpdateServiceRequest,
    id: str = Path(..., title="The ID of the service to update"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    validation_result = service_request.validate()
    if validation_result:
        return validation_result
    if not (service_request.name or service_request.status or service_request.category_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (name ,status or category_id) must be provided"
        )
    try:
        # Call the ServiceManager to update the service by id
        result = await service_manager.service_update(id, service_request)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found"
            )

        return success({"message": "Service updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@router.delete("/delete-service/{id}", status_code=status.HTTP_200_OK)
async def delete_service(
    id: str = Path(..., title="The ID of the service to delete"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    try:
        # Call the ServiceManager to delete the service by id
        result = await service_manager.service_delete(id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found"
            )

        return success({ "message": "Service deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
@router.get("/category-list-for-services",status_code=status.HTTP_200_OK)
async def category_list_for_services(service_manager:ServicesManager = Depends(get_services_manager)):
    # validation_result = category_list_request.validate()
    # if validation_result:
    #     return validation_result
    try:
        result = await service_manager.category_list_for_service()
        return success({"message":"Category List found successfully","data":result})
    except HTTPException as http_ex:

        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    