from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_category_manager, get_services_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import services
from app.v1.schemas.service.service import CreateServiceRequest, DeleteServiceRequest, UpdateServiceRequest
from app.v1.services import CategoryManager, ServicesManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/create-service", status_code=status.HTTP_200_OK)
async def create_service(
    request: Request,
    service_request: CreateServiceRequest,
    token: str = Depends(get_token_from_header),
    service_manager: "ServicesManager" = Depends(lambda: ServicesManager()),
):
    # Validate the service request
    validation_result = service_request.validate()
    if validation_result:
        return validation_result

    try:
        # Convert category_id to ObjectId
        service_request.to_object_id()

        # Create the service
        result = await service_manager.service_create(request=request, token=token, service_request=service_request)
        return success({"message": "Service Created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/service-list", status_code=status.HTTP_200_OK)
async def service_list(
    request: Request,
    token: str = Depends(get_token_from_header),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter services by name or category name"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await service_manager.service_list(request=request, token=token, page=page, limit=limit, search=search, statuss=statuss)
        return success({"message": "Service List found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-service/{id}", status_code=status.HTTP_200_OK)
async def get_service(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the service to retrieve"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    try:
        # Call the ServiceManager to retrieve the service by id
        result = await service_manager.service_get(request=request, token=token, id=id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

        return success({"message": "Service found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-service/{id}", status_code=status.HTTP_200_OK)
async def update_service(
    request: Request,
    service_request: UpdateServiceRequest,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the service to update"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    validation_result = service_request.validate()
    if validation_result:
        return validation_result
    if not (service_request.name or service_request.status or service_request.category_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (name ,status or category_id) must be provided",
        )
    try:
        # Call the ServiceManager to update the service by id
        result = await service_manager.service_update(
            request=request, token=token, id=id, service_request=service_request
        )

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

        return success({"message": "Service updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-service/{id}", status_code=status.HTTP_200_OK)
async def delete_service(
    request: Request,
    token: str = Depends(get_token_from_header),
    id: str = Path(..., title="The ID of the service to delete"),
    service_manager: "ServicesManager" = Depends(get_services_manager),
):
    try:
        # Call the ServiceManager to delete the service by id
        result = await service_manager.service_delete(request=request, token=token, id=id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

        return success({"message": "Service deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/category-list-for-services", status_code=status.HTTP_200_OK)
async def category_list_for_services(
    request: Request,
    token: str = Depends(get_token_from_header),
    service_manager: ServicesManager = Depends(get_services_manager),
):
    # validation_result = category_list_request.validate()
    # if validation_result:
    #     return validation_result
    try:
        result = await service_manager.category_list_for_service(request=request, token=token)
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
