from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.v1.dependencies import get_category_manager, get_subscription_manager
from app.v1.models import services
from app.v1.schemas.subscription.subscription_auth import CreateSubscriptionRequest, UpdateSubscriptionRequest
from app.v1.services import CategoryManager, SubscriptionManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


router = APIRouter()


@router.post("/create-subscription", status_code=status.HTTP_200_OK)
async def create_subscription(
    subscription_request: CreateSubscriptionRequest,
    subscription_manager: "SubscriptionManager" = Depends(lambda: SubscriptionManager()),
):
    # Validate the service request
    validation_result = subscription_request.validate()
    if validation_result:
        return validation_result

    try:
        # Create the service
        result = await subscription_manager.subscription_create(subscription_request)
        return success({"message": "Subscription created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/subscription-list", status_code=status.HTTP_200_OK)
async def subscription_list(
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter subscriptions by title"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        result = await subscription_manager.subscription_list(page, limit, search)
        return success({"message": "Subscription List found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-subscription/{id}", status_code=status.HTTP_200_OK)
async def get_subscription(
    id: str = Path(..., title="The ID of the subscription to retrieve"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        # Call the ServiceManager to retrieve the service by id
        result = await subscription_manager.subscription_get(id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

        return success({"message": "subscription found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-subscription/{id}", status_code=status.HTTP_200_OK)
async def update_service(
    subscription_request: UpdateSubscriptionRequest,
    id: str = Path(..., title="The ID of the service to update"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    validation_result = subscription_request.validate()
    if validation_result:
        return validation_result
    if not (
        subscription_request.title
        or subscription_request.price
        or subscription_request.features
        or subscription_request.status
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (title, price, features, status) must be provided",
        )
    try:
        # Call the ServiceManager to update the service by id
        result = await subscription_manager.subscription_update(id, subscription_request)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

        return success({"message": "subscription updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-subscription/{id}", status_code=status.HTTP_200_OK)
async def delete_service(
    id: str = Path(..., title="The ID of the service to delete"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        # Call the ServiceManager to delete the service by id
        result = await subscription_manager.subscription_delete(id)

        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

        return success({"message": "subscription deleted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
