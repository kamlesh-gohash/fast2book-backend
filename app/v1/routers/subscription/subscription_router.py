from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_category_manager, get_subscription_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User, services
from app.v1.schemas.subscription.subscription_auth import *
from app.v1.services import CategoryManager, SubscriptionManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


@router.post("/create-subscription", status_code=status.HTTP_200_OK)
async def create_subscription(
    subscription_request: CreateSubscriptionRequest,
    current_user: User = Depends(get_current_user),
    _permission: None = has_permission("subscription", "addSubscription"),
    subscription_manager: "SubscriptionManager" = Depends(lambda: SubscriptionManager()),
):
    # Validate the service request
    validation_result = subscription_request.validate()
    if validation_result:
        return validation_result

    try:
        # Create the service
        result = await subscription_manager.subscription_create(
            current_user=current_user, subscription_request=subscription_request
        )
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
    request: Request,
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter subscriptions by title"),
    _permission: None = has_permission("subscription", "List"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await subscription_manager.subscription_list(
            request=request, current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
        )
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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the subscription to retrieve"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        # Call the ServiceManager to retrieve the service by id
        result = await subscription_manager.subscription_get(current_user=current_user, id=id)

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
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the service to update"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    validation_result = subscription_request.validate()
    if validation_result:
        return validation_result
    if not (
        subscription_request.title
        or subscription_request.one_month_price
        or subscription_request.three_month_price
        or subscription_request.yearly_price
        or subscription_request.features
        or subscription_request.status
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (title, price, features, status) must be provided",
        )
    try:
        # Call the ServiceManager to update the service by id
        result = await subscription_manager.subscription_update(
            current_user=current_user, id=id, subscription_request=subscription_request
        )

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
    _permission: None = has_permission("subscription", "deleteSubscription"),
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


# @router.post("/create-plan", status_code=status.HTTP_200_OK)
# async def create_plan(
#     request: Request,
#     plan_request: CreateSubscriptionRequest,
#     token: str = Depends(get_token_from_header),
#     subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
# ):
#     # Validate the service request
#     validation_result = plan_request.validate()
#     if validation_result:
#         return validation_result

#     try:
#         # Create the service
#         result = await subscription_manager.plan_create(request=request, token=token, plan_request=plan_request)
#         return success({"message": "Plan created successfully", "data": result})
#     except HTTPException as http_ex:
#         return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
#     except ValueError as ex:
#         return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
#     except Exception as ex:
#         return internal_server_error(
#             {"message": "An unexpected error occurred", "error": str(ex)},
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#         )


@router.post("/create-plan", status_code=status.HTTP_200_OK)
async def create_plan(
    plan_request: CreateSubscriptionRequest,
    current_user: User = Depends(get_current_user),
    _permission: None = has_permission("subscription", "addSubscription"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):

    try:
        # Create the service
        result = await subscription_manager.plan_create(current_user=current_user, plan_request=plan_request)
        return success({"message": "Plan created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/plan-list", status_code=status.HTTP_200_OK)
async def plan_list(
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter plans by title"),
    _permission: None = has_permission("subscription", "List"),
    subscription_manager: "SubscriptionManager" = Depends(get_subscription_manager),
):
    try:
        result = await subscription_manager.plan_list(current_user=current_user, page=page, limit=limit, search=search)
        return success({"message": "Plan List found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
