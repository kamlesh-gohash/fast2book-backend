from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.v1.dependencies import get_super_user_manager
from app.v1.middleware.auth import check_permission, get_current_user, get_token_from_header
from app.v1.models import User
from app.v1.models.slots import *
from app.v1.schemas.superuser.superuser_auth import *
from app.v1.services import SuperUserManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error


def has_permission(menu_id: str, action: str):
    """
    Dependency to check if the user has permission for a specific action on a menu item.
    """

    async def permission_checker(request: Request):
        await check_permission(request, menu_id, action)

    return Depends(permission_checker)


router = APIRouter()


@router.post("/sign-in", status_code=status.HTTP_200_OK)
async def sign_in(
    super_user_sign_in_request: SuperUserSignInRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)
):
    validation_result = super_user_sign_in_request.validate()
    if validation_result:
        return validation_result
    try:
        # Superuser sign-in logic
        result = await user_manager.super_user_sign_in(
            super_user_sign_in_request.email,
            super_user_sign_in_request.password,
            super_user_sign_in_request.is_login_with_otp,
        )
        # if "OTP sent successfully" in result.get("message", ""):
        #     return result
        return success({"message": "Superuser logged in successfully", "data": result})
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


@router.post("/forget-password", status_code=status.HTTP_200_OK)
async def forget_password(
    super_user_forgot_password_request: SuperUserForgotPasswordRequest,
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_forgot_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Forget password logic
        await user_manager.super_user_forget_password(super_user_forgot_password_request.email)
        return success({"message": "OTP sent successfully", "data": None})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/otp-verify", status_code=status.HTTP_200_OK)
async def otp_verify(
    super_user_otp_request: SuperUserOtpRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)
):
    validation_result = super_user_otp_request.validate()
    if validation_result:
        return validation_result
    try:
        # OTP verification logic
        result = await user_manager.super_user_otp_verify(super_user_otp_request.email, super_user_otp_request.otp)
        return success({"message": "OTP verified successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    super_user_reset_password_request: SuperUserResetPasswordRequest,
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_reset_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Reset password logic
        await user_manager.super_user_reset_password(
            super_user_reset_password_request.email, super_user_reset_password_request.password
        )
        return success({"message": "Password reset successful"})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/resend-otp", status_code=status.HTTP_200_OK)
async def resend_otp(
    super_user_resend_otp_request: SuperUserResendOtpRequest,
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_resend_otp_request.validate()
    if validation_result:
        return validation_result
    try:
        # Resend OTP logic
        await user_manager.super_user_resend_otp(
            super_user_resend_otp_request.email,
        )
        return success({"message": "OTP resent"})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/super_user_profile", status_code=status.HTTP_200_OK)
async def get_profile(
    super_user_profile_request: SuperUserProfileRequest,
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_profile_request.validate()
    if validation_result:
        return validation_result

    try:
        # Get profile logic
        result = await user_manager.get_super_user_profile(super_user_profile_request.email)
        return success({"message": "Profile fetched successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update_super_user_profile", status_code=status.HTTP_200_OK)
async def update_profile(
    super_user_profile_update_request: User, user_manager: SuperUserManager = Depends(get_super_user_manager)
):
    try:
        result = await user_manager.update_super_user_profile(super_user_profile_update_request)
        return success({"message": "profile updated successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/change_super_user_password", status_code=status.HTTP_200_OK)
async def change_password(
    super_user_change_password_request: SuperUserChangePassword,
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_change_password_request.validate()
    if validation_result:
        return validation_result

    try:
        result = await user_manager.change_super_user_password(
            email=super_user_change_password_request.email,
            old_password=super_user_change_password_request.old_password,
            new_password=super_user_change_password_request.new_password,
        )
        return success({"message": "Super user password change Successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-super-user", status_code=status.HTTP_200_OK)
async def create_super_user(
    super_user_create_request: SuperUserCreateRequest,
    current_user: User = Depends(get_current_user),
    _permission: None = has_permission("user-management", "addUser"),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = super_user_create_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await user_manager.create_super_user(
            current_user=current_user, super_user_create_request=super_user_create_request
        )
        return success({"message": "Super user created Successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/super-user-list", status_code=status.HTTP_200_OK)
async def super_user_list(
    request: Request,
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter costumers by name, email, or phone"),
    _permission: None = has_permission("user-management", "List"),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        query_params = request.query_params
        statuss = query_params.get("query[status]")
        result = await user_manager.super_user_list(
            request=request, current_user=current_user, page=page, limit=limit, search=search, statuss=statuss
        )

        return success({"message": "Super user list", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/super-user/{id}", status_code=status.HTTP_200_OK)
async def get_super_user(
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the costumer to retrieve"),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.get_super_user(current_user=current_user, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
        return success({"message": "User details", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-super-user/{id}", status_code=status.HTTP_200_OK)
async def update_super_user(
    update_super_user_request: SuperUserUpdateRequest,
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the costumer to update"),
    _permission: None = has_permission("user-management", "editUser"),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    validation_result = update_super_user_request.validate()
    if validation_result:
        return validation_result
    if not (
        update_super_user_request.first_name
        or update_super_user_request.last_name
        or update_super_user_request.email
        or update_super_user_request.phone
        or update_super_user_request.status
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (first_name ,last_name ,email or phone) must be provided",
        )
    try:
        result = await user_manager.update_super_user(
            current_user=current_user, id=id, update_super_user_request=update_super_user_request
        )
        return success({"message": "User updated successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.delete("/delete-super-user/{id}", status_code=status.HTTP_200_OK)
async def delete_super_user(
    current_user: User = Depends(get_current_user),
    id: str = Path(..., title="The ID of the costumer to delete"),
    _permission: None = has_permission("user-management", "deleteUser"),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.delete_super_user(current_user=current_user, id=id)
        if not result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Costumer not found")
        return success({"message": "User deleted successfully", "data": result})
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


@router.get("/dashboard", status_code=status.HTTP_200_OK)
async def get_dashboard_data(
    current_user: User = Depends(get_current_user),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.get_dashboard_data(current_user=current_user)
        return success({"message": "Dashboard details", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/dashboard-booking", status_code=status.HTTP_200_OK)
async def get_dashboard_booking_data(
    current_user: User = Depends(get_current_user),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.get_dashboard_booking_data(current_user=current_user)
        return success({"message": "Booking list", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/total-subscribers", status_code=status.HTTP_200_OK)
async def get_total_subscribers(
    current_user: User = Depends(get_current_user),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.get_total_subscribers(current_user=current_user)
        return success({"message": "Total subscribers count", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/total-booking-for-year", status_code=status.HTTP_200_OK)
async def get_total_booking_for_year(
    year: int,
    current_user: User = Depends(get_current_user),
    user_manager: SuperUserManager = Depends(get_super_user_manager),
):
    try:
        result = await user_manager.get_total_booking_for_year(current_user=current_user, year=year)
        return success({"message": f"Total booking for year {year}", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
