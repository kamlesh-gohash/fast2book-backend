import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.v1.dependencies import get_support_manager, get_user_manager
from app.v1.middleware.auth import get_token_from_header
from app.v1.models import User, UserToken
from app.v1.models.services import *
from app.v1.models.support import Support
from app.v1.schemas.user.auth import *
from app.v1.services import UserManager
from app.v1.services.support.support_manager import SupportManager
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.token import *


logger = logging.getLogger(__name__)
router = APIRouter()


class GoogleLoginRequest(BaseModel):
    token: str  # Google ID token


# Register a new user (POST request)
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(sign_up_request: SignUpRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = sign_up_request.validate()
    if validation_result:
        print(validation_result)
        return validation_result
    try:
        # User registration logic
        result = await user_manager.create_user(sign_up_request)
        return success({"message": "OTP sent successfully", "data": None})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        print(ex, "ex")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Sign in (POST request) - For authentication, e.g., JWT tokens
@router.post("/sign-in")
async def sign_in_user(sign_in_request: SignInRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = sign_in_request.validate()
    if validation_result:
        return validation_result
    try:
        # Proceed with the sign-in logic after Zon validation
        data = await user_manager.sign_in(
            sign_in_request.email, sign_in_request.password, sign_in_request.is_login_with_otp
        )
        if "OTP sent successfully" in data.get("message", ""):
            return data
        return success({"data": data, "token_type": "bearer"})
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


# Resend OTP if expired (POST request)
@router.post("/resend-otp")
async def resend_otp(resend_otp_request: ResendOtpRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = resend_otp_request.validate()
    if validation_result:
        return validation_result

    try:
        # Resend OTP logic
        otp = await user_manager.resend_otp(email=resend_otp_request.email, phone=resend_otp_request.phone)
        return success({"message": "OTP resent", "data": None})
    except HTTPException as http_ex:
        print(http_ex)
        # Explicitly handle HTTPException and return its response
        return failure({"message": "user not found", "data": None})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Forgot password (POST request) - sends reset link or OTP
@router.post("/forgot-password")
async def forgot_password(
    forgot_password_request: ForgotPasswordRequest, user_manager: UserManager = Depends(get_user_manager)
):
    validation_result = forgot_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Forgot password logic (e.g., send reset link)
        await user_manager.forgot_password(email=forgot_password_request.email, phone=forgot_password_request.phone)
        return success({"message": "Password reset link sent"})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Reset password (POST request) - accepts OTP and new password
@router.post("/reset-password")
async def reset_password(
    reset_password_request: ResetPasswordRequest, user_manager: UserManager = Depends(get_user_manager)
):
    validation_result = reset_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Reset password logic (verify OTP and update password)
        await user_manager.reset_password(
            reset_password_request.email, reset_password_request.phone, reset_password_request.password
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


# validate otp
@router.post("/validate-otp")
async def validate_otp(validate_otp_request: ValidateOtpRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = validate_otp_request.validate()
    if validation_result:
        return validation_result
    try:
        # Validate OTP logic
        result = await user_manager.validate_otp(
            email=validate_otp_request.email, phone=validate_otp_request.phone, otp=validate_otp_request.otp
        )
        return success({"message": "OTP validated successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/profile/{user_id}")
async def get_profile(user_id: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Get profile logic
        result = await user_manager.get_profile(user_id)
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


@router.put("/update-profile/{user_id}")
async def update_profile(
    user_id: str, update_profile_request: User, user_manager: UserManager = Depends(get_user_manager)
):
    try:
        # Update profile logic
        result = await user_manager.update_profile(user_id, update_profile_request)
        return success({"message": "Profile updated successfully", "data": result})
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


@router.post("/refresh-token", status_code=status.HTTP_200_OK)
async def refresh_token(request: RefreshTokenRequest):
    validation_result = request.validate()
    if validation_result:
        return validation_result
    try:
        # Verify the refresh token
        payload = verify_token(request.refresh_token)

        # Get the user email from the token payload
        user_email = payload.get("sub")

        # Fetch user by email to get the ObjectId
        user = await User.find_one({"email": user_email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Generate a new access token
        user_data = user.dict()
        user_data["id"] = str(user.id)  # Convert ObjectId to string

        user_data.pop("password", None)
        user_data.pop("otp", None)

        # Generate new access and refresh tokens
        new_access_token = create_access_token(data={"sub": user.email})
        new_refresh_token = create_refresh_token(data={"sub": user.email})

        data = {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "user_data": user_data,
        }
        return success({"message": "Tokens refreshed successfully", "data": data})

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred")


@router.get("/category-list-for-users", status_code=status.HTTP_200_OK)
async def get_category_list_for_users(user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.get_category_list_for_users()
        return success({"message": "Category list fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/service-list-for-category/{category_slug}", status_code=status.HTTP_200_OK)
async def get_service_list_for_category(category_slug: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.get_service_list_for_category(category_slug)
        return success({"message": "Service list fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
        )


# @router.get("/vendor-list-for-category/{category_slug}", status_code=status.HTTP_200_OK)
# async def get_vendor_list_for_category(category_slug: str, user_manager: UserManager = Depends(get_user_manager)):
#     try:
#         result = await user_manager.get_vendor_list_for_category(category_slug)
#         return success({"message": "Vendor list fetched successfully", "data": result})
#     except HTTPException as http_ex:
#         return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
#     except ValueError as ex:
#         return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
#     except Exception as ex:
#         return internal_server_error(
#             {"message": "An unexpected error occurred", "error": str(ex)},
#         )
@router.get("/vendor-list-for-category/{category_slug}", status_code=status.HTTP_200_OK)
async def get_vendor_list_for_category(
    category_slug: str,
    service_id: str = None,  # Optional query parameter
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        # Pass service_id to the user manager
        result = await user_manager.get_vendor_list_for_category(category_slug, service_id=service_id)
        return success({"message": "Vendor list fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
        )


@router.get("/vendor-list-for-services/{services_id}", status_code=status.HTTP_200_OK)
async def get_vendor_list_for_services(services_id: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.get_vendor_list_for_services(services_id)
        return success({"message": "Vendor list fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
        )


@router.post("/support", status_code=status.HTTP_200_OK)
async def support_request(support_request: Support, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.create_support_request(support_request=support_request)
        return success({"message": "Support request submitted successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/service-search/{id}", status_code=status.HTTP_200_OK)
async def service_search(id: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.service_search(id=id)
        return success({"message": "Service search successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/category-search/{id}", status_code=status.HTTP_200_OK)
async def category_search(id: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.category_search(id=id)
        return success({"message": "Category search successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/top-services", status_code=status.HTTP_200_OK)
async def top_services(user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.get_top_services()
        return success({"message": "Top services fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
        )


@router.get("/category-top-service", status_code=status.HTTP_200_OK)
async def category_top_service(user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.get_category_top_service()
        return success({"message": "Category top service fetched successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    request: Request,
    change_password_request: ChangePasswordRequest,
    token: str = Depends(get_token_from_header),
    user_manager: UserManager = Depends(get_user_manager),
):
    validation_result = change_password_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await user_manager.change_password(
            request=request,
            token=token,
            old_password=change_password_request.old_password,
            new_password=change_password_request.new_password,
        )
        return success({"message": "Password changed successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/google-login", status_code=status.HTTP_200_OK)
async def google_login(request: Request, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.google_login(request=request)
        print(result, "result")
        return success({"message": "Google login successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex, "kkkkkkkkkkkkk")
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
