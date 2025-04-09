import logging

import httpx

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2 import id_token

from app.v1.dependencies import get_support_manager, get_user_manager
from app.v1.middleware.auth import get_current_user, get_current_user_optional, get_token_from_header
from app.v1.models import User, UserToken
from app.v1.models.services import *
from app.v1.models.support import Support
from app.v1.models.ticket import Ticket
from app.v1.schemas.user.auth import *
from app.v1.services import UserManager
from app.v1.services.support.support_manager import SupportManager
from app.v1.utils.email import generate_otp, send_app_link, send_email, send_sms_on_phone
from app.v1.utils.response.response_format import failure, internal_server_error, success, validation_error
from app.v1.utils.token import *


logger = logging.getLogger(__name__)
router = APIRouter()


class GoogleLoginRequest(BaseModel):
    token: str  # Google ID token


# Register a new user (POST request)
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    sign_up_request: SignUpRequest,
    background_task: BackgroundTasks,
    user_manager: UserManager = Depends(get_user_manager),
):
    validation_result = sign_up_request.validate()
    if validation_result:
        return validation_result
    try:
        # User registration logic
        result = await user_manager.create_user(sign_up_request, background_task)
        return success({"message": "OTP sent successfully", "data": None})
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


# Sign in (POST request) - For authentication, e.g., JWT tokens
@router.post("/sign-in")
async def sign_in_user(sign_in_request: SignInRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = sign_in_request.validate()
    if validation_result:
        return validation_result
    try:
        # Proceed with the sign-in logic after Zon validation
        data = await user_manager.sign_in(
            sign_in_request.email, sign_in_request.phone, sign_in_request.password, sign_in_request.is_login_with_otp
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
        otp = await user_manager.resend_otp(
            email=resend_otp_request.email, phone=resend_otp_request.phone, otp_type=resend_otp_request.otp_type
        )
        return success({"message": "OTP resent", "data": None})
    except HTTPException as http_ex:
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
    except HTTPException as http_ex:
        return failure({"message": str(http_ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


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
            email=validate_otp_request.email,
            phone=validate_otp_request.phone,
            otp=validate_otp_request.otp,
            otp_type=validate_otp_request.otp_type,
        )
        return success({"message": "OTP validated successfully", "data": result})
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


@router.get("/profile", status_code=status.HTTP_200_OK)
async def get_profile(
    current_user: User = Depends(get_current_user), user_manager: UserManager = Depends(get_user_manager)
):
    try:
        # Get profile logic
        result = await user_manager.get_profile(current_user=current_user)
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


@router.put("/update-profile", status_code=status.HTTP_200_OK)
async def update_profile(
    profile_update_request: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    # validation_result = profile_update_request.validate()
    # if validation_result:
    #     return validation_result
    try:
        # Update profile logic
        result = await user_manager.update_profile(
            current_user=current_user, profile_update_request=profile_update_request
        )
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


@router.get("/vendor-list-for-category/{category_slug}", status_code=status.HTTP_200_OK)
async def get_vendor_list_for_category(
    category_slug: str,
    service_id: str = None,  # Optional query parameter
    address: str = None,  # New optional query parameter
    date: str = None,  # New optional query parameter for the start date
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    current_user: Optional[User] = Depends(get_current_user_optional),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        start_date = datetime.strptime(date, "%Y-%m-%d").date() if date else None
        # Pass service_id to the user manager
        result = await user_manager.get_vendor_list_for_category(
            current_user=current_user,
            category_slug=category_slug,
            service_id=service_id,
            address=address,
            date=start_date,
            page=page,
            limit=limit,
        )
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
async def support_request(
    support_request: Support, background_tasks: BackgroundTasks, user_manager: UserManager = Depends(get_user_manager)
):
    try:
        result = await user_manager.create_support_request(
            support_request=support_request, background_tasks=background_tasks
        )
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
    change_password_request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    validation_result = change_password_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await user_manager.change_password(
            current_user=current_user,
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
async def google_login(request: Request, payload: dict, user_manager: UserManager = Depends(get_user_manager)):
    try:
        result = await user_manager.google_login(request=request, payload=payload)
        return success({"message": "Google login successful", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/blog-list", status_code=status.HTTP_200_OK)
async def blog_list(
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    search: str = Query(None, description="Search term to filter categories by name or category name"),
    category: str = Query(None, description="Filter blogs by category"),
    user_manager: UserManager = Depends(get_user_manager),
):
    # validation_result = category_list_request.validate()
    # if validation_result:
    #     return validation_result
    try:

        result = await user_manager.blog_list(page, limit, search, category)
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
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        # Call the BlogManager to retrieve the blog by id
        result = await user_manager.get_blog_by_id(id)

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


@router.get("/get-app-link", status_code=status.HTTP_200_OK)
async def send_link(background_tasks: BackgroundTasks, email: str = Query(None), phone: str = Query(None)):
    try:
        if not email and not phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone must be provided",
            )

        # Send link via email
        if email:
            source = "APP Link"
            to_email = email
            link = "https://fast2book.com/"
            context = {"to_email": email, "link": link}
            background_tasks.add_task(send_email, to_email=to_email, source=source, context=context)

        # Send link via SMS
        if phone:
            to_phone = phone
            expiry_minutes = 10
            app_link = "https://fast2book.com/"
            await send_app_link(to_phone, app_link)

        return success({"message": "Link sent successfully", "data": None})

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


@router.get("/get-notifications-list", status_code=status.HTTP_200_OK)
async def get_notifications_list(
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.get_notifications_list(current_user=current_user)
        return success({"message": "Notifications list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.put("/update-notification", status_code=status.HTTP_200_OK)
async def update_notification(
    request: Request,
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.update_notification(request=request, current_user=current_user)
        return success({"message": "Notifications update successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vednor-list", status_code=status.HTTP_200_OK)
async def get_vendor_list(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.get_vendor_list(
            request=request,
            current_user=current_user,
        )
        return success({"message": "Vendors list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-vendor-slot", status_code=status.HTTP_200_OK)
async def get_vendor_slot(
    vendor_id: str, request: Request, date: str = Query(None), user_manager: UserManager = Depends(get_user_manager)
):
    try:
        result = await user_manager.get_vendor_slot(vendor_id=vendor_id, request=request, date=date)
        return success({"message": "Vendor slot found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-category-service/{category_slug}", status_code=status.HTTP_200_OK)
async def get_category_service(
    category_slug: str,
    request: Request,
    page: int = Query(1, ge=1, description="Page number (must be >= 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of items per page (1-100)"),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.get_category_service(
            request=request, category_slug=category_slug, page=page, limit=limit
        )
        return success({"message": "Category service found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/create-ticket", status_code=status.HTTP_200_OK)
async def create_ticket(
    request: Request,
    ticket_data: Ticket,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user_optional),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.create_ticket(
            request=request, ticket_data=ticket_data, current_user=current_user, background_tasks=background_tasks
        )
        return success({"message": "Ticket created successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/get-user-location", status_code=status.HTTP_200_OK)
async def get_user_location(
    request: Request,
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.get_user_location(request=request, current_user=current_user)
        return success({"message": "User location found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/get-user-ticket-list", status_code=status.HTTP_200_OK)
async def get_user_ticket_list(
    request: Request,
    current_user: User = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    try:
        result = await user_manager.get_user_ticket_list(request=request, current_user=current_user)
        return success({"message": "User ticket list found successfully", "data": result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
