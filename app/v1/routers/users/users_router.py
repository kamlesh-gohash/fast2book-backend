from fastapi import APIRouter, Depends, HTTPException, status
from app.v1.dependencies import get_user_manager
from app.v1.services import UserManager
from app.v1.models import User
from app.v1.models import UserToken
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.user.auth import *
from app.v1.utils.token import *

router = APIRouter()


# Register a new user (POST request)
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(sign_up_request: SignUpRequest, user_manager: UserManager = Depends(get_user_manager)):
    validation_result = sign_up_request.validate()
    if validation_result:
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
        data = await user_manager.sign_in(sign_in_request.email, sign_in_request.password)
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
    # Send OTP for registration or login (POST request)


# @router.post("/send-otp")
# async def send_otp(send_otp_request: SendOtpRequest, user_manager: UserManager = Depends(get_user_manager)):
#     try:
#         # Send OTP logic (e.g., via email or SMS)
#         otp = await user_manager.send_otp(send_otp_request.email)
#         return success({"message": "OTP sent", "otp": otp})
#     except ValueError as ex:
#         return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
#     except Exception as ex:
#         return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


# # Update password (POST request) - update password after login
# @router.post("/update-password")
# async def update_password(update_password_request: UpdatePasswordRequest, user_manager: UserManager = Depends(get_user_manager)):
#     try:
#         # Update password logic (verify old password and change to new one)
#         await user_manager.update_password(update_password_request.email, update_password_request.old_password, update_password_request.new_password)
#         return success({"message": "Password updated successfully"})
#     except ValueError as ex:
#         return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
#     except Exception as ex:
#         return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


@router.post("/refresh-token", response_model=UserToken)
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
        new_access_token = create_access_token(data={"sub": user_email})

        # Return a UserToken instance
        # Convert the ObjectId to a string
        user_token = UserToken(user_id=str(user.id), access_token=new_access_token)
        return user_token

    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred")
