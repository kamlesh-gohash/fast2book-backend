from fastapi import APIRouter, Depends, HTTPException, status
from app.v1.dependencies import get_user_manager
from app.v1.services import UserManager
from app.v1.models import User
from app.v1.utils.response.response_format import success, failure, validation_error, internal_server_error
from app.v1.utils.response.response_code import ResponseCode

router = APIRouter()

# Register a new user (POST request)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: User, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # User registration logic
        result = await user_manager.create_user(user)
        return success({"message": "User registered successfully", "user": result})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_409_CONFLICT)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Sign in (POST request) - For authentication, e.g., JWT tokens


@router.post("/sign-in")
async def sign_in_user(user: User, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Implement the sign-in logic (e.g., check password, return token)
        token = await user_manager.sign_in(user)
        return success({"access_token": token, "token_type": "bearer"})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Send OTP for registration or login (POST request)


@router.post("/send-otp")
async def send_otp(email: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Send OTP logic (e.g., via email or SMS)
        otp = await user_manager.send_otp(email)
        return success({"message": "OTP sent", "otp": otp})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Resend OTP if expired (POST request)


@router.post("/resend-otp")
async def resend_otp(email: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Resend OTP logic
        otp = await user_manager.resend_otp(email)
        return success({"message": "OTP resent", "otp": otp})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Forgot password (POST request) - sends reset link or OTP


@router.post("/forgot-password")
async def forgot_password(email: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Forgot password logic (e.g., send reset link)
        await user_manager.forgot_password(email)
        return success({"message": "Password reset link sent"})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Reset password (POST request) - accepts OTP and new password


@router.post("/reset-password")
async def reset_password(email: str, otp: str, new_password: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Reset password logic (verify OTP and update password)
        await user_manager.reset_password(email, otp, new_password)
        return success({"message": "Password reset successful"})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Update password (POST request) - update password after login


@router.post("/update-password")
async def update_password(email: str, old_password: str, new_password: str, user_manager: UserManager = Depends(get_user_manager)):
    try:
        # Update password logic (verify old password and change to new one)
        await user_manager.update_password(email, old_password, new_password)
        return success({"message": "Password updated successfully"})
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
