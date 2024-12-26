from fastapi import APIRouter, Depends, HTTPException, status
from app.v1.dependencies import get_super_user_manager
from app.v1.services import SuperUserManager
from app.v1.models import User
from app.v1.utils.response.response_format import success, failure, internal_server_error, validation_error
from app.v1.schemas.superuser.superuser_auth import SuperUserSignInRequest, SuperUserForgotPasswordRequest,SuperUserOtpRequest,SuperUserResetPasswordRequest,SuperUserResendOtpRequest,SuperUserProfileRequest,SuperUserChangePassword,SuperUserCreateRequest

router = APIRouter()


@router.post("/sign-in", status_code=status.HTTP_200_OK)
async def sign_in(super_user_sign_in_request: SuperUserSignInRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_sign_in_request.validate()
    if validation_result:
        return validation_result
    try:
        # Superuser sign-in logic
        result = await user_manager.super_user_sign_in(
            super_user_sign_in_request.email, 
            super_user_sign_in_request.password
        )
        return success({"message": "Superuser logged in successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_401_UNAUTHORIZED)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.post("/forget-password", status_code=status.HTTP_200_OK)
async def forget_password(super_user_forgot_password_request: SuperUserForgotPasswordRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_forgot_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Forget password logic
        await user_manager.super_user_forget_password(super_user_forgot_password_request.email)
        return success({"message": "OTP sent successfully", "data": None})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        print(http_ex,'aaaaaaaaaaaaaaa')
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        print(ex)
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)    
    
@router.post("/otp-verify", status_code=status.HTTP_200_OK)
async def otp_verify(super_user_otp_request: SuperUserOtpRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_otp_request.validate()
    if validation_result:
        return validation_result
    try:
        # OTP verification logic
        result = await user_manager.super_user_otp_verify(
            super_user_otp_request.email, 
            super_user_otp_request.otp
        )
        return success({"message": "OTP verified successfully", "data": result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(super_user_reset_password_request: SuperUserResetPasswordRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_reset_password_request.validate()
    if validation_result:
        return validation_result
    try:
        # Reset password logic
        await user_manager.super_user_reset_password(
            super_user_reset_password_request.email, 
            super_user_reset_password_request.password
        )
        return success({"message": "Password reset successful"})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response       
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error(
            {"message": "An unexpected error occurred", "error": str(ex)}, 
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )    
    
@router.post("/resend-otp", status_code=status.HTTP_200_OK)
async def resend_otp(super_user_resend_otp_request: SuperUserResendOtpRequest, user_manager: SuperUserManager = Depends(get_super_user_manager)):
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
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)  
    
@router.get("/super_user_profile", status_code=status.HTTP_200_OK)    
async def get_profile(super_user_profile_request: SuperUserProfileRequest,user_manager: SuperUserManager = Depends(get_super_user_manager)):
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
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.put("/update_super_user_profile", status_code=status.HTTP_200_OK)    
async def update_profile(super_user_profile_update_request: User,user_manager: SuperUserManager = Depends(get_super_user_manager)):
    try:
        result = await user_manager.update_super_user_profile(super_user_profile_update_request)
        return success({"message":"profile updated successfully","data":result})
    except HTTPException as http_ex:
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.post("/change_super_user_password",status_code=status.HTTP_200_OK)    
async def change_password(super_user_change_password_request:SuperUserChangePassword,user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_change_password_request.validate()
    if validation_result:
        return validation_result
    
    try:
        result = await user_manager.change_super_user_password(email=super_user_change_password_request.email,
            old_password=super_user_change_password_request.old_password,
            new_password=super_user_change_password_request.new_password,)
        return success({"message":"Super user password change Successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@router.post("/create_super_user", status_code=status.HTTP_200_OK)    
async def create_super_user(super_user_create_request:SuperUserCreateRequest,user_manager: SuperUserManager = Depends(get_super_user_manager)):
    validation_result = super_user_create_request.validate()
    if validation_result:
        return validation_result
    try:
        result = await user_manager.create_super_user(super_user_create_request)
        return success({"message":"Super user created Successfully","data":result})
    except HTTPException as http_ex:
        # Explicitly handle HTTPException and return its response
        return failure({"message": http_ex.detail, "data": None}, status_code=http_ex.status_code)
    except ValueError as ex:
        return failure({"message": str(ex)}, status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as ex:
        print(ex)
        return internal_server_error({"message": "An unexpected error occurred", "error": str(ex)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)