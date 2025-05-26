# app/v1/middleware/auth.py

import os

from typing import Optional

import httpx

from bson import ObjectId  # Import ObjectId to work with MongoDB IDs
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2 import id_token

from app.v1.config.auth import oauth
from app.v1.models import User, user_collection
from app.v1.models.user import *
from app.v1.utils.response.response_format import unauthorized
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


# OAuth2PasswordBearer handles the token extraction from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

import jwt  # PyJWT library

from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


def check_access_to_route(current_user: User, required_role: str):
    """Access control for users based on their role (e.g., admin, user)."""
    if current_user.role != required_role:
        raise HTTPException(status_code=403, detail="Access denied")


SECRET_KEY = os.getenv("SECRET_KEY")  # Use the same secret key that signs the JWT
ALGORITHM = "HS256"  # Ensure this matches the algorithm used to sign the token

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get the current authenticated user from either a JWT token or a Google ID token."""
    try:
        # Handle JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")

        if not sub:
            raise HTTPException(status_code=401, detail="Invalid token: Missing 'sub' claim.")
        sub = str(sub).strip()
        # Try to fetch user by email or phone
        user = None
        if "@" in sub:
            user = await User.get_user_by_email(sub)
            if not user:
                raise HTTPException(status_code=404, detail="User not found by email.")
        elif sub.isdigit():
            user = await User.get_user_by_phone(sub)
            if not user:
                raise HTTPException(status_code=404, detail="User not found by phone.")
        else:
            raise HTTPException(status_code=401, detail="Invalid token: 'sub' is neither email nor phone.")

        return user

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")

    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except GoogleAuthError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


async def get_current_user_by_google(
    request: Request,
    token: str,
    email: str,
    first_name: str,
    last_name: str,
    picture: str,
    device_token: Optional[str] = None,
    web_token: Optional[str] = None,
):
    """Get the current authenticated user from a Google OAuth access token."""
    try:

        # Use the Google tokeninfo endpoint to validate the OAuth access token
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}")
            token_info = response.json()

            # Check for errors in the response
            if "error" in token_info:
                raise HTTPException(status_code=401, detail="Invalid Google OAuth access token.")

            # Validate the email in the token info
            token_email = token_info.get("email")
            if not token_email or token_email != email:
                raise HTTPException(status_code=401, detail="Invalid Google token: Email mismatch.")

            # Fetch or create the user in your database
            user = await user_collection.find_one({"email": email})
            if not user:
                # Create a new user if they don't exist
                user = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "picture": picture,
                    "provider": "google",
                    "is_active": True,
                    "status": "active",
                    "roles": ["user"],
                    "notification_settings": DEFAULT_NOTIFICATION_PREFERENCES,
                    "device_token": device_token,
                    "web_token": web_token,
                    "created_at": datetime.utcnow(),
                }
                result = await user_collection.insert_one(user)
                user_id = str(result.inserted_id)  # Convert ObjectId to string
                user["id"] = user_id  # Add _id as a string to the response
            else:
                # Update the user if they already exist
                await user_collection.update_one(
                    {"email": email},
                    {
                        "$set": {
                            "first_name": first_name,
                            "last_name": last_name,
                            "picture": picture,
                            "web_token": web_token,
                            "device_token": device_token,
                        }
                    },
                )

            # Remove sensitive fields
            user.pop("password", None)
            user.pop("otp", None)
            user["id"] = str(user["_id"])
            user.pop("_id", None)

            # Generate access and refresh tokens
            access_token = create_access_token(data={"sub": email})
            refresh_token = create_refresh_token(data={"sub": email})

            return {
                "user_data": user,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }

    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate Google token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


async def get_current_user_by_apple(
    request: Request,
    token: str,
    email: str,
    first_name: str,
    last_name: str,
    picture: str,
    apple_user_id: str,
    device_token: Optional[str] = None,
    web_token: Optional[str] = None,
):
    """Get the current authenticated user from an Apple Sign In token."""
    try:
        # Fetch or create the user in your database using Apple ID
        user = await user_collection.find_one({"apple_id": apple_user_id})

        if not user:
            # If user doesn't exist with Apple ID, check by email
            user = await user_collection.find_one({"email": email})

            if not user:
                # Create a new user if they don't exist
                user = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "picture": picture,
                    "provider": "apple",
                    "apple_id": apple_user_id,
                    "is_active": True,
                    "status": "active",
                    "roles": ["user"],
                    "notification_settings": DEFAULT_NOTIFICATION_PREFERENCES,
                    "device_token": device_token,
                    "web_token": web_token,
                    "created_at": datetime.utcnow(),
                }
                result = await user_collection.insert_one(user)
                user["id"] = str(result.inserted_id)
            else:
                # Update existing user with Apple ID
                await user_collection.update_one(
                    {"email": email},
                    {
                        "$set": {
                            "apple_id": apple_user_id,
                            "first_name": first_name,
                            "last_name": last_name,
                            "picture": picture,
                            "provider": "apple",
                            "web_token": web_token,
                            "device_token": device_token,
                            "is_active": True,
                            "status": "active",
                        }
                    },
                )
                user = await user_collection.find_one({"email": email})
        else:
            # Update the user if they already exist with Apple ID
            await user_collection.update_one(
                {"apple_id": apple_user_id},
                {
                    "$set": {
                        "first_name": first_name,
                        "last_name": last_name,
                        "picture": picture,
                        "web_token": web_token,
                        "device_token": device_token,
                    }
                },
            )
            user = await user_collection.find_one({"apple_id": apple_user_id})

        if not user:
            raise HTTPException(status_code=404, detail="User not found after creation/update")

        if user.get("status") != "active":
            raise HTTPException(status_code=401, detail="User account is not active")

        # Create tokens
        access_token = create_access_token(data={"sub": user["email"]})
        refresh_token = create_refresh_token(data={"sub": user["email"]})

        # Format the response
        user_data = user.copy()
        user_data["id"] = str(user_data["_id"])
        user_data.pop("_id", None)
        user_data.pop("password", None)

        return {"user_data": user_data, "access_token": access_token, "refresh_token": refresh_token}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Authentication error: {str(e)}")


async def get_token_from_header(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided")

    # The token should be in the format 'Bearer <token>'
    token_prefix = "Bearer "
    if not authorization.startswith(token_prefix):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    token = authorization[len(token_prefix) :]
    return token


async def check_permission(request: Request, menu_id: str, action: str):
    # Extract the token from the Authorization header
    token = await get_token_from_header(request.headers.get("Authorization"))
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Get the current user using the token
    current_user = await get_current_user(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Check if the user has the required permissions
    menu_item = next((menu for menu in current_user.menu if menu["id"] == menu_id), None)
    if not menu_item or not menu_item["actions"].get(action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action.",
        )


from starlette.middleware.base import BaseHTTPMiddleware


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for certain paths (e.g., login, docs, etc.)
        normalized_path = request.url.path.rstrip("/")

        # Skip authentication for certain paths (e.g., login, docs, etc.)
        if normalized_path in ["/v1/vendor/sign-in", "/docs", "/openapi.json"]:
            return await call_next(request)

        # Get the token from the header
        authorization = request.headers.get("Authorization")
        if not authorization:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Token not provided"},
            )

        # Extract the token from the 'Bearer <token>' format
        token_prefix = "Bearer "
        if not authorization.startswith(token_prefix):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid token format"},
            )

        token = authorization[len(token_prefix) :]

        # Validate the token and get the current user
        try:
            current_user = await get_current_user(request, token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Attach the user to the request state
            request.state.user = current_user
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"message": e.detail},
            )
        except Exception as e:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "An unexpected error occurred"},
            )

        # Proceed to the next middleware or route handler
        return await call_next(request)


async def get_current_user_optional(token: Optional[str] = Depends(oauth2_scheme)) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        user = await user_collection.find_one({"email": str(user_id)})
        if user is None:
            return None
        return User(**user)
    except (ExpiredSignatureError, Exception):
        return None
