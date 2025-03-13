# app/v1/middleware/auth.py

import os

from typing import Optional

import httpx

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2 import id_token

from app.v1.config.auth import oauth
from app.v1.models import User, user_collection
from app.v1.models.user import *
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


# OAuth2PasswordBearer handles the token extraction from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
#     """Get the current authenticated user from the OAuth token."""
#     try:
#         # Extract user information from the token
#         print(token,"token in request")
#         user_info = await oauth.google.parse_id_token(request, token)
#         print(user_info,'user info')
#         user = await User.get_user_by_email(user_info["email"])
#         print(user,'user')
#         return user
#     except Exception as e:
#         raise HTTPException(status_code=401, detail="Unauthorized")

import jwt  # PyJWT library

from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


def check_access_to_route(current_user: User, required_role: str):
    """Access control for users based on their role (e.g., admin, user)."""
    if current_user.role != required_role:
        raise HTTPException(status_code=403, detail="Access denied")


SECRET_KEY = os.getenv("SECRET_KEY")  # Use the same secret key that signs the JWT
ALGORITHM = "HS256"  # Ensure this matches the algorithm used to sign the token


# async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
#     """Get the current authenticated user from the JWT token."""
#     try:

#         # Decode the token
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         # Extract email from the token's payload
#         email = payload.get("sub")  # Ensure the token contains a 'sub' claim for email
#         if not email:
#             raise HTTPException(status_code=401, detail="Invalid token: Missing 'sub' claim.")

#         # Fetch the user from the database
#         user = await User.get_user_by_email(email)
#         if not user:
#             raise HTTPException(status_code=404, detail="User not found.")

#         return user
#     except ExpiredSignatureError:
#         raise HTTPException(status_code=401, detail="Token has expired.")
#     except InvalidTokenError as e:
#         raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail="Internal server error")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    """Get the current authenticated user from either a JWT token or a Google ID token."""
    try:
        # Check if the token is a Google ID token
        if token.startswith("google_"):
            # Extract the actual Google ID token
            google_token = token.replace("google_", "")
            id_info = id_token.verify_oauth2_token(google_token, requests.Request(), GOOGLE_CLIENT_ID)
            # Validate the issuer
            if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
                raise HTTPException(status_code=401, detail="Invalid Google token issuer.")

            # Extract email from Google ID token
            email = id_info.get("email")
            if not email:
                raise HTTPException(status_code=401, detail="Invalid Google token: Missing email.")

            # Fetch or create the user in your database
            user = await User.get_user_by_email(email)
            if not user:
                # Create a new user if they don't exist
                user = await User.create_user(
                    email=email,
                    name=id_info.get("name"),
                    picture=id_info.get("picture"),
                    provider="google",
                )

            return user

        else:
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
                }
                result = await user_collection.insert_one(user)
                user_id = str(result.inserted_id)  # Convert ObjectId to string
                user["id"] = user_id  # Add _id as a string to the response
            else:
                # Update the user if they already exist
                await user_collection.update_one(
                    {"email": email},
                    {"$set": {"first_name": first_name, "last_name": last_name, "picture": picture}},
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


async def get_token_from_header(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided")

    # The token should be in the format 'Bearer <token>'
    token_prefix = "Bearer "
    if not authorization.startswith(token_prefix):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    token = authorization[len(token_prefix) :]
    return token
