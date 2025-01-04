# app/v1/middleware/auth.py

import os

from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from app.v1.config.auth import oauth
from app.v1.models import User


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


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    """Get the current authenticated user from the JWT token."""
    try:

        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Extract email from the token's payload
        email = payload.get("sub")  # Ensure the token contains a 'sub' claim for email
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token: Missing 'sub' claim.")

        # Fetch the user from the database
        user = await User.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        return user
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


async def get_token_from_header(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided")

    # The token should be in the format 'Bearer <token>'
    token_prefix = "Bearer "
    if not authorization.startswith(token_prefix):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    token = authorization[len(token_prefix) :]
    return token
