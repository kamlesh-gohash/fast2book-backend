# app/v1/middleware/auth.py

import os

from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from app.v1.config.auth import oauth
from app.v1.models import User
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2 import id_token
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
            
            # Verify the Google ID token
            id_info = id_token.verify_oauth2_token(google_token, requests.Request(), GOOGLE_CLIENT_ID)
            
            # Validate the issuer
            if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
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
    except GoogleAuthError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")
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
