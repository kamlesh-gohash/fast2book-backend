# app/v1/middleware/auth.py

from fastapi import Request, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.v1.config.auth import oauth
from fastapi import Depends
from app.v1.models import User
from app.v1.config.auth import oauth
import os

# OAuth2PasswordBearer handles the token extraction from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    """Get the current authenticated user from the OAuth token."""
    try:
        # Extract user information from the token
        user_info = await oauth.google.parse_id_token(request, token)
        user = await User.get_user_by_email(user_info["email"])
        return user
    except Exception as e:
        raise HTTPException(status_code=401, detail="Unauthorized")


def check_access_to_route(current_user: User, required_role: str):
    """Access control for users based on their role (e.g., admin, user)."""
    if current_user.role != required_role:
        raise HTTPException(status_code=403, detail="Access denied")
