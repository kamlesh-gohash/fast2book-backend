import jwt

from datetime import datetime, timedelta
import os
from fastapi import HTTPException, status
from app.v1.config.auth import oauth

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"  # You can use other algorithms like RS256 if you want
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 2
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24


async def get_oauth_tokens(user) -> dict:
    """
    Get OAuth tokens for the user (Google OAuth in this case).
    """
    try:
        # Assuming the user has the authorization code (stored previously)
        oauth_client = oauth.create_client("google")

        if oauth_client is None:
            raise HTTPException(status_code=500, detail="Google OAuth client not initialized.")

        # Fetch token using the authorization code
        token = await oauth_client.fetch_token(
            "https://oauth2.googleapis.com/token",
            authorization_response=user.oauth_authorization_code,  # This should be saved previously
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        )

        return {"access_token": token["access_token"], "refresh_token": token["refresh_token"]}
    except Exception as ex:
        raise HTTPException(status_code=500, detail="Failed to retrieve OAuth tokens: " + str(ex))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Function to create refresh token
def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
