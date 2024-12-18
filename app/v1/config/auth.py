# app/v1/config/auth.py

import os
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize OAuth
oauth = OAuth()


def init_oauth(app):
    # Google OAuth configuration
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        access_token_url='https://oauth2.googleapis.com/token',
        refresh_token_url='https://oauth2.googleapis.com/token',
        client_kwargs={'scope': 'openid profile email'},
        fetch_token=None,
    )
