import os

from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

# Constants
DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
DEBUG = os.getenv("DEBUG", "False").lower() in ["true", "1", "yes"]
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
FRONT_URL = os.getenv("FRONT_URL", "http://*")

# Apple Sign In Configuration
APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID")
APPLE_TEAM_ID = os.getenv("APPLE_TEAM_ID")
APPLE_KEY_ID = os.getenv("APPLE_KEY_ID")

# Export all constants as a dictionary for other modules if needed
ALL_CONSTANTS = {
    "DATABASE_URL": DATABASE_URL,
    "DATABASE_NAME": DATABASE_NAME,
    "SECRET_KEY": SECRET_KEY,
    "DEBUG": DEBUG,
    "EMAIL_HOST": EMAIL_HOST,
    "EMAIL_PORT": EMAIL_PORT,
    "FRONT_URL": FRONT_URL,
    "APPLE_CLIENT_ID": APPLE_CLIENT_ID,
    "APPLE_TEAM_ID": APPLE_TEAM_ID,
    "APPLE_KEY_ID": APPLE_KEY_ID,
}
