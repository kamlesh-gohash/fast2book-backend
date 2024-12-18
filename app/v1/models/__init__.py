from app.v1.models.user import User
from app.v1.config import DATABASE_NAME, DATABASE_URL
from motor.motor_asyncio import AsyncIOMotorClient


def get_model(COLLECTION_NAME):
    client = AsyncIOMotorClient(DATABASE_URL)
    db = client[DATABASE_NAME]
    return db[COLLECTION_NAME]


user_collection = get_model("users")

__all__ = {
    "user_collection": user_collection
}
