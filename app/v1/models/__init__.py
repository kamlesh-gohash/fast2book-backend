from app.v1.models.user import User
from app.v1.config import DATABASE_NAME, DATABASE_URL
from motor.motor_asyncio import AsyncIOMotorClient
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.subscription import Subscription

def get_model(COLLECTION_NAME):
    client = AsyncIOMotorClient(DATABASE_URL)
    db = client[DATABASE_NAME]
    return db[COLLECTION_NAME]


user_collection = get_model("users")
category_collection = get_model("categories")
services_collection = get_model("services")
vendor_collection = get_model("vendors")
subscription_collection = get_model("subscriptions")


__all__ = {
    "user_collection": user_collection,
    "category_collection":category_collection,
    "services_collection":services_collection,
    "vendor_collection":vendor_collection,
    "subscription_collection":subscription_collection
}
