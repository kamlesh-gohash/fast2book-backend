from motor.motor_asyncio import AsyncIOMotorClient

from app.v1.config import DATABASE_NAME, DATABASE_URL
from app.v1.models.blog import Blog
from app.v1.models.booking import Bookings
from app.v1.models.category import Category
from app.v1.models.services import Service
from app.v1.models.subscription import Subscription
from app.v1.models.user import User
from app.v1.models.user_token import UserToken


def get_model(COLLECTION_NAME):
    client = AsyncIOMotorClient(DATABASE_URL)
    db = client[DATABASE_NAME]
    return db[COLLECTION_NAME]


user_collection = get_model("users")
category_collection = get_model("categories")
services_collection = get_model("services")
vendor_collection = get_model("vendors")
subscription_collection = get_model("subscriptions")
blog_collection = get_model("blogs")
user_token_collection = get_model("user_tokens")
booking_collection = get_model("bookings")
slots_collection = get_model("slots")
payment_collection = get_model("payments")
support_collection = get_model("supports")
permission_collection = get_model("permissions")
permission_assign_request = get_model("permission_assign_request")
plan_collection = get_model("plans")
booking_payments_collection = get_model("booking_payments")
vendor_services_collection = get_model("vendor_services")
vendor_ratings_collection = get_model("vendor_ratings")
video_collection = get_model("videos")
ticket_collection = get_model("tickets")
vendor_query_collection = get_model("vendor_queries")


__all__ = {
    "user_collection": user_collection,
    "category_collection": category_collection,
    "services_collection": services_collection,
    "vendor_collection": vendor_collection,
    "subscription_collection": subscription_collection,
    "blog_collection": blog_collection,
    "user_token_collection": user_token_collection,
    "booking_collection": booking_collection,
    "slots_collection": slots_collection,
    "payment_collection": payment_collection,
    "support_collection": support_collection,
    "permission_collection": permission_collection,
    "permission_assign_request": permission_assign_request,
    "plan_collection": plan_collection,
    "booking_payments_collection": booking_payments_collection,
    "vendor_services_collection": vendor_services_collection,
    "vendor_ratings_collection": vendor_ratings_collection,
    "video_collection": video_collection,
    "ticket_collection": ticket_collection,
    "vendor_query_collection": vendor_query_collection,
}
