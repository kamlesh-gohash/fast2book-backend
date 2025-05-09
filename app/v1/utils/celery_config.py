import os

import razorpay

from bson import ObjectId
from celery import Celery
from pymongo import MongoClient

from app.v1.models import vendor_collection


RAZOR_PAY_KEY_ID = os.getenv("RAZOR_PAY_KEY_ID")
RAZOR_PAY_KEY_SECRET = os.getenv("RAZOR_PAY_KEY_SECRET")
razorpay_client = razorpay.Client(auth=(RAZOR_PAY_KEY_ID, RAZOR_PAY_KEY_SECRET))
# Initialize MongoDB client (replace with your connection string)
# mongo_client = MongoClient("mongodb://localhost:27017")
# db = mongo_client["your_database"]  # Replace with your database name
# vendor_collection = db["vendors"]  # Replace with your collection name

# Initialize Celery
celery_app = Celery("tasks", broker="redis://localhost:6379/0", backend="redis://localhost:6379/0")

# Configure Celery
celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task
def update_vendor_subscription_status(vendor_id: str):
    """Update vendor subscription status when billing cycle ends."""
    try:
        result = vendor_collection.update_one(
            {"_id": ObjectId(vendor_id)},
            {"$set": {"razorpay_subscription_id": None, "is_subscription": False, "manage_plan": None}},
        )
    except Exception as ex:
        print(f"Error updating vendor {vendor_id}: {str(ex)}")


@celery_app.task
def pause_vendor_subscription(vendor_id: str, subscription_id: str):
    """Pause vendor subscription at billing cycle end."""
    try:
        razorpay_client.subscription.pause(subscription_id, data={"pause_at": "now"})

        # Update vendor in MongoDB
        result = vendor_collection.update_one(
            {"_id": ObjectId(vendor_id)},
            {
                "$set": {
                    "is_subscription": False,
                }
            },
        )
        print(f"Paused vendor {vendor_id} subscription: {result.modified_count} documents")
    except Exception as ex:
        print(f"Error pausing vendor {vendor_id} subscription: {str(ex)}")


@celery_app.task
def resume_vendor_subscription(vendor_id: str, subscription_id: str):
    """Resume vendor subscription at billing cycle end."""
    try:
        razorpay_client.subscription.resume(subscription_id, data={"resume_at": "now"})

        # Update vendor in MongoDB
        result = vendor_collection.update_one(
            {"_id": ObjectId(vendor_id)},
            {
                "$set": {
                    "is_subscription": True,
                }
            },
        )
        print(f"Resumed vendor {vendor_id} subscription: {result.modified_count} documents")
    except Exception as ex:
        print(f"Error resuming vendor {vendor_id} subscription: {str(ex)}")
    """Resume vendor subscription at billing cycle end."""
    try:
        razorpay_client.subscription.resume(subscription_id, data={"resume_at": "now"})

        # Update vendor in MongoDB
        result = vendor_collection.update_one(
            {"_id": ObjectId(vendor_id)},
            {
                "$set": {
                    "is_subscription": True,
                }
            },
        )
        print(f"Resumed vendor {vendor_id} subscription: {result.modified_count} documents")
    except Exception as ex:
        print(f"Error resuming vendor {vendor_id} subscription: {str(ex)}")
