import asyncio
import random
import uuid

from datetime import datetime, timedelta
from typing import Any, Optional

import bcrypt
import pytz
import razorpay.errors

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import BackgroundTasks, Body, HTTPException, Query, Request, status
from pytz import timezone

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    booking_collection,
    category_collection,
    notification_collection,
    payment_collection,
    services_collection,
    slots_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.booking import *
from app.v1.models.transfer_amount import TransferAmount
from app.v1.models.user import User
from app.v1.schemas.booking.booking import CancelBookingRequest, CreateBookingRequest
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.notification import send_push_notification
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


razorpay_client = razorpay.Client(auth=(os.getenv("RAZOR_PAY_KEY_ID"), os.getenv("RAZOR_PAY_KEY_SECRET")))


def convert_objectids_to_strings(data):
    if isinstance(data, dict):
        return {key: convert_objectids_to_strings(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_objectids_to_strings(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data


def convert_objectid_to_str(data):
    """Recursively convert ObjectId to string in a dictionary or list."""
    if isinstance(data, dict):
        return {k: convert_objectid_to_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_objectid_to_str(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data


def convert_object_ids(data: Any) -> Any:
    """Recursively convert ObjectId to string in nested data structures"""
    if isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, dict):
        return {key: convert_object_ids(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_object_ids(item) for item in data]
    return data


class BookingManager:

    async def book_appointment(
        self,
        current_user: User,
        booking_date: str = Query(..., description="Booking date in YYYY-MM-DD format"),
        slot: str = Query(..., description="Time slot in 'HH:MM - HH:MM' format"),
        vendor_id: str = Query(..., description="Vendor ID"),
        service_id: str = Query(..., description="Service ID"),
        vendor_user_id: Optional[str] = Query(None, description="Vendor User ID (optional)"),  # New optional parameter
    ):
        try:
            # Fetch vendor details
            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # Fetch category details
            category_id = vendor.get("category_id")
            category = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            # Fetch service details
            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            # Fetch vendor user details
            if (
                vendor_user_id and vendor_user_id.lower() != "null"
            ):  # If vendor_user_id is provided, fetch that specific user
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            else:  # Default to the vendor's primary user
                if vendor["business_type"] == "business":
                    vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
                else:
                    vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor["_id"])})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            # Get the vendor user's fees
            amount = vendor_user.get("fees", 0.0)  # Default to 0.0 if fees is None
            if not isinstance(amount, (int, float)):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fees value")

            # Fetch payment configuration
            payment_method = "Razorpay"
            payment_config = await payment_collection.find_one({"name": payment_method})
            if not payment_config:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment configuration not found")

            admin_charge_type = payment_config.get("charge_type")  # 'percentage' or 'fixed'
            admin_charge_value = payment_config.get("charge_value")  # e.g., 10 for 10% or 50 for $50

            # Calculate admin charge
            if admin_charge_type == "percentage":
                admin_charge = (admin_charge_value / 100) * amount
            elif admin_charge_type == "fixed":
                admin_charge = admin_charge_value
            else:
                admin_charge = 0.0

            # Calculate total amount
            total_amount = amount + admin_charge

            # Prepare response data
            response_data = {
                "vendor": {
                    "id": str(vendor.get("_id")),
                    "business_name": vendor.get("business_name"),
                    "name": vendor_user.get("first_name"),
                    "last_name": vendor_user.get("last_name"),
                    "fees": str(amount),  # Convert float to string
                    "location": vendor.get("location"),
                    "specialization": vendor_user.get("specialization"),
                    "user_image": vendor_user.get("user_image", ""),
                    "user_image_url": vendor_user.get("user_image_url", ""),
                    "is_payment_required": vendor.get("is_payment_required", False),
                },
                "category": {
                    "id": str(category.get("_id")),
                    "name": category.get("name"),
                },
                "service": {
                    "id": str(service.get("_id")),
                    "name": service.get("name"),
                },
                "booking_date": booking_date,
                "time_slot": slot,
                "platform_fee": str(admin_charge),  # Convert float to string
                "total_amount": str(total_amount),  # Convert float to string
                "vendor_user_id": str(vendor_user.get("_id")) if vendor_user else None,
            }

            return response_data

        except HTTPException as http_ex:
            raise http_ex
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(ex)}",
            )

    def get_vendor_slots(self, vendor_user, date):
        """
        Extracts and filters available slots for the given vendor and date.
        """
        for availability in vendor_user.get("availability_slots", []):
            if availability["day"].lower() == self.get_weekday(date).lower():
                return availability["time_slots"]
        return []

    def is_slot_available(self, available_slots, requested_slot):
        """
        Checks if the requested slot matches any available slots.
        """
        for slot in available_slots:
            if (
                slot["start_time"] == requested_slot["start_time"]
                and slot["end_time"] == requested_slot["end_time"]
                # and slot["duration"] == requested_slot["duration"]
            ):
                return True
        return False

    def get_weekday(self, date):
        """
        Returns the day of the week for a given date.
        """
        return datetime.strptime(date, "%Y-%m-%d").strftime("%A")

    async def user_booking_checkout(self, current_user: User, id: str):
        try:
            current_user_id = str(current_user.id)
            booking_id = str(id)
            booking_details = await booking_collection.find_one(
                {"_id": ObjectId(booking_id), "user_id": ObjectId(current_user_id)}
            )
            if not booking_details:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            vendor = await vendor_collection.find_one({"_id": ObjectId(booking_details["vendor_id"])})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            user_id = str(vendor.get("user_id"))
            user_name = await user_collection.find_one({"_id": ObjectId(user_id)})

            category = await category_collection.find_one({"_id": ObjectId(booking_details["category_id"])})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            service = await services_collection.find_one({"_id": ObjectId(booking_details["service_id"])})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
            amount = booking_details["amount"]
            payment_method = "Razorpay"
            payment_config = await payment_collection.find_one({"name": payment_method})
            if not payment_config:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment configuration not found")

            admin_charge_type = payment_config.get("charge_type")  # 'percentage' or 'fixed'
            admin_charge_value = payment_config.get("charge_value")  # e.g., 10 for 10% or 50 for $50

            if admin_charge_type == "percentage":
                admin_charge = (admin_charge_value / 100) * amount
            elif admin_charge_type == "fixed":
                admin_charge = admin_charge_value
            else:
                admin_charge = 0

            total_amount = amount + admin_charge

            booking_data = {
                "id": str(booking_details["_id"]),
                "vendor": {
                    "id": str(vendor.get("_id")),
                    "business_name": vendor.get("business_name"),
                    "name": user_name.get("first_name"),
                    "last_name": user_name.get("last_name"),
                    "fees": vendor.get("fees", 0),
                    "location": vendor.get("location"),
                    "specialization": vendor.get("specialization"),
                    "is_payment_required": vendor.get("is_payment_required", False),
                },
                "category": {
                    "id": str(category.get("_id")),
                    "name": category.get("name"),
                },
                "service": {
                    "id": str(service.get("_id")),
                    "name": service.get("name"),
                },
                "booking_date": booking_details["booking_date"],
                "time_slot": booking_details["time_slot"],
                "status": booking_details["status"],
                "booking_status": booking_details["booking_status"],
                "payment_status": booking_details["payment_status"],
                "booking_order_id": booking_details["booking_order_id"],
                "amount": booking_details["amount"],
                "platform_fee": admin_charge,
                "total_amount": total_amount,
                "created_at": booking_details["created_at"],
            }

            return booking_data

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_list_for_vendor(
        self, current_user: User, search: str = None, start_date: str = None, end_date: str = None
    ):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user_id = str(current_user.vendor_id)
            vendor = await vendor_collection.find_one({"_id": ObjectId(user_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            query = {"vendor_id": ObjectId(vendor["_id"])}
            if start_date or end_date:
                date_filter = {}
                if start_date:
                    try:
                        datetime.strptime(start_date, "%Y-%m-%d")
                        date_filter["$gte"] = start_date
                    except ValueError:
                        raise HTTPException(
                            status_code=400, detail="Invalid start date format. Please use 'YYYY-MM-DD'"
                        )
                if end_date:
                    try:
                        datetime.strptime(end_date, "%Y-%m-%d")
                        date_filter["$lte"] = end_date
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid end date format. Please use 'YYYY-MM-DD'")
                if date_filter:
                    query["booking_date"] = date_filter
            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"user_name": search_regex},
                    {"service_name": search_regex},
                    {"business_name": search_regex},
                    {"category_name": search_regex},
                ]

            bookings = await booking_collection.find(query).to_list(None)
            if not bookings:
                return []

            # Process each booking
            for booking in bookings:
                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)
                booking["user_id"] = str(booking["user_id"])
                booking["vendor_id"] = str(booking["vendor_id"])
                booking["category_id"] = str(booking["category_id"])
                booking["service_id"] = str(booking["service_id"])

                # Fetch and enrich user details
                user = await user_collection.find_one({"_id": ObjectId(booking["user_id"])})
                if user:
                    booking["user_name"] = user.get("first_name")
                    booking["user_email"] = user.get("email")
                    booking["user_image"] = user.get("user_image")
                    booking["user_image_url"] = user.get("user_image_url")

                # Fetch and enrich vendor details
                vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
                if vendor:
                    booking["business_name"] = vendor.get("business_name")
                    booking["business_type"] = vendor.get("business_type")

                    # Fetch vendor user details
                    vendor_user = await user_collection.find_one({"vendor_id": ObjectId(booking["vendor_id"])})
                    if vendor.get("business_type") == "business" and vendor_user:
                        vendor_user = await user_collection.find_one({"created_by": str(vendor_user["_id"])})
                    if vendor_user:
                        booking["vendor_email"] = vendor_user.get("email")
                        booking["vendor_name"] = vendor_user.get("first_name")

                # Fetch and enrich category details
                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])})
                if category:
                    booking["category_name"] = category.get("name")

                # Fetch and enrich service details
                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])})
                if service:
                    booking["service_name"] = service.get("name")

            # Convert all ObjectId to strings recursively
            bookings = convert_objectid_to_str(bookings)
            return bookings

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_get_booking(self, current_user: User, id: str):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user_id = str(current_user.id)

            vendor = await vendor_collection.find_one({"user_id": user_id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            booking["id"] = str(booking["_id"])
            booking.pop("_id", None)
            booking["user_id"] = str(booking["user_id"])
            booking["vendor_id"] = str(booking["vendor_id"])
            booking["category_id"] = str(booking["category_id"])
            booking["service_id"] = str(booking["service_id"])

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def vendor_update_booking(self, request: Request, current_user: User, id: str):
        try:
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user_id = str(current_user.id)

            vendor = await vendor_collection.find_one({"user_id": user_id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            if str(vendor["_id"]) != str(booking["vendor_id"]):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            booking = await booking_collection.update_one({"_id": ObjectId(id)}, {"$set": request.json})

            booking["id"] = str(booking["_id"])
            booking.pop("_id", None)

            booking["user_id"] = str(booking["user_id"])
            booking["vendor_id"] = str(booking["vendor_id"])
            booking["category_id"] = str(booking["category_id"])
            booking["service_id"] = str(booking["service_id"])

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_list(self, current_user: User, status_filter: str = None):
        try:
            if "user" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            user_id = str(current_user.id)
            user = await user_collection.find_one({"_id": ObjectId(user_id)})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            user_timezone = user.get("timezone", "Asia/Kolkata")
            tz = pytz.timezone(user_timezone)

            current_datetime = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(tz)

            upcoming_bookings = []
            past_bookings = []

            bookings = await booking_collection.find({"user_id": user["_id"]}).to_list(None)

            for booking in bookings:
                if str(booking.get("payment_status", "")).lower() != "paid":
                    continue

                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)
                booking["user_id"] = str(booking.get("user_id"))
                booking["vendor_id"] = str(booking.get("vendor_id"))
                booking["category_id"] = str(booking.get("category_id"))
                booking["service_id"] = str(booking.get("service_id"))
                booking["vendor_user_id"] = str(booking.get("vendor_user_id"))

                # Handle category lookup
                category = await category_collection.find_one({"_id": ObjectId(booking.get("category_id"))})
                booking["category_name"] = category.get("name") if category else None

                # Handle service lookup
                service = await services_collection.find_one({"_id": ObjectId(booking.get("service_id"))})
                if service:
                    booking["service_name"] = service.get("name")
                    booking["service_image"] = service.get("service_image", "")
                    booking["service_image_url"] = service.get("service_image_url", "")
                else:
                    booking["service_name"] = None
                    booking["service_image"] = ""
                    booking["service_image_url"] = ""

                # Handle vendor and vendor_user lookup
                vendor = await vendor_collection.find_one({"_id": ObjectId(booking.get("vendor_id"))})
                vendor_user = await user_collection.find_one({"_id": ObjectId(booking.get("vendor_user_id"))})

                if vendor and vendor_user:
                    booking["vendor_first_name"] = vendor_user.get("first_name")
                    booking["vendor_last_name"] = vendor_user.get("last_name")
                    booking["vendor_email"] = vendor_user.get("email")
                    booking["vendor_phone"] = vendor_user.get("phone")
                    booking["user_image"] = vendor_user.get("user_image")
                    booking["user_image_url"] = vendor_user.get("user_image_url")
                    booking["vendor_location"] = vendor.get("location")
                    booking["specialization"] = vendor_user.get("specialization")
                    booking["business_name"] = vendor.get("business_name")
                else:
                    booking["vendor_first_name"] = None
                    booking["vendor_last_name"] = None
                    booking["vendor_email"] = None
                    booking["vendor_phone"] = None
                    booking["user_image"] = None
                    booking["user_image_url"] = None
                    booking["vendor_location"] = None
                    booking["specialization"] = None
                    booking["business_name"] = None

                # Safely parse time_slot with fallback
                time_slot = booking.get("time_slot", "")
                booking_datetime = None
                try:
                    start_time = time_slot.split("-")[0].strip() if "-" in time_slot else time_slot.strip()
                    if start_time and any(c.isdigit() for c in start_time):
                        booking_datetime = tz.localize(
                            datetime.strptime(booking["booking_date"] + " " + start_time, "%Y-%m-%d %I:%M %p")
                        )
                    else:
                        booking_datetime = tz.localize(datetime.strptime(booking["booking_date"], "%Y-%m-%d"))
                except (ValueError, IndexError) as e:
                    booking_datetime = tz.localize(datetime.strptime(booking["booking_date"], "%Y-%m-%d"))

                booking_status = booking.get("booking_status", "").lower()

                # Split into upcoming and past based on datetime
                if booking_datetime >= current_datetime and booking_status not in ["cancelled", "completed"]:
                    upcoming_bookings.append(booking)
                else:
                    # Include past bookings with any status, but filter by status_filter if provided
                    if status_filter:
                        if booking_status == status_filter.lower() and booking_status in [
                            "completed",
                            "cancelled",
                            "pending",
                        ]:
                            past_bookings.append(booking)
                    else:
                        # Include all past bookings regardless of status
                        past_bookings.append(booking)

            def sort_by_date(bookings_list):
                return sorted(bookings_list, key=lambda x: x.get("booking_date", "") or "", reverse=True)

            upcoming_bookings = sort_by_date(upcoming_bookings)
            past_bookings = sort_by_date(past_bookings)

            return {"upcoming_bookings": upcoming_bookings, "past_bookings": past_bookings}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def cancel_booking(
        self, current_user: User, id: str, cancel_request: CancelBookingRequest, background_tasks: BackgroundTasks
    ):
        try:
            if "user" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user_id = str(current_user.id)

            user = await user_collection.find_one({"_id": ObjectId(user_id)})
            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            cancellation_data = {
                "booking_status": "cancelled",
                "booking_cancel_reason": cancel_request.reason,
                "cancelled_at": datetime.utcnow(),
            }
            update_result = await booking_collection.update_one({"_id": ObjectId(id)}, {"$set": cancellation_data})

            service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
            vendor_user = await user_collection.find_one({"_id": ObjectId(booking["vendor_user_id"])})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor_user_obj = await user_collection.find_one({"vendor_id": ObjectId(booking["vendor_id"])})
            if not vendor_user_obj:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            source = "Booking Cancelled"
            context = {
                "user_id": user_id,
                "user_name": user.get("first_name") + " " + user.get("last_name"),
                "booking_status": "cancelled",
                "reason": cancel_request.reason,
                "service_name": service.get("service_name"),
                "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                "booking_date": booking.get("booking_date"),
            }

            background_tasks.add_task(send_email, to_email=vendor_user.get("email"), source=source, context=context)
            source = "Booking Cancelled Vendor"
            context = {
                "user_id": user_id,
                "user_name": user.get("first_name") + " " + user.get("last_name"),
                "booking_status": "cancelled",
                "reason": cancel_request.reason,
                "service_name": service.get("service_name"),
                "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                "booking_date": booking.get("booking_date"),
                "time_slot": booking.get("time_slot"),
            }

            background_tasks.add_task(
                send_email,
                to_email=vendor_user.get("email"),
                source=source,
                context=context,
                cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
            )

            # Handle notifications for the user
            subscriptions = []
            device_token = current_user.device_token
            web_token = current_user.web_token
            if device_token:
                subscriptions.append(device_token)
            if web_token:
                subscriptions.append(web_token)

            if subscriptions:
                background_tasks.add_task(
                    send_push_notification,
                    subscriptions=subscriptions,
                    title="Booking Cancelled",
                    body=f"Your booking with {vendor_user.get('first_name')} {vendor_user.get('last_name')} has been Cancelled.",
                    data={"booking_id": str(booking["_id"]), "type": "booking_cancelled"},
                    api_type="booking",
                )
                await notification_collection.insert_one(
                    {
                        "user_id": current_user.id,
                        "message_title": "Booking Cancelled",
                        "message": f"Your booking with {vendor_user.get('first_name')} {vendor_user.get('last_name')} has been Cancelled.",
                        "user_image_url": vendor_user.get("user_image_url"),
                        "seen": False,
                        "sent": True,
                        "created_at": datetime.now(),
                    }
                )

            # Handle notifications for the vendor
            subscriptions = []
            vendor_device_token = vendor_user_obj.get("device_token")
            vendor_web_token = vendor_user_obj.get("web_token")
            if vendor_device_token:
                subscriptions.append(vendor_device_token)
            if vendor_web_token:
                subscriptions.append(vendor_web_token)

            if subscriptions:
                background_tasks.add_task(
                    send_push_notification,
                    subscriptions=subscriptions,
                    title="Booking Cancelled",
                    body=f"Your booking with {current_user.first_name} {current_user.last_name} has been Cancelled.",
                    data={"booking_id": str(booking["_id"]), "type": "booking_cancelled"},
                    api_type="booking",
                )
                await notification_collection.insert_one(
                    {
                        "user_id": vendor_user_obj.get("id"),
                        "message_title": "Booking Cancelled",
                        "message": f"Your booking with {current_user.first_name} {current_user.last_name} has been Cancelled.",
                        "user_image_url": current_user.user_image_url,
                        "seen": False,
                        "sent": True,
                        "created_at": datetime.now(),
                    }
                )

            return {"reason": cancel_request.reason}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_list_for_admin(
        self,
        current_user: User,
        search: str = None,
        role: str = "vendor",
        start_date: str = None,
        end_date: str = None,
    ) -> Dict[str, Any]:
        try:
            # Check admin permissions
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            # Build query
            query = {}

            # Date filter
            if start_date or end_date:
                date_filter = {}
                if start_date:
                    try:
                        datetime.strptime(start_date, "%Y-%m-%d")
                        date_filter["$gte"] = start_date
                    except ValueError:
                        raise HTTPException(
                            status_code=400, detail="Invalid start date format. Please use 'YYYY-MM-DD'"
                        )
                if end_date:
                    try:
                        datetime.strptime(end_date, "%Y-%m-%d")
                        date_filter["$lte"] = end_date
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid end date format. Please use 'YYYY-MM-DD'")
                if date_filter:
                    query["booking_date"] = date_filter

            # Search filter
            if search:
                search = search.strip()
                if not search:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search term cannot be empty")
                search_regex = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"user_name": search_regex},
                    {"service_name": search_regex},
                    {"business_name": search_regex},
                ]

            # Fetch bookings and convert immediately
            raw_bookings = await booking_collection.find(query).to_list(None)
            bookings = [convert_object_ids(booking) for booking in raw_bookings]

            # Process each booking
            for booking in bookings:
                # Remove _id and set id
                if "_id" in booking:
                    booking["id"] = booking["_id"]
                    del booking["_id"]

                # User information
                user_id = booking.get("user_id")
                if user_id:
                    user = await user_collection.find_one({"_id": ObjectId(user_id)})
                    if user:
                        user_data = convert_object_ids(user)
                        booking["user_name"] = user_data.get("first_name", "")
                        booking["user_email"] = user_data.get("email", "")
                        booking["user_image"] = user_data.get("user_image")
                        booking["user_image_url"] = user_data.get("user_image_url")

                # Vendor information
                vendor_id = booking.get("vendor_id")
                if vendor_id:
                    vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
                    if vendor:
                        vendor_data = convert_object_ids(vendor)
                        booking["business_name"] = vendor_data.get("business_name")
                        booking["business_type"] = vendor_data.get("business_type")

                        # Vendor user information
                        vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor_id)})
                        if vendor_user:
                            vendor_user_data = convert_object_ids(vendor_user)
                            booking["vendor_email"] = vendor_user_data.get("email")
                            booking["vendor_name"] = vendor_user_data.get("first_name")

                # Category information
                category_id = booking.get("category_id")
                if category_id:
                    category = await category_collection.find_one({"_id": ObjectId(category_id)})
                    if category:
                        category_data = convert_object_ids(category)
                        booking["category_name"] = category_data.get("name")

                # Service information
                service_id = booking.get("service_id")
                if service_id:
                    service = await services_collection.find_one({"_id": ObjectId(service_id)})
                    if service:
                        service_data = convert_object_ids(service)
                        booking["service_name"] = service_data.get("name")

            total_bookings = await booking_collection.count_documents(query)

            return {
                "data": bookings,
                "total_bookings": total_bookings,
            }

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def get_user_booking_for_admin(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "admin" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")
            booking["id"] = str(booking["_id"])
            booking.pop("_id", None)
            booking["user_id"] = str(booking["user_id"])
            booking["vendor_id"] = str(booking["vendor_id"])
            booking["category_id"] = str(booking["category_id"])
            booking["service_id"] = str(booking["service_id"])

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def booking_payment(
        self,
        current_user: User,
        vendor_id: str,
        slot: str,
        booking_date: str,
        service_id: str,
        category_id: str,
        vendor_user_id: Optional[str] = None,
        background_tasks: BackgroundTasks = None,
    ):
        try:
            # Fetch all required data concurrently
            async def fetch_service():
                return await services_collection.find_one({"_id": ObjectId(service_id)})

            async def fetch_category():
                return await category_collection.find_one({"_id": ObjectId(category_id)})

            async def fetch_vendor():
                return await vendor_collection.find_one({"_id": ObjectId(vendor_id)})

            async def fetch_vendor_user_obj():
                return await user_collection.find_one({"vendor_id": ObjectId(vendor_id)})

            async def fetch_vendor_user():
                return await user_collection.find_one({"_id": ObjectId(vendor_user_id)}) if vendor_user_id else None

            async def fetch_transfer_amount():
                return await TransferAmount.find_one({})

            service, category, vendor, vendor_user_obj, vendor_user, transfer_amount = await asyncio.gather(
                fetch_service(),
                fetch_category(),
                fetch_vendor(),
                fetch_vendor_user_obj(),
                fetch_vendor_user(),
                fetch_transfer_amount(),
            )

            # Validate fetched data
            if not service:
                raise HTTPException(status_code=404, detail="Service not found")
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            if not vendor:
                raise HTTPException(status_code=404, detail="Vendor not found")
            if not vendor_user_obj:
                raise HTTPException(status_code=404, detail="Vendor User not found")
            if vendor_user_id and not vendor_user:
                raise HTTPException(status_code=404, detail="Vendor User not found")
            if transfer_amount:
                try:
                    # Handle dictionary case
                    transfer_value = (
                        transfer_amount.get("value", 90)
                        if isinstance(transfer_amount, dict)
                        else getattr(transfer_amount, "value", 90)
                    )
                except AttributeError:
                    transfer_value = 90
            else:
                transfer_value = 90

            # Validate booking slot
            booking_datetime = datetime.strptime(booking_date, "%Y-%m-%d")
            day_of_week = booking_datetime.strftime("%A")

            availability_slots = (
                vendor_user.get("availability_slots", [])
                if vendor_user
                else vendor_user_obj.get("availability_slots", [])
            )
            day_slots = next((d for d in availability_slots if d["day"] == day_of_week), None)
            if not day_slots:
                raise HTTPException(status_code=400, detail=f"No availability defined for {day_of_week}")

            try:
                slot_start_str, slot_end_str = slot.split("-")
                slot_start = datetime.strptime(slot_start_str.strip(), "%I:%M %p")
                slot_end = datetime.strptime(slot_end_str.strip(), "%I:%M %p")
                standardized_slot = f"{slot_start.strftime('%I:%M %p')}-{slot_end.strftime('%I:%M %p')}"
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid slot format. Use 'HH:MM AM-HH:MM PM' (e.g., '9:00 AM-10:00 AM')",
                )

            slot_available = False
            selected_time_slot = None
            for time_slot in day_slots["time_slots"]:
                ts_start = datetime.strptime(time_slot["start_time"], "%I:%M %p")
                ts_end = datetime.strptime(time_slot["end_time"], "%I:%M %p")
                if slot_start == ts_start and slot_end == ts_end:
                    slot_available = True
                    selected_time_slot = time_slot
                    break

            if not slot_available:
                raise HTTPException(
                    status_code=400, detail=f"Slot {standardized_slot} is not available on {day_of_week}"
                )

            # Check existing bookings
            async def check_booking_count():
                return await booking_collection.count_documents(
                    {
                        "vendor_user_id": vendor_user_id,
                        "booking_date": booking_date,
                        "time_slot": standardized_slot,
                        "booking_status": {"$ne": "cancelled"},
                    }
                )

            async def check_user_bookings():
                return await booking_collection.find(
                    {
                        "user_id": current_user.id,
                        "booking_status": {"$ne": "cancelled"},
                        "service_id": ObjectId(service_id),
                        "booking_date": booking_date,
                        "time_slot": standardized_slot,
                        "vendor_user_id": vendor_user_id,
                    }
                ).to_list(length=None)

            booking_count, user_bookings = await asyncio.gather(check_booking_count(), check_user_bookings())

            if booking_count >= selected_time_slot["max_seat"]:
                raise HTTPException(
                    status_code=409, detail=f"Slot {standardized_slot} on {booking_date} is fully booked"
                )
            if user_bookings:
                raise HTTPException(
                    status_code=409,
                    detail=f"You already have a booking on {booking_date} at {standardized_slot}",
                )

            is_payment_required = vendor.get("is_payment_required", True)
            fees = vendor_user.get("fees", 0) if vendor_user else vendor_user_obj.get("fees", 0)

            temp_order_id = str(uuid.uuid4())[:8]
            booking_data = {
                "user_id": str(current_user.id),
                "vendor_id": str(ObjectId(vendor_id)),
                "service_id": str(ObjectId(service_id)),
                "category_id": str(ObjectId(category_id)),
                "time_slot": standardized_slot,
                "booking_date": booking_date,
                "amount": fees,
                "booking_status": "pending",
                "payment_status": "pending",
                "vendor_user_id": str(ObjectId(vendor_user_id)) if vendor_user_id else None,
                "created_at": datetime.utcnow().isoformat(),
                "temp_order_id": temp_order_id,
            }

            if is_payment_required:
                payment_config = await payment_collection.find_one({"name": "Razorpay"})
                if not payment_config:
                    raise HTTPException(status_code=404, detail="Payment configuration not found")

                admin_charge_type = payment_config.get("charge_type")
                admin_charge_value = payment_config.get("charge_value")
                amount = float(fees)
                admin_charge = (
                    (admin_charge_value / 100) * amount
                    if admin_charge_type == "percentage"
                    else admin_charge_value if admin_charge_type == "fixed" else 0
                )
                total_charges = amount + admin_charge
                total_amount = int(total_charges * 100)
                booking_data["amount"] = total_charges
                vendor_amount = int(amount * 100) if transfer_value == 0 else int(amount * transfer_value * 100 / 100)
                razorpay_order = razorpay_client.order.create(
                    {
                        "amount": total_amount,
                        "currency": "INR",
                        "receipt": f"temp_booking_{temp_order_id}",
                        "payment_capture": 1,
                        "transfers": [
                            {
                                "account": vendor.get("account_id"),
                                "amount": vendor_amount,
                                "currency": "INR",
                                "on_hold": False,
                            }
                        ],
                    }
                )
                user_data = await user_collection.find_one({"_id": ObjectId(current_user.id)})
                if not user_data:
                    raise HTTPException(status_code=404, detail="User not found")

                notification_settings = user_data.get("notification_settings", {})
                payment_confirmation_enabled = notification_settings.get("payment_confirmation", True)
                user_context = {
                    "vendor_name": f"{vendor_user.get('first_name', '')} {vendor_user.get('last_name', '')}",
                    "service_name": service.get("name"),
                    "category_name": category.get("name"),
                    "currency": "INR",
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "user_name": f"{current_user.first_name} {current_user.last_name}",
                    "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                }
                vendor_context = {
                    "vendor_name": f"{vendor_user.get('first_name', '')} {vendor_user.get('last_name', '')}",
                    "service_name": service.get("name"),
                    "category_name": category.get("name"),
                    "currency": "INR",
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "user_name": f"{current_user.first_name} {current_user.last_name}",
                    "contact": current_user.phone,
                    "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                }

                # if payment_confirmation_enabled:
                #     background_tasks.add_task(
                #         send_email, to_email=current_user.email, source="Booking Confirmation", context=user_context
                #     )
                # background_tasks.add_task(
                #     send_email,
                #     to_email=vendor_user.get("email") if vendor_user else vendor_user_obj.get("email"),
                #     source="Booking Notification",
                #     context=vendor_context,
                #     cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
                # )

                return {
                    "data": {
                        "order_id": temp_order_id,
                        "razorpay_order_id": razorpay_order["id"],
                        "amount": total_amount / 100,
                        "currency": "INR",
                        "booking_data": booking_data,
                    }
                }
            else:
                db_booking_data = {
                    "user_id": ObjectId(current_user.id),
                    "vendor_id": ObjectId(vendor_id),
                    "service_id": ObjectId(service_id),
                    "category_id": ObjectId(category_id),
                    "time_slot": standardized_slot,
                    "booking_date": booking_date,
                    "amount": fees,
                    "booking_status": "pending",
                    "payment_status": "paid",
                    "vendor_user_id": ObjectId(vendor_user_id) if vendor_user_id else None,
                    "created_at": datetime.utcnow(),
                }
                booking_result = await booking_collection.insert_one(db_booking_data)
                booking_id = booking_result.inserted_id

                user_data = await user_collection.find_one({"_id": ObjectId(current_user.id)})
                if not user_data:
                    raise HTTPException(status_code=404, detail="User not found")

                notification_settings = user_data.get("notification_settings", {})
                payment_confirmation_enabled = notification_settings.get("payment_confirmation", True)

                user_context = {
                    "booking_id": str(booking_id),
                    "vendor_name": f"{vendor_user.get('first_name', '')} {vendor_user.get('last_name', '')}",
                    "service_name": service.get("name"),
                    "category_name": category.get("name"),
                    "currency": "INR",
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "user_name": f"{current_user.first_name} {current_user.last_name}",
                    "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                }
                vendor_context = {
                    "booking_id": str(booking_id),
                    "vendor_name": f"{vendor_user.get('first_name', '')} {vendor_user.get('last_name', '')}",
                    "service_name": service.get("name"),
                    "category_name": category.get("name"),
                    "currency": "INR",
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "user_name": f"{current_user.first_name} {current_user.last_name}",
                    "contact": current_user.phone,
                    "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                }

                # if payment_confirmation_enabled:
                #     background_tasks.add_task(
                #         send_email, to_email=current_user.email, source="Booking Confirmation", context=user_context
                #     )
                # background_tasks.add_task(
                #     send_email,
                #     to_email=vendor_user.get("email") if vendor_user else vendor_user_obj.get("email"),
                #     source="Booking Notification",
                #     context=vendor_context,
                #     cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
                # )
                try:
                    background_tasks.add_task(
                        send_push_notification,
                        # device_token="dcgG3i3XxScJ5hI4LU-uwI:APA91bHEgnCDp-VGnJ6iNGpPQ4XTuO3pvnRiK2XPhLviXen9cIwMLA5Hp2ploBPkRv3qvBolhANkYZXreJgOcKuQrwaQ7kFu9xFVRdeLd6wlatdUaTs1EVk",
                        subscriptions=subscriptions,
                        title="Booking Confirmed",
                        body=f"Your booking for {service.get('name')} with {vendor_user.get('first_name')} on {booking_date} at {standardized_slot} has been confirmed.",
                        data={"booking_id": str(booking_id), "type": "booking_confirmed"},
                        api_type="booking",
                    )
                    await notification_collection.insert_one(
                        {
                            "user_id": ObjectId(current_user.id),
                            "message_title": "Booking Confirmed",
                            "message": f"Your booking for {service.get('name')} with {vendor_user.get('first_name')} on {booking_date} at {standardized_slot} has been confirmed.",
                            "user_image_url": vendor_user.get("user_image_url"),
                            "seen": False,
                            "sent": True,
                            "created_at": datetime.now(),
                        }
                    )
                    subscriptions = []
                    vendor_device_token = vendor.get("device_token")
                    if vendor_device_token:
                        subscriptions.append(vendor_device_token)
                    vendor_web_token = vendor.get("web_token")
                    if vendor_web_token:
                        subscriptions.append(vendor_web_token)
                    background_tasks.add_task(
                        send_push_notification,
                        # device_token="dcgG3i3XxScJ5hI4LU-uwI:APA91bHEgnCDp-VGnJ6iNGpPQ4XTuO3pvnRiK2XPhLviXen9cIwMLA5Hp2ploBPkRv3qvBolhANkYZXreJgOcKuQrwaQ7kFu9xFVRdeLd6wlatdUaTs1EVk",
                        subscriptions=subscriptions,
                        title="Booking Confirmed",
                        body=f"You got new booking from {user_data.get('first_name')} on {booking_date} at {standardized_slot} .",
                        data={"booking_id": str(booking_id), "type": "booking_confirmed"},
                        api_type="booking",
                    )
                    await notification_collection.insert_one(
                        {
                            "user_id": vendor.get("_id"),
                            "message_title": "Booking Confirmed",
                            "message": f"You got new booking from {user_data.get('first_name')} on {booking_date} at {standardized_slot} .",
                            "user_image_url": user_data.get("user_image_url"),
                            "seen": False,
                            "sent": True,
                            "created_at": datetime.now(),
                        }
                    )
                except Exception as e:
                    # Log the error but don't interrupt the flow
                    print(f"Failed to send push notification: {str(e)}")
                return {
                    "data": {
                        "order_id": str(booking_id),
                        "amount": fees,
                        "currency": "INR",
                        "payment_status": "paid",
                    }
                }

        except razorpay.errors.BadRequestError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(ex)}")

    async def user_booking_view(self, current_user: User, id: str):
        try:
            booking = await booking_collection.find_one({"temp_order_id": str(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            # Convert fields to string and format
            booking["id"] = str(booking["_id"])
            booking.pop("_id", None)
            booking["user_id"] = str(booking["user_id"])
            booking["vendor_id"] = str(booking["vendor_id"])
            booking["category_id"] = str(booking["category_id"])
            booking["service_id"] = str(booking["service_id"])

            if "amount" in booking and booking["amount"] is not None:
                booking["amount"] = float(booking["amount"])

            if "booking_order_id" in booking and booking["booking_order_id"] is not None:
                booking["booking_order_id"] = str(booking["booking_order_id"])

            # Fetch category details
            category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])})
            if category:
                booking["category_name"] = category.get("name", "Unknown")
            else:
                booking["category_name"] = "Unknown"

            # Fetch service details
            service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])})
            if service:
                booking["service_name"] = service.get("name", "Unknown")
            else:
                booking["service_name"] = "Unknown"

            # Fetch vendor details
            vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
            if vendor:
                booking["vendor_details"] = {
                    "business_name": vendor.get("business_name", "Unknown"),
                    "business_address": vendor.get("location", "Unknown"),
                }
            else:
                booking["vendor_details"] = "Unknown"

            # Convert all ObjectIds to strings recursively
            booking = convert_objectids_to_strings(booking)

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_resulding(
        self, current_user: User, booking_id: str, reason_for_reschulding, background_tasks: BackgroundTasks
    ):
        try:
            booking = await booking_collection.find_one({"_id": ObjectId(booking_id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            vendor_id = booking.get("vendor_id")
            if not vendor_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor ID not found in booking")

            try:
                parsed_date = datetime.strptime(reason_for_reschulding.new_date, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Use YYYY-MM-DD"
                )

            try:
                start_time, end_time = reason_for_reschulding.new_slot.split(" - ")
                start_time_obj = datetime.strptime(start_time, "%I:%M %p").time()  # Handle AM/PM
                end_time_obj = datetime.strptime(end_time, "%I:%M %p").time()
            except ValueError:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid time slot format")

            total_bookings = await booking_collection.count_documents(
                {
                    "vendor_id": vendor_id,
                    "booking_date": reason_for_reschulding.new_date,
                    "time_slot": reason_for_reschulding.new_slot,
                }
            )

            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor found")

            max_seat = 10
            if total_bookings >= max_seat:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Selected slot is fully booked. Please choose another slot.",
                )

            updated_booking = await booking_collection.update_one(
                {"_id": ObjectId(booking_id)},
                {
                    "$set": {
                        "booking_date": reason_for_reschulding.new_date,
                        "time_slot": reason_for_reschulding.new_slot,
                        "reaschulding_reason": reason_for_reschulding.reason,
                    }
                },
            )

            if updated_booking.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update booking"
                )

            subscriptions = []
            device_token = current_user.device_token
            web_subscription = current_user.web_token
            if device_token:
                subscriptions.append(device_token)
            if web_subscription:
                subscriptions.append(web_subscription)

            vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor.get("_id"))})
            vendor_user_obj = await user_collection.find_one({"_id": ObjectId(booking.get("vendor_user_id"))})

            try:
                # Send notification to the user
                background_tasks.add_task(
                    send_push_notification,
                    subscriptions=subscriptions,
                    title="Booking Rescheduled",
                    body=f"Your booking with {vendor_user_obj.get('first_name')} {vendor_user_obj.get('last_name')} has been rescheduled to {reason_for_reschulding.new_date} at {reason_for_reschulding.new_slot}.",
                    data={"booking_id": str(booking_id), "type": "booking_rescheduled"},
                    api_type="booking",  # Add api_type here
                )
                await notification_collection.insert_one(
                    {
                        "user_id": current_user.id,
                        "message_title": "Booking Rescheduled",
                        "message": f"Your booking with {vendor_user_obj.get('first_name')} {vendor_user_obj.get('last_name')} has been rescheduled to {reason_for_reschulding.new_date} at {reason_for_reschulding.new_slot}.",
                        "user_image_url": vendor_user_obj.get("user_image_url"),
                        "seen": False,
                        "sent": True,
                        "created_at": datetime.now(),
                    }
                )

                # Prepare subscriptions for vendor
                subscriptions = []
                device_token = vendor_user.get("device_token")
                web_subscription = vendor_user.get("web_token")
                if device_token:
                    subscriptions.append(device_token)
                if web_subscription:
                    subscriptions.append(web_subscription)

                # Send notification to the vendor
                background_tasks.add_task(
                    send_push_notification,
                    subscriptions=subscriptions,
                    title="Booking Rescheduled",
                    body=f"Your booking with {current_user.first_name} {current_user.last_name} has been rescheduled to {reason_for_reschulding.new_date} at {reason_for_reschulding.new_slot}.",
                    data={"booking_id": str(booking_id), "type": "booking_rescheduled"},
                    api_type="booking",  # Add api_type here
                )
                await notification_collection.insert_one(
                    {
                        "user_id": vendor_user.get("id"),
                        "message_title": "Booking Rescheduled",
                        "user_image_url": current_user.user_image_url,
                        "message": f"Your booking with {current_user.first_name} {current_user.last_name} has been rescheduled to {reason_for_reschulding.new_date} at {reason_for_reschulding.new_slot}.",
                        "seen": False,
                        "sent": True,
                        "created_at": datetime.now(),
                    }
                )
            except Exception as e:
                # Log the error but don't interrupt the flow
                print(f"Failed to send push notification: {str(e)}")

            return {"status": "SUCCESS", "message": "Booking updated successfully"}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_update_request(self, current_user: User, booking_id: str, date: str):
        try:
            booking = await booking_collection.find_one({"_id": ObjectId(booking_id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            vendor_id = booking.get("vendor_id")
            if not vendor_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor ID not found in booking")

            try:
                requested_date = datetime.strptime(date, "%Y-%m-%d")  # Convert string to datetime
                requested_date_str = requested_date.date().isoformat()
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Use YYYY-MM-DD"
                )

            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor found")

            vendor_business_type = vendor.get("business_type")
            user_data = await user_collection.find_one({"vendor_id": ObjectId(vendor_id)})
            vendor_user_id = booking.get("vendor_user_id")

            if not vendor_user_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor user ID found")

            # Fetch the user whose slots will be used
            if vendor_business_type == "business":
                # Fetch the user(s) created by the vendor
                created_users = await user_collection.find({"created_by": str(user_data["_id"])}).to_list(length=None)
                if not created_users:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND, detail="No users created by this vendor found"
                    )

                # Use the first created user's slots (or handle multiple users as needed)
                user_slots = created_users[0].get("availability_slots")
                if not user_slots:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND, detail="No slots found for the created user"
                    )
            else:
                # Fetch the vendor's own user details
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor user found")

                user_slots = vendor_user.get("availability_slots")
                if not user_slots:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor slots found")

            day_of_week = requested_date.strftime("%A")
            filtered_slots = None
            for slot in user_slots:
                if slot.get("day") == day_of_week:
                    filtered_slots = slot.get("time_slots")
                    break

            if not filtered_slots:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No slots found for {day_of_week}")

            # Process slots to include max_seats and bookings_left
            for slot in filtered_slots:
                if "start_time" in slot and isinstance(slot["start_time"], datetime):
                    slot["start_time"] = slot["start_time"].isoformat()
                if "end_time" in slot and isinstance(slot["end_time"], datetime):
                    slot["end_time"] = slot["end_time"].isoformat()

            updated_slots = []
            for slot in filtered_slots:
                slot_start_time = slot["start_time"]
                slot_end_time = slot["end_time"]

                total_bookings_for_slot = await booking_collection.count_documents(
                    {
                        "vendor_id": vendor_id,
                        "booking_date": requested_date_str,
                        "time_slot": {"$gte": slot_start_time, "$lt": slot_end_time},
                    }
                )
                max_seats = slot.get("max_seat", 0)  # Assuming max_seat is stored in the slot, default to 0 if missing
                bookings_left = max_seats - total_bookings_for_slot

                updated_slots.append(
                    {
                        "start_time": slot_start_time,
                        "end_time": slot_end_time,
                        "max_seats": max_seats,
                        "total_bookings": total_bookings_for_slot,
                        "bookings_left": bookings_left,
                    }
                )

            return {"slots": updated_slots}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_payment_history(self, current_user: User):
        try:
            payment_history = await booking_collection.find({"user_id": ObjectId(current_user.id)}).to_list(length=None)

            if not payment_history:
                return {"message": "No payment history found", "data": []}

            formatted_history = []
            ist = timezone("Asia/Kolkata")

            for booking in payment_history:
                created_at_value = booking.get("created_at")
                if isinstance(created_at_value, dict):
                    date_str = created_at_value.get("$date", "1970-01-01T00:00:00Z")
                    created_at = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                else:
                    created_at = created_at_value if created_at_value else datetime.utcnow()

                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone("UTC"))
                created_at_ist = created_at.astimezone(ist)

                date_str_formatted = created_at_ist.strftime("%d-%m-%Y")
                time_str = created_at_ist.strftime("%I:%M %p")

                payment_id = booking.get("payment_id", "N/A")
                order_id = booking.get("booking_order_id", "N/A")
                if payment_id != "N/A" and order_id != "N/A":
                    booking_status = booking.get("booking_status", "N/A")
                    if booking_status == "cancelled":
                        booking_status_formatted = "Cancelled"
                    elif booking_status == "completed":
                        booking_status_formatted = "Completed"
                    else:
                        booking_status_formatted = "Pending"

                    if booking_status_formatted == "Cancelled":
                        payment_status = "Initiated"
                    else:
                        payment_status = "Paid" if booking.get("payment_status") == "paid" else "Pending"

                    history_entry = {
                        "order_id": order_id,
                        "payment_status": payment_status,
                        "booking_status": booking_status_formatted,
                        "date": date_str_formatted,
                        "time": time_str,
                        "transaction_id": payment_id,
                        "payment_method": booking.get("payment_method", "N/A"),
                        "created_at": created_at_ist,
                    }
                    formatted_history.append(history_entry)

            formatted_history.sort(key=lambda x: x["created_at"], reverse=True)

            for entry in formatted_history:
                del entry["created_at"]

            return formatted_history

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
