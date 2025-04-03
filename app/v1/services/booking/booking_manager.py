import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import pytz
import razorpay.errors

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Query, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import (
    booking_collection,
    category_collection,
    payment_collection,
    services_collection,
    slots_collection,
    user_collection,
    vendor_collection,
)
from app.v1.models.booking import *
from app.v1.models.user import User
from app.v1.schemas.booking.booking import CancelBookingRequest, CreateBookingRequest
from app.v1.utils.email import generate_otp, send_email
from app.v1.utils.token import create_access_token, create_refresh_token, get_oauth_tokens


razorpay_client = razorpay.Client(auth=(os.getenv("RAZOR_PAY_KEY_ID"), os.getenv("RAZOR_PAY_KEY_SECRET")))


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

            query = {}
            if start_date or end_date:
                date_filter = {}

                if start_date:
                    try:
                        # Validate the date format
                        datetime.strptime(start_date, "%Y-%m-%d")
                        date_filter["$gte"] = start_date
                    except ValueError:
                        raise HTTPException(
                            status_code=400, detail="Invalid start date format. Please use 'YYYY-MM-DD'"
                        )

                if end_date:
                    try:
                        # Validate the date format
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
            bookings = await booking_collection.find({"vendor_id": ObjectId(vendor["_id"]), **query}).to_list(None)
            # Convert ObjectId to string in the response
            for booking in bookings:
                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)

                # for booking in bookings:
                #     booking["user_id"] = str(booking["user_id"])
                #     booking["vendor_id"] = str(booking["vendor_id"])
                #     booking["category_id"] = str(booking["category_id"])
                #     booking["service_id"] = str(booking["service_id"])
                # for booking in bookings:
                #     booking["id"] = str(booking["_id"])
                #     booking.pop("_id", None)

                # Fetch user details
                user_id = booking["user_id"]
                user = await user_collection.find_one({"_id": ObjectId(user_id)})
                if user:
                    booking["user_name"] = user["first_name"]
                    booking["user_email"] = user["email"]

                # Fetch vendor details
                vendor_id = booking["vendor_id"]
                vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
                if vendor:
                    vendor_user_id = vendor["_id"]
                    booking["business_name"] = vendor["business_name"]
                    booking["business_type"] = vendor["business_type"]

                # Fetch vendor user details

                vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor_id)})
                if vendor.get("business_type") == "business":
                    vendor_user = await user_collection.find_one({"created_by": str(vendor_user.get("_id"))})
                booking["vendor_email"] = vendor_user["email"]
                booking["vendor_name"] = vendor_user["first_name"]

                # Fetch category details
                category_id = booking["category_id"]
                category = await category_collection.find_one({"_id": ObjectId(category_id)})
                booking["category_name"] = category.get("name") if category else None

                # Fetch service details
                service_id = booking["service_id"]
                service = await services_collection.find_one({"_id": ObjectId(service_id)})
                booking["service_name"] = service.get("name") if service else None

                # Convert ObjectId fields to string
                booking["user_id"] = str(booking["user_id"])
                booking["vendor_id"] = str(booking["vendor_id"])
                booking["category_id"] = str(booking["category_id"])
                booking["service_id"] = str(booking["service_id"])

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
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
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
                booking["user_id"] = str(booking["user_id"])
                booking["vendor_id"] = str(booking["vendor_id"])
                booking["category_id"] = str(booking["category_id"])
                booking["service_id"] = str(booking["service_id"])
                booking["vendor_user_id"] = str(booking["vendor_user_id"])

                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])})
                booking["category_name"] = category.get("name") if category else None

                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])})
                booking["service_name"] = service.get("name") if service else None
                booking["service_image"] = service.get("service_image")
                booking["service_image_url"] = service.get("service_image_url")

                vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
                vendor_user = await user_collection.find_one({"_id": ObjectId(booking["vendor_user_id"])})
                if vendor:
                    booking["vendor__first_name"] = vendor_user.get("first_name")
                    booking["vendor_last_name"] = vendor_user.get("last_name")  # Fixed typo
                    booking["vendor_email"] = vendor_user.get("email")
                    booking["vendor_phone"] = vendor_user.get("phone")
                    booking["user_image"] = vendor_user.get("user_image")
                    booking["user_image_url"] = vendor_user.get("user_image_url")

                    booking["vendor_location"] = vendor.get("location")
                    booking["specialization"] = vendor_user.get("specialization")
                    booking["business_name"] = vendor.get("business_name")

                # Safely parse time_slot
                time_slot = booking.get("time_slot", "")
                try:
                    # Split on "-" and take the start time
                    start_time = time_slot.split("-")[0].strip()
                    # Ensure start_time is in valid format before parsing
                    if not start_time or not any(c.isdigit() for c in start_time):
                        continue  # Skip this booking if time_slot is invalid
                    booking_datetime = tz.localize(
                        datetime.strptime(booking["booking_date"] + " " + start_time, "%Y-%m-%d %I:%M %p")
                    )
                except (ValueError, IndexError) as e:
                    continue  # Skip this booking if parsing fails

                booking_status = booking.get("booking_status", "").lower()

                if booking_datetime >= current_datetime and booking_status not in ["cancelled", "completed"]:
                    upcoming_bookings.append(booking)
                else:
                    if status_filter:
                        if booking_status == status_filter.lower() and booking_status in ["completed", "cancelled"]:
                            past_bookings.append(booking)
                    else:
                        if booking_status in ["completed", "cancelled"]:
                            past_bookings.append(booking)

            def sort_by_date(bookings_list):
                return sorted(bookings_list, key=lambda x: x["booking_date"])

            upcoming_bookings = sort_by_date(upcoming_bookings)
            past_bookings = sort_by_date(past_bookings)

            return {"upcoming_bookings": upcoming_bookings, "past_bookings": past_bookings}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def cancel_booking(self, current_user: User, id: str, cancel_request: CancelBookingRequest):
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
            # if update_result.modified_count == 0:
            #     raise HTTPException(
            #         status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to cancel booking"
            #     )
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

            await send_email(
                to_email=vendor_user.get("email"),
                source=source,
                context=context,
            )
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

            await send_email(
                to_email=vendor_user.get("email"),
                source=source,
                context=context,
                cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
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
    ):
        try:
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            valid_roles = ["admin", "user", "vendor"]
            if role not in valid_roles:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role: '{role}'. Valid roles are: {valid_roles}.",
                )

            query = {}

            # Add date filter if provided
            if start_date or end_date:
                date_filter = {}

                if start_date:
                    try:
                        # Validate the date format
                        datetime.strptime(start_date, "%Y-%m-%d")
                        date_filter["$gte"] = start_date
                    except ValueError:
                        raise HTTPException(
                            status_code=400, detail="Invalid start date format. Please use 'YYYY-MM-DD'"
                        )

                if end_date:
                    try:
                        # Validate the date format
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
                    # Add more fields for searching if needed
                ]

            bookings = await booking_collection.find(query).to_list(None)

            for booking in bookings:
                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)
                user_id = booking["user_id"]
                user = await user_collection.find_one({"_id": ObjectId(user_id)})
                if user:
                    booking["user_name"] = user["first_name"]
                    booking["user_email"] = user["email"]
                vendor_id = booking["vendor_id"]
                vendor = await vendor_collection.find_one({"_id": vendor_id})
                vendor_id = booking.get("vendor_id")
                if vendor_id:
                    vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
                    if vendor:
                        booking["business_name"] = vendor.get("business_name")  # Fetch business name
                        booking["business_type"] = vendor.get("business_type")

                        vendor_user_id = vendor.get("_id")  # Use .get() to avoid KeyError
                        if vendor_user_id:  # Only query if vendor_user_id exists
                            vendor_user = await user_collection.find_one({"vendor_id": ObjectId(vendor_user_id)})
                            if vendor_user:
                                booking["vendor_email"] = vendor_user.get("email")
                                booking["vendor_name"] = vendor_user.get("first_name")
                booking["user_id"] = str(booking["user_id"])
                booking["vendor_id"] = str(booking["vendor_id"])
                category_id = booking["category_id"]
                service_id = booking["service_id"]
                category = await category_collection.find_one({"_id": category_id})
                booking["category_id"] = str(booking["category_id"])
                booking["category_name"] = category.get("name") if category else None

                service = await services_collection.find_one({"_id": service_id})
                booking["service_id"] = str(booking["service_id"])
                booking["service_name"] = service.get("name") if service else None

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
    ):
        try:
            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            category = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            vendor_user_obj = await user_collection.find_one({"vendor_id": ObjectId(vendor_id)})
            if not vendor_user_obj:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor User not found")
            vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor User not found")

            booking_datetime = datetime.strptime(booking_date, "%Y-%m-%d")
            day_of_week = booking_datetime.strftime("%A")

            # Check slot availability
            availability_slots = vendor_user.get("availability_slots", [])
            day_slots = next((d for d in availability_slots if d["day"] == day_of_week), None)

            if not day_slots:
                raise HTTPException(status_code=400, detail=f"No availability defined for {day_of_week}")

            # Parse requested slot and standardize format
            try:
                slot_start_str, slot_end_str = slot.split("-")
                slot_start = datetime.strptime(slot_start_str.strip(), "%I:%M %p")
                slot_end = datetime.strptime(slot_end_str.strip(), "%I:%M %p")
                # Standardize the slot format without spaces around hyphen
                standardized_slot = f"{slot_start.strftime('%I:%M %p')}-{slot_end.strftime('%I:%M %p')}"
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid slot format. Use 'HH:MM AM-HH:MM PM' (e.g., '9:00 AM-10:00 AM')",
                )

            # Check if slot matches any available time slot exactly
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

            # Check current bookings against max_seat
            booking_count = await booking_collection.count_documents(
                {
                    "vendor_user_id": vendor_user_id,
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "booking_status": {"$ne": "cancelled"},
                }
            )

            if booking_count >= selected_time_slot["max_seat"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Slot {standardized_slot} on {booking_date} is fully booked",
                )
            user_bookings = await booking_collection.find(
                {
                    "user_id": current_user.id,
                    "booking_status": {"$ne": "cancelled"},
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "vendor_user_id": vendor_user_id,
                }
            ).to_list(length=None)

            if user_bookings:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"You already have a booking on {booking_date} at {standardized_slot}",
                )

            is_payment_required = vendor.get("is_payment_required", True)
            booking_data = {
                "user_id": current_user.id,
                "vendor_id": ObjectId(vendor_id),
                "service_id": ObjectId(service_id),
                "category_id": ObjectId(category_id),
                "time_slot": standardized_slot,  # Use standardized format here
                "booking_date": booking_date,
                "amount": vendor_user.get("fees", 0),
                "booking_status": "panding",
                "payment_status": "paid" if not is_payment_required else "panding",
                "vendor_user_id": vendor_user_id if vendor_user_id else None,
                "created_at": datetime.utcnow(),
            }

            # Insert the booking into the database
            booking_result = await booking_collection.insert_one(booking_data)
            booking_id = booking_result.inserted_id

            # Step 7: Handle payment logic
            if is_payment_required:
                # Process payment via Razorpay
                amount = float(vendor_user.get("fees", 0))
                payment_method = "Razorpay"
                payment_config = await payment_collection.find_one({"name": payment_method})
                if not payment_config:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment configuration not found")

                admin_charge_type = payment_config.get("charge_type")
                admin_charge_value = payment_config.get("charge_value")

                if admin_charge_type == "percentage":
                    admin_charge = (admin_charge_value / 100) * amount
                elif admin_charge_type == "fixed":
                    admin_charge = admin_charge_value
                else:
                    admin_charge = 0

                total_charges = amount + admin_charge
                total_amount = int(total_charges * 100)

                order_currency = "INR"
                razorpay_order = razorpay_client.order.create(
                    {
                        "amount": total_amount,
                        "currency": order_currency,
                        "receipt": f"booking_{booking_id}",
                        "payment_capture": 1,
                    }
                )

                # Update the booking with the Razorpay order ID and total amount
                await booking_collection.update_one(
                    {"_id": booking_id},
                    {"$set": {"booking_order_id": razorpay_order["id"], "amount": total_charges}},
                )

                user_data = await user_collection.find_one({"_id": ObjectId(current_user.id)})
                if not user_data:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

                notification_settings = user_data.get("notification_settings", {})
                payment_confirmation_enabled = notification_settings.get("payment_confirmation", True)

                # Send email only if payment confirmation is enabled
                if payment_confirmation_enabled:
                    source = "Booking Confirmation"
                    context = {
                        "booking_id": str(booking_id),
                        "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                        "service_name": service.get("name"),
                        "category_name": category.get("name"),
                        "amount": amount,
                        "currency": "INR",
                        "payment_method": payment_method,
                        "booking_date": booking_date,
                        "time_slot": standardized_slot,
                        "user_name": current_user.first_name + " " + current_user.last_name,
                        "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                    }

                    await send_email(
                        to_email=current_user.email,
                        source=source,
                        context=context,
                    )
                    source = "Booking Notification"
                    context = {
                        "booking_id": str(booking_id),
                        "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                        "service_name": service.get("name"),
                        "category_name": category.get("name"),
                        "currency": "INR",
                        "booking_date": booking_date,
                        "time_slot": standardized_slot,
                        "user_name": current_user.first_name + " " + current_user.last_name,
                        "contact": current_user.phone,
                        "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                    }
                    await send_email(
                        to_email=vendor_user.get("email"),
                        source=source,
                        context=context,
                        cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
                    )

                return {
                    "data": {
                        "order_id": str(booking_id),
                        "razorpay_order_id": razorpay_order["id"],
                        "amount": amount,
                        "currency": order_currency,
                    }
                }
            else:
                # If payment is not required, send email directly
                user_data = await user_collection.find_one({"_id": ObjectId(current_user.id)})
                if not user_data:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

                notification_settings = user_data.get("notification_settings", {})
                payment_confirmation_enabled = notification_settings.get("payment_confirmation", True)

                if payment_confirmation_enabled:
                    source = "Booking Confirmation"
                    context = {
                        "booking_id": str(booking_id),
                        "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                        "service_name": service.get("name"),
                        "category_name": category.get("name"),
                        "currency": "INR",
                        "booking_date": booking_date,
                        "time_slot": standardized_slot,
                        "user_name": current_user.first_name + " " + current_user.last_name,
                        "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                    }

                    await send_email(
                        to_email=current_user.email,
                        source=source,
                        context=context,
                    )
                source = "Booking Notification"
                context = {
                    "booking_id": str(booking_id),
                    "vendor_name": vendor_user.get("first_name") + " " + vendor_user.get("last_name"),
                    "service_name": service.get("name"),
                    "category_name": category.get("name"),
                    "currency": "INR",
                    "booking_date": booking_date,
                    "time_slot": standardized_slot,
                    "user_name": current_user.first_name + " " + current_user.last_name,
                    "contact": current_user.phone,
                    "location": vendor.get("location", {}).get("formatted_address", "Not specified"),
                }
                await send_email(
                    to_email=vendor_user.get("email"),
                    source=source,
                    context=context,
                    cc_email=vendor_user_obj.get("email") if vendor.get("business_type") == "business" else None,
                )

                return {
                    "data": {
                        "order_id": str(booking_id),
                        "amount": vendor_user.get("fees", 0),
                        "currency": "INR",
                        "payment_status": "paid",
                    }
                }

        except razorpay.errors.BadRequestError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def user_booking_view(self, current_user: User, id: str):
        try:
            booking = await booking_collection.find_one({"_id": ObjectId(id)})
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

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_resulding(self, current_user: User, booking_id: str, reason_for_reschulding):
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
                start_time_obj = datetime.strptime(start_time, "%H:%M").time()
                end_time_obj = datetime.strptime(end_time, "%H:%M").time()
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

            for slot in filtered_slots:
                if "start_time" in slot and isinstance(slot["start_time"], datetime):
                    slot["start_time"] = slot["start_time"].isoformat()
                if "end_time" in slot and isinstance(slot["end_time"], datetime):
                    slot["end_time"] = slot["end_time"].isoformat()

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
                slot["total_bookings"] = total_bookings_for_slot

            return {"slots": filtered_slots}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_payment_history(self, current_user: User):
        try:
            payment_history = await payment_collection.find({"user_id": str(current_user.id)}).to_list(length=None)
            return payment_history
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
