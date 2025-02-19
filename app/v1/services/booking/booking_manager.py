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
        request: Request,
        token: str,
        booking_date: str = Query(..., description="Booking date in YYYY-MM-DD format"),
        slot: str = Query(..., description="Time slot in 'HH:MM - HH:MM' format"),
        vendor_id: str = Query(..., description="Vendor ID"),
        service_id: str = Query(..., description="Service ID"),
    ):
        try:
            # Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

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
            if vendor["business_type"] == "business":
                vendor_user = await user_collection.find_one({"created_by": vendor["user_id"]})
            else:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor["user_id"])})
            if not vendor_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            amount = vendor.get("fees")
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
            # Prepare response data
            response_data = {
                "vendor": {
                    "id": str(vendor.get("_id")),
                    "business_name": vendor.get("business_name"),
                    "name": vendor_user.get("first_name"),
                    "last_name": vendor_user.get("last_name"),
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
                "booking_date": booking_date,
                "time_slot": slot,
                "platform_fee": admin_charge,
                "total_amount": total_amount,
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

    async def user_booking_checkout(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

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
        self, request: Request, token: str, search: str = None, start_date: str = None, end_date: str = None
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "vendor" not in [role.value for role in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            user_id = str(current_user.id)
            vendor = await vendor_collection.find_one({"user_id": user_id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            # print(booking_collection, 'booking_collection')
            # async for booking in booking_collection.find({"vendor_id": vendor["_id"]}):
            #     print(booking, 'booking')
            #     booking["_id"] = str(booking["_id"])
            #     bookings.append(booking)
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
                    vendor_user_id = vendor["user_id"]
                    booking["business_name"] = vendor["business_name"]
                    booking["business_type"] = vendor["business_type"]

                # Fetch vendor user details
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if vendor_user:
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

    async def vendor_get_booking(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

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

    async def vendor_update_booking(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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

    async def user_booking_list(self, request: Request, token: str, status_filter: str = None):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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

                category = await category_collection.find_one({"_id": ObjectId(booking["category_id"])})
                booking["category_name"] = category.get("name") if category else None

                service = await services_collection.find_one({"_id": ObjectId(booking["service_id"])})
                booking["service_name"] = service.get("name") if service else None
                booking["service_image"] = service.get("service_image")
                booking["service_image_url"] = service.get("service_image_url")

                vendor = await vendor_collection.find_one({"_id": ObjectId(booking["vendor_id"])})
                if vendor:
                    booking["vendor_name"] = vendor.get("business_name")
                    booking["vendor_location"] = vendor.get("location")
                    booking["specialization"] = vendor.get("specialization")

                booking_datetime = tz.localize(
                    datetime.strptime(
                        booking["booking_date"] + " " + booking["time_slot"].split(" - ")[0], "%Y-%m-%d %H:%M"
                    )
                )

                booking_status = booking.get("booking_status", "").lower()

                if booking_status == "cancelled":
                    if status_filter:
                        if status_filter.lower() == "cancelled":
                            past_bookings.append(booking)
                    else:
                        past_bookings.append(booking)
                else:
                    if booking_datetime >= current_datetime:
                        if booking_status == "panding":
                            upcoming_bookings.append(booking)
                    else:
                        if status_filter:
                            if booking_status == status_filter.lower():
                                past_bookings.append(booking)
                        else:
                            past_bookings.append(booking)

            def sort_by_date(bookings_list):
                return sorted(bookings_list, key=lambda x: x["booking_date"])

            upcoming_bookings = sort_by_date(upcoming_bookings)
            past_bookings = sort_by_date(past_bookings)

            return {"upcoming_bookings": upcoming_bookings, "past_bookings": past_bookings}

        except HTTPException:
            raise
        except Exception as ex:
            print(ex, "ex")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def cancel_booking(self, request: Request, token: str, id: str, cancel_request: CancelBookingRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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

            return {"reason": cancel_request.reason}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_list_for_admin(
        self,
        request: Request,
        token: str,
        search: str = None,
        role: str = "vendor",
        start_date: str = None,
        end_date: str = None,
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise ValueError(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
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

                        vendor_user_id = vendor.get("user_id")  # Use .get() to avoid KeyError
                        if vendor_user_id:  # Only query if vendor_user_id exists
                            vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
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

    # async def booking_payment(self, request: Request, token: str, id: str):
    #     try:
    #         current_user = await get_current_user(request=request, token=token)
    #         if not current_user:
    #             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    #         booking = await booking_collection.find_one({"_id": ObjectId(id)})
    #         if not booking:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")
    #         if "amount" not in booking or booking["amount"] is None:
    #             raise HTTPException(
    #                 status_code=status.HTTP_400_BAD_REQUEST, detail="Amount is missing or invalid in booking"
    #             )

    #         # amount = int(booking["amount"] * 100)
    #         # print(amount,'amount in booking payment')
    #         amount = float(booking["amount"])
    #         payment_method = "Razorpay"
    #         payment_config = await payment_collection.find_one({"name": payment_method})
    #         if not payment_config:
    #             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment configuration not found")

    #         admin_charge_type = payment_config.get("charge_type")  # 'percentage' or 'fixed'
    #         admin_charge_value = payment_config.get("charge_value")  # e.g., 10 for 10% or 50 for $50

    #         if admin_charge_type == "percentage":
    #             admin_charge = (admin_charge_value / 100) * amount
    #         elif admin_charge_type == "fixed":
    #             admin_charge = admin_charge_value
    #         else:
    #             admin_charge = 0

    #         total_charges = amount + admin_charge
    #         total_amount = int(total_charges * 100)

    #         order_currency = "INR"
    #         razorpay_order = razorpay_client.order.create(
    #             {"amount": total_amount, "currency": order_currency, "receipt": f"booking_{id}", "payment_capture": 1}
    #         )

    #         await booking_collection.update_one(
    #             {"_id": ObjectId(id)}, {"$set": {"booking_order_id": razorpay_order["id"], "amount": total_charges}}
    #         )

    #         return {
    #             "data": {
    #                 "order_id": str(booking["_id"]),
    #                 "razorpay_order_id": razorpay_order["id"],
    #                 "amount": amount,
    #                 "currency": order_currency,
    #             }
    #         }

    #     except razorpay.errors.BadRequestError as e:
    #         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    #     except Exception as ex:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
    #         )

    async def booking_payment(
        self,
        request: Request,
        token: str,
        vendor_id: str,
        slot: str,
        booking_date: str,
        service_id: str,
        category_id: str,
    ):
        try:
            # Step 1: Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Step 2: Fetch service details
            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

            category = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            is_payment_required = vendor.get("is_payment_required", True)
            booking_data = {
                "user_id": current_user.id,  # Access the user ID using dot notation
                "vendor_id": ObjectId(vendor_id),
                "service_id": ObjectId(service_id),
                "category_id": ObjectId(category_id),
                "time_slot": slot,
                "booking_date": booking_date,
                "amount": vendor.get("fees", 0),
                "booking_status": "panding",
                "payment_status": "paid" if not is_payment_required else "panding",  # Set payment status
                "created_at": datetime.utcnow(),
            }

            # Insert the booking into the database
            booking_result = await booking_collection.insert_one(booking_data)
            booking_id = booking_result.inserted_id

            # Step 7: Handle payment logic
            if is_payment_required:
                # Process payment via Razorpay
                amount = float(vendor.get("fees", 0))
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

                return {
                    "data": {
                        "order_id": str(booking_id),
                        "razorpay_order_id": razorpay_order["id"],
                        "amount": amount,
                        "currency": order_currency,
                    }
                }
            else:
                return {
                    "data": {
                        "order_id": str(booking_id),
                        "amount": vendor.get("fees", 0),
                        "currency": "INR",
                        "payment_status": "paid",
                    }
                }

        except razorpay.errors.BadRequestError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def user_booking_view(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Fetch the booking
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
                    "business_address": vendor.get("business_address", "Unknown"),
                }
            else:
                booking["vendor_details"] = "Unknown"

            return booking

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_resulding(self, request: Request, token: str, booking_id: str, reason_for_reschulding):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

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

    async def user_booking_update_request(self, request: Request, token: str, booking_id: str, date: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

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
            vendor_user_id = vendor.get("user_id")

            if not vendor_user_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vendor user ID found")

            # Fetch the user whose slots will be used
            if vendor_business_type == "business":
                # Fetch the user(s) created by the vendor
                created_users = await user_collection.find({"created_by": str(vendor_user_id)}).to_list(length=None)
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
