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

    async def book_appointment(self, request: Request, token: str, booking_request: CreateBookingRequest):
        try:
            # Get current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            vendor_id = booking_request.vendor_id
            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
            if vendor["business_type"] == "business":
                vendor_user = await user_collection.find_one({"created_by": vendor["user_id"]})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")
            else:
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor["user_id"])})
                if not vendor_user:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor user not found")

            try:
                start_time, end_time = [time.strip() for time in booking_request.time_slot.split(" - ")]
            except (IndexError, ValueError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid time_slot format. Expected 'HH:MM - HH:MM'.",
                )

            requested_slot = {"start_time": start_time, "end_time": end_time}
            available_slots = self.get_vendor_slots(vendor_user, booking_request.booking_date)

            # Check slot availability
            if not self.is_slot_available(available_slots, requested_slot):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Selected time slot is not available",
                )

            category_id = booking_request.category_id
            category = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            service_id = booking_request.service_id
            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
            booking_order_id = str(random.randint(100000, 999999))
            amount = vendor.get("fees", 0)
            new_booking = await booking_collection.insert_one(
                {
                    "user_id": current_user.id,
                    "vendor_id": vendor_id,
                    "category_id": category_id,
                    "service_id": service_id,
                    "booking_date": booking_request.booking_date,
                    "time_slot": booking_request.time_slot,
                    "status": booking_request.status,
                    "booking_status": booking_request.booking_status,
                    "payment_status": booking_request.payment_status,
                    "booking_order_id": booking_order_id,
                    "amount": amount,
                    "created_at": datetime.utcnow(),
                }
            )
            user_id = str(vendor.get("user_id"))
            user_name = await user_collection.find_one({"_id": ObjectId(user_id)})
            booking_data = {
                "id": str(new_booking.inserted_id),
                "vendor": {
                    "id": str(vendor.get("_id")),
                    "business_name": vendor.get("business_name"),
                    "name": user_name.get("first_name"),
                    "last_name": user_name.get("last_name"),
                    "fees": vendor.get("fees", 0),
                    "location": vendor.get("location"),
                    "specialization": vendor.get("specialization"),
                },
                "category": {
                    "id": str(category.get("_id")),
                    "name": category.get("name"),
                },
                "service": {
                    "id": str(service.get("_id")),
                    "name": service.get("name"),
                },
                "booking_date": booking_request.booking_date,
                "time_slot": booking_request.time_slot,
                "status": booking_request.status,
                "booking_status": booking_request.booking_status,
                "payment_status": booking_request.payment_status,
                "booking_order_id": booking_order_id,
                "created_at": datetime.utcnow(),
            }
            return booking_data

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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
            bookings = await booking_collection.find({"vendor_id": str(vendor["_id"]), **query}).to_list(None)

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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            user_id = str(current_user.id)

            vendor = await vendor_collection.find_one({"user_id": user_id})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            if str(vendor["_id"]) != str(booking["vendor_id"]):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

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

            return {"upcoming_bookings": upcoming_bookings, "past_bookings": past_bookings}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def cancel_booking(self, request: Request, token: str, id: str, cancel_request: CancelBookingRequest):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            if "user" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

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
                vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
                if vendor:
                    vendor_user_id = vendor["user_id"]
                    booking["business_name"] = vendor["business_name"]
                    booking["business_type"] = vendor["business_type"]
                vendor_user = await user_collection.find_one({"_id": ObjectId(vendor_user_id)})
                if vendor_user:
                    booking["vendor_email"] = vendor_user["email"]
                    booking["vendor_name"] = vendor_user["first_name"]
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
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

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

    async def booking_payment(self, request: Request, token: str, id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            booking = await booking_collection.find_one({"_id": ObjectId(id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")
            if "amount" not in booking or booking["amount"] is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Amount is missing or invalid in booking"
                )
            order_amount = int(booking["amount"] * 100)
            order_currency = "INR"
            razorpay_order = razorpay_client.order.create(
                {"amount": order_amount, "currency": order_currency, "receipt": f"booking_{id}", "payment_capture": 1}
            )

            await booking_collection.update_one(
                {"_id": ObjectId(id)}, {"$set": {"booking_order_id": razorpay_order["id"]}}
            )

            return {
                "data": {
                    "order_id": str(booking["_id"]),
                    "razorpay_order_id": razorpay_order["id"],
                    "amount": booking["amount"],
                    "currency": order_currency,
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

    async def user_booking_resulding(self, request: Request, token: str, booking_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            booking = await booking_collection.find_one({"_id": ObjectId(booking_id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def user_booking_update_request(self, request: Request, token: str, booking_id: str, date: str):
        try:
            # Step 1: Authenticate the user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Step 2: Fetch the booking details
            booking = await booking_collection.find_one({"_id": ObjectId(booking_id)})
            if not booking:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

            # Step 3: Extract vendor ID and requested date
            vendor_id = booking.get("vendor_id")  # Assuming the booking has a `vendor_id` field
            if not vendor_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor ID not found in booking")

            # Step 4: Validate and convert the date to datetime.datetime
            try:
                requested_date = datetime.strptime(date, "%Y-%m-%d")  # Convert to datetime.datetime
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Use YYYY-MM-DD"
                )

            # Step 5: Fetch vendor's slots for the requested date
            vendor_slots = await slots_collection.find(
                {
                    "vendor_id": ObjectId(vendor_id),
                    "date": requested_date,
                }
            ).to_list(length=None)
            if not vendor_slots:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="No available slots found for the vendor on this date"
                )

            # Step 6: Convert datetime objects to strings for serialization
            for slot in vendor_slots:
                if "date" in slot:
                    slot["date"] = slot["date"].isoformat()  # Convert datetime to ISO format string
                if "start_time" in slot and isinstance(slot["start_time"], datetime):
                    slot["start_time"] = slot["start_time"].isoformat()
                if "end_time" in slot and isinstance(slot["end_time"], datetime):
                    slot["end_time"] = slot["end_time"].isoformat()

            # Step 7: Return the available slots
            return {"message": "Vendor slots retrieved successfully", "data": vendor_slots}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
