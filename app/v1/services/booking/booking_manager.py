import random

from datetime import datetime, timedelta
from typing import Optional

import bcrypt

from bcrypt import gensalt, hashpw
from bson import ObjectId  # Import ObjectId to work with MongoDB IDs

# from app.v1.utils.token import generate_jwt_token
from fastapi import Body, HTTPException, Request, status

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


class BookingManager:

    async def book_appointment(self, request: Request, token: str, booking_request: CreateBookingRequest):
        print(booking_request, "booking_request")
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            vendor_id = booking_request.vendor_id
            vendor = await vendor_collection.find_one({"_id": ObjectId(vendor_id)})
            if not vendor:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")

            date = booking_request.date
            time_slot = booking_request.time_slot

            try:
                requested_slot = {
                    "start_time": time_slot.split(" - ")[0].strip(),
                    "end_time": time_slot.split(" - ")[1].strip(),
                    "duration": (
                        datetime.strptime(time_slot.split(" - ")[1], "%H:%M")
                        - datetime.strptime(time_slot.split(" - ")[0], "%H:%M")
                    ).seconds
                    // 60,
                }
            except (IndexError, ValueError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid time_slot format. Expected 'HH:MM - HH:MM'.",
                )

            available_slots = self.get_vendor_slots(vendor, date)
            print(available_slots, "available_slots")
            if not self.is_slot_available(available_slots, requested_slot):
                print("not available")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Selected time slot is not available",
                )

            category_id = booking_request.category_id
            print(category_id, "category_id")
            category = await category_collection.find_one({"_id": ObjectId(category_id)})
            if not category:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

            # Validate service
            service_id = booking_request.service_id
            print(service_id, "service_id")
            service = await services_collection.find_one({"_id": ObjectId(service_id)})
            print(service, "service")
            if not service:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
            print("service", service)

            new_booking = await booking_collection.insert_one(
                {
                    "user_id": current_user.id,
                    "vendor_id": vendor_id,
                    "category_id": category_id,
                    "service_id": service_id,
                    "date": date,
                    "time_slot": time_slot,
                    "status": "pending",
                    "created_at": datetime.utcnow(),
                }
            )
            print(new_booking, "new_booking")
            return {"booking_id": str(new_booking.inserted_id)}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    def get_vendor_slots(self, vendor, date):
        """
        Extracts and filters available slots for the given vendor and date.
        """
        print(vendor, "vendor")
        for availability in vendor.get("availability_slots", []):
            print(availability, "availability")
            if availability["day"].lower() == self.get_weekday(date).lower():
                print(availability["time_slots"], 'availability["time_slots"]')
                return availability["time_slots"]
        return []

    def is_slot_available(self, available_slots, requested_slot):
        """
        Checks if the requested slot matches any available slots.
        """
        print(available_slots, "available_slots")
        for slot in available_slots:
            print(slot, "slot")
            if (
                slot["start_time"] == requested_slot["start_time"]
                and slot["end_time"] == requested_slot["end_time"]
                and slot["duration"] == requested_slot["duration"]
            ):
                print("Slot is available")
                return True
        print("Slot is not available")
        return False

    def get_weekday(self, date):
        """
        Returns the day of the week for a given date.
        """
        return datetime.strptime(date, "%Y-%m-%d").strftime("%A")

    async def user_booking_list_for_vendor(self, request: Request, token: str):
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
            bookings = await booking_collection.find({"vendor_id": str(vendor["_id"])}).to_list(None)

            # Convert ObjectId to string in the response
            for booking in bookings:
                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)

            for booking in bookings:
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

    async def user_booking_list(self, request: Request, token: str):
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

            # async for booking in booking_collection.find({"user_id": user["_id"]}):
            #     booking["_id"] = str(booking["_id"])
            #     bookings.append(booking)
            bookings = await booking_collection.find({"user_id": user["_id"]}).to_list(None)
            # Convert ObjectId to string in the response

            for booking in bookings:
                booking["id"] = str(booking["_id"])
                booking.pop("_id", None)
                booking["user_id"] = str(booking["user_id"])
                booking["vendor_id"] = str(booking["vendor_id"])
                booking["category_id"] = str(booking["category_id"])
                booking["service_id"] = str(booking["service_id"])

            return bookings

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
                "status": "Cancelled",
                "cancellation_reason": cancel_request.reason,
                "cancelled_at": datetime.utcnow(),
            }
            update_result = await booking_collection.update_one({"_id": ObjectId(id)}, {"$set": cancellation_data})

            if update_result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to cancel booking"
                )

            return {"reason": cancel_request.reason}

        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
