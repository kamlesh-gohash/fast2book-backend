from datetime import datetime, timedelta, time
from enum import Enum
from beanie import Link
from pydantic import BaseModel
from app.v1.models.user import StatusEnum, User
from app.v1.models.vendor import Vendor
from typing import List


class DayEnum(str, Enum):
    monday = "Monday"
    tuesday = "Tuesday"
    wednesday = "Wednesday"
    thursday = "Thursday"
    friday = "Friday"
    saturday = "Saturday"
    sunday = "Sunday"


class TimeSlot(BaseModel):
    start_time: time  # Only time
    end_time: time  # Only time
    duration: int = 0  # Duration will be calculated on the backend

    # Calculate duration based on start_time and end_time
    def calculate_duration(self):
        start_seconds = (self.start_time.hour * 3600) + (self.start_time.minute * 60) + self.start_time.second
        end_seconds = (self.end_time.hour * 3600) + (self.end_time.minute * 60) + self.end_time.second
        self.duration = (end_seconds - start_seconds) // 60
        return self.duration

    # Override the dict method to convert times to strings
    class Config:
        json_encoders = {time: lambda v: v.strftime("%H:%M")}  # Convert `time` to string format "HH:MM"

    def dict(self, *args, **kwargs):
        data = super().dict(*args, **kwargs)
        return data


class DaySlot(BaseModel):
    day: DayEnum
    time_slots: List[TimeSlot]


class SlotRequest(BaseModel):
    slots: List[DaySlot]

    class Config:
        arbitrary_types_allowed = True


class Slots(BaseModel):
    user_id: Link[User]
    vendor_id: Link[Vendor]
    day: DayEnum
    start_time: datetime
    end_time: datetime
    slots: list[SlotRequest]
    status: StatusEnum = StatusEnum.Active

    class Settings:
        name = "slots"

    def calculate_slots(self):
        """Automatically calculates slots between start_time and end_time for the given day."""
        slot_list = []
        current_start = self.start_time
        while current_start < self.end_time:
            current_end = current_start + timedelta(minutes=30)  # You can adjust the duration here
            duration = int((current_end - current_start).total_seconds() / 60)  # Calculate duration in minutes
            slot_list.append(SlotRequest(start_time=current_start, end_time=current_end, duration=duration))
            current_start = current_end  # Move to the next slot
        self.slots = slot_list  # Update the slots list with calculated slots
