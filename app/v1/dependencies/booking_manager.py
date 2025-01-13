from app.v1.services.booking.booking_manager import BookingManager


def get_booking_manager() -> BookingManager:
    return BookingManager()
