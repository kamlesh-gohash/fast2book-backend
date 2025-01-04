from app.v1.services.booking.booking_manager import SuperUserBookingManager


def get_super_user_booking_manager() -> SuperUserBookingManager:
    return SuperUserBookingManager()
