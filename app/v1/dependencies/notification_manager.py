from app.v1.services.notification.notification_manager import NotificationManager


def get_notification_manager() -> NotificationManager:
    return NotificationManager()
