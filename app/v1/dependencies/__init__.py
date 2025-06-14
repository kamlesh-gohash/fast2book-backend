__all__ = [
    "get_user_manager",
    "get_super_user_manager",
    "get_category_manager",
    "get_services_manager",
    "get_vendor_manager",
    "get_costumer_manager",
    "get_subscription_manager",
    "get_blog_manager",
    "get_booking_manager",
    "get_payment_manager",
    "get_support_manager",
    "get_permission_manager",
    "get_razor_pay_manager",
    "get_video_manager",
    "get_rating_manager",
    "get_notification_manager",
    "get_offer_manager",
]

from app.v1.dependencies.blog_manager import get_blog_manager
from app.v1.dependencies.booking_manager import get_booking_manager
from app.v1.dependencies.category_manager import get_category_manager
from app.v1.dependencies.costumer_manager import get_costumer_manager
from app.v1.dependencies.notification_manager import get_notification_manager
from app.v1.dependencies.offer_manager import get_offer_manager
from app.v1.dependencies.payment_manager import get_payment_manager
from app.v1.dependencies.permission_manager import get_permission_manager
from app.v1.dependencies.rating_manager import get_rating_manager
from app.v1.dependencies.razor_pay import get_razor_pay_manager
from app.v1.dependencies.services_manager import get_services_manager
from app.v1.dependencies.subscription_manager import get_subscription_manager
from app.v1.dependencies.super_user_manager import get_super_user_manager
from app.v1.dependencies.support_manager import get_support_manager
from app.v1.dependencies.user_manager import get_user_manager
from app.v1.dependencies.vendor_manager import get_vendor_manager
from app.v1.dependencies.video_manager import get_video_manager
