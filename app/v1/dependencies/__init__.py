__all__ = [
    "get_user_manager",
    "get_super_user_manager",
    "get_category_manager",
    "get_services_manager",
    "get_vendor_manager",
    "get_costumer_manager",
    "get_subscription_manager",
    "get_blog_manager",
]

from app.v1.dependencies.user_manager import get_user_manager
from app.v1.dependencies.super_user_manager import get_super_user_manager
from app.v1.dependencies.category_manager import get_category_manager
from app.v1.dependencies.services_manager import get_services_manager
from app.v1.dependencies.vendor_manager import get_vendor_manager
from app.v1.dependencies.costumer_manager import get_costumer_manager
from app.v1.dependencies.subscription_manager import get_subscription_manager
from app.v1.dependencies.blog_manange import get_blog_manager
