from fastapi import APIRouter

from app.v1.routers.users import users_router
from app.v1.routers.superuser import super_user_router
from app.v1.routers.category import category_router
from app.v1.routers.service import service_router
from app.v1.routers.vendor import vendor_router
from app.v1.routers.costumer import costumer_router
from app.v1.routers.subscription import subscription_router
from app.v1.routers.blog import blog_router

router = APIRouter(prefix="/v1")
router.include_router(users_router.router, prefix="/users", tags=["Users"])
router.include_router(super_user_router.router, prefix="/superuser", tags=["SuperUser"])
router.include_router(category_router.router, prefix="/category",tags=["Category"])
router.include_router(service_router.router, prefix="/service",tags=["Service"])
router.include_router(vendor_router.router, prefix="/vendor",tags=["Vendor"])
router.include_router(costumer_router.router, prefix="/costumer",tags=["Costumer"])
router.include_router(subscription_router.router, prefix="/subscription",tags=["Subscription"])
router.include_router(blog_router.router, prefix="/blog",tags=["Blog"])
