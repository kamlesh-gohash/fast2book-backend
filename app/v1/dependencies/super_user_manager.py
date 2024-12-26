from app.v1.services.superuser.super_user_manager import SuperUserManager


def get_super_user_manager() -> SuperUserManager:
    return SuperUserManager()
