from app.v1.services.permission.permission_manager import PermissionManager


def get_permission_manager() -> PermissionManager:
    return PermissionManager()
