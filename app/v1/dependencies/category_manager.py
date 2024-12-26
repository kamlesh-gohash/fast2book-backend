from app.v1.services.category.category_manager import CategoryManager


def get_category_manager() -> CategoryManager:
    return CategoryManager()
