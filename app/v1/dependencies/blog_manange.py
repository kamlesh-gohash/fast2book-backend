from app.v1.services.blog.blog_manager import BlogManager


def get_blog_manager() -> BlogManager:
    return BlogManager()
