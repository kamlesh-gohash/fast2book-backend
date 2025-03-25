from app.v1.services.rating.rating_manager import RatingManager


def get_rating_manager() -> RatingManager:
    return RatingManager()
