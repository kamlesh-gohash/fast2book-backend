from app.v1.services.offer.offer_manager import OfferManager


def get_offer_manager() -> OfferManager:
    return OfferManager()
