from app.v1.services.subscription.subscription_manager import SubscriptionManager


def get_subscription_manager() -> SubscriptionManager:
    return SubscriptionManager()
