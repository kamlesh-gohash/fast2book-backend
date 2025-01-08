from app.v1.services.payment.payment_manager import PaymentManager


def get_payment_manager() -> PaymentManager:
    return PaymentManager()
