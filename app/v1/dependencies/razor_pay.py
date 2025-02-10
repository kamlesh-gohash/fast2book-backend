from app.v1.services.razorpay.razor_pay_manager import RazorPayManager


def get_razor_pay_manager() -> RazorPayManager:
    return RazorPayManager()
