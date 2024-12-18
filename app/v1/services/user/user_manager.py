from app.v1.models import User
import random
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from starlette.requests import Request
from starlette.responses import JSONResponse

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"
def send_email(email: str, otp: str):
    # Dummy email sender (replace with an email service)
    print(f"Sending OTP {otp} to email {email}")
class UserManager:
    # _users_by_email: dict[str, User] = {}
    # _users_by_phone: dict[str, User] = {}
    _users_by_identifier: dict[str, User] = {}

    def create_user(self, user: User) -> User:
        if user.email in self._users_by_identifier:
            raise ValueError(f"User with email '{user.email}' already exists")
        if user.phone in self._users_by_identifier:
            raise ValueError(f"User with phone '{user.phone}' already exists")
        self._users_by_identifier[user.email] = user
        otp = generate_otp()
        if user.email:
            email = user.email
            send_email(email,otp)
        if user.phone:
            self._users_by_identifier[user.phone] = user
        return user

    def get_user(self, email: str) -> User:
        if email not in self._users_by_identifier:
            raise ValueError(f"User with email '{email}' does not exist")
        return self._users_by_identifier[email]

    def list_users(self) -> list[User]:
        return list(self._users_by_identifier.values())

    def update_user(self, email: str, user: User) -> User:
        if email not in self._users_by_identifier:
            raise ValueError(f"User with email '{email}' does not exist")
        self._users_by_identifier[email] = user
        return user

    def delete_user(self, email: str) -> User:
        if email not in self._users_by_identifier:
            raise ValueError(f"User with email '{email}' does not exist")
        return self._users_by_identifier.pop(email)
