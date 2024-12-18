from app.v1.models import User
import random
from app.v1.models import user_collection


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


async def send_email(email: str, otp: str):
    # Dummy email sender (replace with an email service)
    print(f"Sending OTP {otp} to email {email}")


class UserManager:
    async def create_user(self, user: User) -> dict:
        existing_user = await user_collection.find_one(
            {"$or": [{"email": user.email}, {"phone": user.phone}]}
        )
        if existing_user:
            raise ValueError("User with this email or phone already exists")

        otp = generate_otp()

        if user.email:
            await send_email(user.email, otp)

        user_dict = user.dict()
        user_dict["otp"] = otp

        result = await user_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)  # Ensure `_id` is string

        return user_dict  # Returns a valid dictionary

    async def get_user(self, email: str) -> dict:
        user = await user_collection.find_one({"email": email})
        if not user:
            raise ValueError(f"User with email '{email}' does not exist")
        user["_id"] = str(user["_id"])  # Convert ObjectId to string
        return user

    async def list_users(self) -> list:
        users = []
        async for user in user_collection.find():
            user["_id"] = str(user["_id"])  # Convert ObjectId to string
            users.append(user)
        return users

    async def update_user(self, email: str, update_data: dict) -> dict:
        result = await user_collection.find_one_and_update(
            {"email": email},
            {"$set": update_data},
            return_document=True
        )
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
        return result

    async def delete_user(self, email: str) -> dict:
        result = await user_collection.find_one_and_delete({"email": email})
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
        return result
