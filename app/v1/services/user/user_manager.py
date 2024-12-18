# app/v1/middleware/user_manager.py

import random
from app.v1.models import User
from app.v1.models import user_collection
from app.v1.utils.email import send_email


class UserManager:
    def generate_otp(self) -> str:
        """Generate a random OTP."""
        return f"{random.randint(100000, 999999)}"

    async def create_user(self, user: User) -> dict:
        """Create a new user in the database."""
        existing_user = await user_collection.find_one(
            {"$or": [{"email": user.email}, {"phone": user.phone}]}
        )
        if existing_user:
            raise ValueError("User with this email or phone already exists")

        otp = self.generate_otp()

        if user.email:
            await send_email(user.email, otp)

        user_dict = user.dict()
        user_dict["otp"] = otp

        result = await user_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)  # Ensure `_id` is string

        return user_dict  # Returns a valid dictionary

    async def get_user(self, email: str) -> dict:
        """Retrieve user details by email."""
        user = await user_collection.find_one({"email": email})
        if not user:
            raise ValueError(f"User with email '{email}' does not exist")
        user["_id"] = str(user["_id"])  # Convert ObjectId to string
        return user

    async def list_users(self) -> list:
        """List all users."""
        users = []
        async for user in user_collection.find():
            user["_id"] = str(user["_id"])  # Convert ObjectId to string
            users.append(user)
        return users

    async def update_user(self, email: str, update_data: dict) -> dict:
        """Update user details."""
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
        """Delete a user by email."""
        result = await user_collection.find_one_and_delete({"email": email})
        if not result:
            raise ValueError(f"User with email '{email}' does not exist")
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
        return result
