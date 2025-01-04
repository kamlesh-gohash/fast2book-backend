from datetime import datetime

from bcrypt import gensalt, hashpw

from app.v1.models import User


def hash_password(password: str) -> str:
    """Hash the password using bcrypt."""
    return hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")


async def seed_data():
    existing_count = await User.find({"user_role": 2}).count()
    if existing_count == 0:
        hashed_password = hash_password("Admin@123")
        seed_user = User(
            first_name="SUPER",
            last_name="ADMIN",
            email="vicky@yopmail.com",
            password=hashed_password,
            user_role=2,
            phone="+919928821640",
            created_at=datetime.utcnow(),
        )
        await seed_user.create()
        print("Admin user seeded successfully!")
    else:
        print("Admin user already exists!")
