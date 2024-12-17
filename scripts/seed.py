from app.v1.models import User
from datetime import datetime


async def seed_data():
    existing_count = await User.find({"user_role": 2}).count()
    if existing_count == 0:
        hashed_password = User.hash_password("Admin@123")
        seed_user = User(
            first_name="SUPER",
            last_name="ADMIN",
            email="admin@gmail.com",
            password=hashed_password,
            user_role=2,
            created_at=datetime.utcnow(),
        )
        await seed_user.create()
        print("Admin user seeded successfully!")
    else:
        print("Admin user already exists!")
