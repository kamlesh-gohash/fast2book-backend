from datetime import datetime

from bcrypt import gensalt, hashpw

from app.v1.models import User, payment_collection, category_collection
from app.v1.models.payment import PaymentType
from app.v1.models.category import Category


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


async def seed_payment_types():
    """Seed payment types into the database."""
    payment_methods = [
        {"name": "Card", "description": "Payment via credit or debit card"},
        {"name": "Razorpay", "description": "Payment via Razorpay gateway"},
        {"name": "PhonePe", "description": "Payment via PhonePe wallet"},
    ]

    for method in payment_methods:
        print(f"Seeding payment type: {method['name']}")
        # Check if the payment type already exists
        existing_method = await payment_collection.count_documents({"name": method["name"]})
        if existing_method == 0:
            # Create a new payment type
            payment_type = PaymentType(name=method["name"], description=method["description"])
            await payment_collection.insert_one(payment_type.dict())
            print(f"Payment type '{method['name']}' seeded successfully!")
        else:
            print(f"Payment type '{method['name']}' already exists!")


async def seed_categorys():
    """Seed categorys into the database."""
    categories = [
        {"name": "Doctor"},
        {"name": "Salon"},
        {"name": "Cator"},
    ]

    for category in categories:
        print(f"Seeding category: {category['name']}")
        # Check if the category already exists
        existing_category = await category_collection.count_documents({"name": category["name"]})
        if existing_category == 0:
            # Create a new category
            seed_category = Category(
                name=category["name"],
            )

            await seed_category.create()
            print(f"Category '{category['name']}' seeded successfully!")
        else:
            print(f"Category '{category['name']}' already exists!")
