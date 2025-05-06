from datetime import datetime

from bcrypt import gensalt, hashpw

from app.v1.models import User, category_collection, payment_collection, transfer_amount_collection
from app.v1.models.category import Category
from app.v1.models.payment import PaymentType
from app.v1.models.permission import DEFAULT_MENU_STRUCTURE
from app.v1.models.transfer_amount import TransferAmount


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
            email="fast2book@yopmail.com",
            password=hashed_password,
            user_role=2,
            phone="9928821641",
            created_at=datetime.utcnow(),
            menu=DEFAULT_MENU_STRUCTURE,
        )
        await seed_user.create()
        print("Admin user seeded successfully!")
    else:
        print("Admin user already exists!")


# async def seed_payment_types():
#     """Seed payment types into the database."""
#     payment_methods = [
#         {"name": "GST", "description": "GST Payment"},
#         {"name": "Platform Fees", "description": "Platform Fees Payment"},
#     ]

#     for method in payment_methods:
#         print(f"Seeding payment type: {method['name']}")
#         # Check if the payment type already exists
#         existing_method = await payment_collection.count_documents({"name": method["name"]})
#         if existing_method == 0:
#             # Create a new payment type
#             payment_type = PaymentType(name=method["name"], description=method["description"])
#             await payment_collection.insert_one(payment_type.dict())
#             print(f"Payment type '{method['name']}' seeded successfully!")
#         else:
#             print(f"Payment type '{method['name']}' already exists!")


async def seed_categorys():
    """Seed categorys into the database."""
    categories = [
        {"name": "Doctor"},
        {"name": "Salon"},
        {"name": "Cater"},
    ]

    for category in categories:
        print(f"Seeding category: {category['name']}")
        # Check if the category already exists
        existing_category = await category_collection.count_documents({"name": category["name"]})
        if existing_category == 0:
            # Create a new category
            seed_category = Category(
                name=category["name"],
                slug=category["name"].lower().replace(" ", "-"),
                created_at=datetime.utcnow(),
            )

            await seed_category.create()
            print(f"Category '{category['name']}' seeded successfully!")
        else:
            print(f"Category '{category['name']}' already exists!")


async def seed_payment_types():
    """Seed payment types into the database."""
    payment_methods = [
        {
            "name": "GST",
            "description": "GST Fees",
            "charge_type": "percentage",
            "charge_value": 18,
        },
        {
            "name": "Platform Fees",
            "description": "Platform Fees",
            "charge_type": "fixed",
            "charge_value": 50,
        },
    ]

    for method in payment_methods:
        print(f"Seeding payment type: {method['name']}")
        # Check if the payment type already exists
        existing_method = await payment_collection.count_documents({"name": method["name"]})
        if existing_method == 0:
            # Create a new payment type
            payment_type = PaymentType(
                name=method["name"],
                description=method["description"],
                charge_type=method["charge_type"],
                charge_value=method["charge_value"],
            )
            await payment_collection.insert_one(payment_type.dict())
            print(f"Payment type '{method['name']}' seeded successfully!")
        else:
            print(f"Payment type '{method['name']}' already exists!")


async def seed_transfar_amount():
    """Seed transfer amount."""
    try:
        # Check if any document exists using Beanie's count
        existing = await TransferAmount.find().count()

        if not existing:
            transfer_amount = TransferAmount(value=0.0)
            await transfer_amount.insert()  # Now this will work
            print("Value Limit Added Successfully")
        else:
            print("Already set value limit")
    except Exception as ex:
        print(f"Error in Adding Value Limit: {str(ex)}")
        raise
