from datetime import datetime

from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.v1.config import DATABASE_NAME, DATABASE_URL
from app.v1.models.user import User


async def initiate_database():
    client = AsyncIOMotorClient(DATABASE_URL)
    await init_beanie(
        database=client[DATABASE_NAME],
        document_models=[
            "app.v1.models.user.User",
            "app.v1.models.category.Category",
            "app.v1.models.transfer_amount.TransferAmount",
        ],
    )
    print("MongoDB Connected")
