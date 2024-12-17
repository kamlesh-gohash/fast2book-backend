from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from models.user import User
from app.v1.config import DATABASE_URL
from app.v1.config import DATABASE_NAME


async def init_db():
    client = AsyncIOMotorClient(DATABASE_URL)
    await init_beanie(database=client[DATABASE_NAME], document_models=[User])
