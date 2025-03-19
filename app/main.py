from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles  # Import StaticFiles
from scripts.seed import seed_categorys, seed_data, seed_payment_types

from app.v1.config.constants import FRONT_URL
from app.v1.config.db import initiate_database
from app.v1.middleware.auth import AuthMiddleware
from app.v1.middleware.exception_handlers.custom_handlers import exception_handlers
from app.v1.middleware.response_format import add_response_format
from app.v1.routers.base_router import router


@asynccontextmanager
async def lifespan(app: FastAPI):

    await initiate_database()
    await seed_data()
    await seed_payment_types()
    await seed_categorys()

    yield


app = FastAPI(lifespan=lifespan, exception_handlers=exception_handlers, openapi=False)
# app.mount("/media", StaticFiles(directory="/var/www/python/fast-api/fast2book-backend/app/v1/media"), name="media")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# app.add_middleware(AuthMiddleware)
app.include_router(router)


app.middleware("http")(add_response_format)
