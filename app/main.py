from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.v1.config.db import initiate_database
from app.v1.routers.base_router import router
from app.v1.middleware.exception_handlers.custom_handlers import exception_handlers
from app.v1.middleware.response_format import add_response_format
from contextlib import asynccontextmanager
from app.v1.config.constants import FRONT_URL
from scripts.seed import seed_data
from fastapi.staticfiles import StaticFiles  # Import StaticFiles

@asynccontextmanager
async def lifespan(app: FastAPI):

    await initiate_database()
    await seed_data()
    
    yield


app = FastAPI(lifespan=lifespan, exception_handlers=exception_handlers, openapi=False)
# app.mount("/media", StaticFiles(directory="/var/www/python/fast-api/fast2book-backend/app/v1/media"), name="media")


app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)


app.middleware("http")(add_response_format)
