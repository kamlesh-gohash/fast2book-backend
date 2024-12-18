from fastapi import FastAPI
from app.v1.config.db import initiate_database
from app.v1.routers.base_router import router
from app.v1.middleware.exception_handlers.custom_handlers import exception_handlers
from app.v1.middleware.response_format import add_response_format
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the database connection when the app starts
    await initiate_database()
    yield


# Initialize FastAPI app
app = FastAPI(lifespan=lifespan, exception_handlers=exception_handlers, openapi=False)

# Include versioned API router
app.include_router(router)

# Apply the global response middleware
app.middleware("http")(add_response_format)
