import os

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles  # Import StaticFiles
from scripts.seed import seed_categorys, seed_data, seed_payment_types, seed_transfar_amount
from starlette.middleware.base import BaseHTTPMiddleware

# app.middleware("http")(add_response_format)
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from app.v1.config.constants import FRONT_URL
from app.v1.config.db import initiate_database
from app.v1.middleware.exception_handlers.custom_handlers import exception_handlers
from app.v1.middleware.response_format import add_response_format
from app.v1.routers.base_router import router


# @asynccontextmanager
# async def lifespan(app: FastAPI):

#     await initiate_database()
#     await seed_data()
#     await seed_payment_types()
#     await seed_categorys()

#     yield


# app = FastAPI(lifespan=lifespan, exception_handlers=exception_handlers, openapi=False)
# # app.mount("/media", StaticFiles(directory="/var/www/python/fast-api/fast2book-backend/app/v1/media"), name="media")


# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# app.include_router(router)


@asynccontextmanager
async def lifespan(app: FastAPI):

    await initiate_database()
    await seed_data()
    await seed_payment_types()
    await seed_categorys()
    await seed_transfar_amount()

    yield


app = FastAPI(lifespan=lifespan, exception_handlers=exception_handlers, openapi=False)

# CORS (Configure based on your needs)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://fast2book.com", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Protect against Host Header Attacks

# Add Security Headers
if os.getenv("DEBUG") == "True":

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["fast2book.com", "*.fast2book.com"])

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            response.headers["X-Frame-Options"] = "DENY"  # Prevent Clickjacking
            response.headers["X-Content-Type-Options"] = "nosniff"  # Prevent MIME type sniffing
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"  # Enforce HTTPS
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"  # Prevent XSS
            )
            return response

    app.add_middleware(SecurityHeadersMiddleware)

app.include_router(router)

app.middleware("http")(add_response_format)
