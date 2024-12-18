from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager

from app.v1.routers import base_router as v1_router
from app.v1.config.db import initiate_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    await initiate_database()
    yield

app = FastAPI(lifespan=lifespan, openapi=False)

app.include_router(v1_router.router)


@app.get("/up")
async def up() -> str:
    return "ok"


# @app.get("/")
# async def root() -> RedirectResponse:
#     return RedirectResponse(url="/docs")
