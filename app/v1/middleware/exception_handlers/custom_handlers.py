from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.v1.utils.response.response_code import ResponseCode
from app.v1.utils.response.response_format import record_not_found


# Custom 404 handler
async def not_found(request, exc: HTTPException):
    return JSONResponse(
        content=record_not_found({"message": "The route you are looking for does not exist"}),
        status_code=ResponseCode.recordNotFound,
    )


# Global Exception Handler for uncaught exceptions


async def custom_exception_handler(request, exc: Exception):
    return JSONResponse(
        status_code=ResponseCode.internalServerError,
        content={"message": str(exc)},
    )


async def custom_http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "UNAUTHORIZED",
            "message": "You are not authorized to access this Page.",
            "data": None,
        },
    )


# Define exception handlers
# exception_handlers = {
#     404: not_found,  # Register the custom 404 handler
#     Exception: custom_exception_handler,  # Handle all uncaught exceptions
# }

exception_handlers = {Exception: custom_exception_handler, HTTPException: custom_http_exception_handler}
