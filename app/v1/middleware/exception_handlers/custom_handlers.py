from fastapi import HTTPException
from fastapi.responses import JSONResponse
from app.v1.utils.response.response_format import record_not_found
from app.v1.utils.response.response_code import ResponseCode


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


# Define exception handlers
exception_handlers = {
    404: not_found,  # Register the custom 404 handler
    Exception: custom_exception_handler,  # Handle all uncaught exceptions
}
