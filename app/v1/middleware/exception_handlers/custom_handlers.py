from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError  # Import RequestValidationError
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


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Extract validation errors
    errors = exc.errors()
    # Construct a detailed message for each error
    error_messages = []
    for error in errors:
        field = error.get("loc", ["unknown"])[-1]  # Get the field name
        error_messages.append(f"This field '{field}' is required")

    # Join all error messages into a single string
    detailed_message = "; ".join(error_messages) if error_messages else "Validation failed: Missing or invalid fields"

    return JSONResponse(
        status_code=ResponseCode.badRequest,  # Use 400 or a custom code
        content={
            "status": "BAD_REQUEST",
            "message": detailed_message,
            "data": None,  # Set to None as you don't want raw error details
        },
    )


# Define exception handlers
# exception_handlers = {
#     404: not_found,  # Register the custom 404 handler
#     Exception: custom_exception_handler,  # Handle all uncaught exceptions
# }

exception_handlers = {
    404: not_found,
    Exception: custom_exception_handler,
    HTTPException: custom_http_exception_handler,
    RequestValidationError: validation_exception_handler,
}
