from fastapi.responses import JSONResponse
from app.v1.utils.response.response_status import ResponseStatus


def success(data=None):
    return {
        "status": ResponseStatus.SUCCESS,
        "message": (
            data.get("message", "Your request is successfully executed")
            if data
            else "Your request is successfully executed"
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }


def failure(data=None, status_code=None):
    """
    Failure response that includes status code.
    """
    content = {
        "status": ResponseStatus.FAILURE,
        "message": (
            data.get("message", "Some error occurred while performing action.")
            if data
            else "Some error occurred while performing action."
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }

    # Return a JSONResponse with the appropriate status code
    return JSONResponse(
        status_code=status_code if status_code else 400, content=content  # Default to 400 if no status_code is provided
    )


def internal_server_error(data=None, status_code=None):
    """
    Failure response that includes status code.
    """
    content = {
        "status": ResponseStatus.SERVER_ERROR,
        "message": data.get("message", "Internal server error.") if data else "Internal server error.",
        "data": data.get("data", None) if data and data.get("data") else None,
    }

    # Return a JSONResponse with the appropriate status code
    return JSONResponse(status_code=status_code if status_code else 500, content=content)


def bad_request(data=None):
    return {
        "status": ResponseStatus.BAD_REQUEST,
        "message": (
            data.get("message", "Request parameters are invalid or missing.")
            if data
            else "Request parameters are invalid or missing."
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }


def record_not_found(data=None):
    return {
        "status": ResponseStatus.RECORD_NOT_FOUND,
        "message": (
            data.get("message", "Record(s) not found with specified criteria.")
            if data
            else "Record(s) not found with specified criteria."
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }


def validation_error(data=None):
    return {
        "status": ResponseStatus.VALIDATION_ERROR,
        "message": (
            data.get("message", "Invalid Data, Validation Failed.") if data else "Invalid Data, Validation Failed."
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }


def unauthorized(data=None):
    return {
        "status": ResponseStatus.UNAUTHORIZED,
        "message": (
            data.get("message", "You are not authorized to access the request")
            if data
            else "You are not authorized to access the request"
        ),
        "data": data.get("data", None) if data and data.get("data") else None,
    }
