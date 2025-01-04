from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.v1.utils.response.response_code import ResponseCode
from app.v1.utils.response.response_format import success


async def add_response_format(request: Request, call_next):
    response = await call_next(request)

    # Handle StreamingResponse
    if isinstance(response, StreamingResponse):
        return response

    # Check for JSON response and apply success format
    if isinstance(response, JSONResponse):
        return JSONResponse(
            status_code=response.status_code if response.status_code else ResponseCode.success,
            content=success({"data": response.json()}),
        )

    # Default successful response formatting
    return JSONResponse(
        status_code=response.status_code if response.status_code else ResponseCode.success,
        content=success({"data": response.body.decode() if isinstance(response.body, bytes) else response.body}),
    )
