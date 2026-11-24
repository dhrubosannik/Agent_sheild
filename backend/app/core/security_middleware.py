"""Small local API hardening middleware."""

from collections import deque
from time import monotonic
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings


class SecurityHardeningMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._requests: dict[str, deque[float]] = {}

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.max_request_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body exceeds the configured size limit."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid content-length header."},
                )

        client = request.client.host if request.client else "unknown"
        now = monotonic()
        window = deque()
        for timestamp in self._requests.get(client, deque()):
            if now - timestamp < settings.rate_limit_window_seconds:
                window.append(timestamp)
        if len(window) >= settings.rate_limit_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded."},
            )
        window.append(now)
        self._requests[client] = window

        correlation_id = request.headers.get("x-correlation-id", str(uuid4()))
        response = await call_next(request)
        response.headers["x-correlation-id"] = correlation_id
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["content-security-policy"] = "default-src 'none'"
        return response
