"""API hardening middleware (pure ASGI).

* Request-size limit enforced on the bytes actually received, so chunked
  bodies without Content-Length cannot bypass it.
* Rate limiting through a pluggable store (see ``rate_limit``). The client
  address is the socket peer unless ``TRUSTED_PROXY_COUNT`` > 0, in which case
  the address appended by the outermost trusted proxy in X-Forwarded-For is
  used (spoofed entries to its left are ignored).
* Security headers. API responses get ``default-src 'none'``; the Swagger UI
  and ReDoc pages get a CSP that allows the assets FastAPI loads for them.
"""

from __future__ import annotations

import json
from uuid import uuid4

import anyio

from .config import Settings, get_settings
from .rate_limit import RateLimitUnavailableError, RateLimiter, build_rate_limiter

API_CSP = "default-src 'none'; frame-ancestors 'none'"
# FastAPI's /docs and /redoc pages load JS/CSS from jsDelivr, an inline
# bootstrap script and the favicon from fastapi.tiangolo.com.
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "connect-src 'self'; "
    "worker-src blob:; "
    "frame-ancestors 'none'"
)
DOCS_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def client_address(scope: dict, settings: Settings) -> str:
    peer = scope.get("client")
    peer_host = peer[0] if peer else "unknown"
    hops = settings.trusted_proxy_count
    if hops <= 0:
        return peer_host
    forwarded = ""
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            forwarded = f"{forwarded},{value.decode('latin-1')}" if forwarded else value.decode("latin-1")
    chain = [part.strip() for part in forwarded.split(",") if part.strip()]
    # Each trusted proxy appends the address it received from; the entry
    # appended by the outermost trusted proxy is at index -hops.
    if len(chain) >= hops:
        return chain[-hops]
    return peer_host


class SecurityHardeningMiddleware:
    def __init__(self, app, limiter: RateLimiter | None = None) -> None:
        self.app = app
        self._limiter = limiter

    @property
    def limiter(self) -> RateLimiter:
        if self._limiter is None:
            self._limiter = build_rate_limiter(get_settings())
        return self._limiter

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        correlation_id = headers.get(b"x-correlation-id", b"").decode("latin-1")[:128] or str(uuid4())
        path = scope.get("path", "")
        csp = DOCS_CSP if path in DOCS_PATHS else API_CSP

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                extra = [
                    (b"x-correlation-id", correlation_id.encode("latin-1")),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", csp.encode()),
                    (b"cache-control", b"no-store"),
                ]
                existing = {name.lower() for name, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    (name, value) for name, value in extra if name not in existing
                ]
            await send(message)

        async def reject(status: int, detail: str, extra_headers: list[tuple[bytes, bytes]] | None = None):
            body = json.dumps({"detail": detail}).encode()
            await send_with_headers({
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
                + (extra_headers or []),
            })
            await send_with_headers({"type": "http.response.body", "body": body})

        # 1. Declared size.
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > settings.max_request_bytes:
                    await reject(413, "Request body exceeds the configured size limit.")
                    return
            except ValueError:
                await reject(400, "Invalid content-length header.")
                return

        # 2. Rate limit (before reading the body).
        key = f"ip:{client_address(scope, settings)}"
        try:
            allowed = await anyio.to_thread.run_sync(self.limiter.hit, key)
        except RateLimitUnavailableError:
            if not settings.rate_limit_fail_open:
                await reject(503, "Rate limiting unavailable.")
                return
            allowed = True
        if not allowed:
            await reject(429, "Rate limit exceeded.", [(b"retry-after", str(settings.rate_limit_window_seconds).encode())])
            return

        # 3. Actual size: buffer the body (bounded) so chunked uploads are counted.
        if scope.get("method") in BODY_METHODS:
            chunks: list[bytes] = []
            received = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > settings.max_request_bytes:
                    await reject(413, "Request body exceeds the configured size limit.")
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            replayed = False

            async def replay_receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, replay_receive, send_with_headers)
            return

        await self.app(scope, receive, send_with_headers)
