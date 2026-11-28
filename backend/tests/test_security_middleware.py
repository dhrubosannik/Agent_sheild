"""Request-size, rate-limit, proxy and security-header tests (Phase 13.2, P5)."""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest

from backend.app.core.config import Settings, get_settings
from backend.app.core.rate_limit import InMemoryRateLimiter, validate_rate_limit_configuration
from backend.app.core.security_middleware import API_CSP, DOCS_CSP, SecurityHardeningMiddleware, client_address
from backend.app.main import app as real_app


def _app(limit: int = 3) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        return {"size": len(await request.body())}

    @app.get("/ping")
    def ping():
        return {"ok": True}

    app.add_middleware(SecurityHardeningMiddleware, limiter=InMemoryRateLimiter(limit, 60))
    return app


def test_rate_limit_returns_429_with_retry_after() -> None:
    client = TestClient(_app(limit=3))
    codes = [client.get("/ping").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    blocked = client.get("/ping")
    assert blocked.headers["retry-after"] == str(get_settings().rate_limit_window_seconds)
    assert blocked.headers["content-security-policy"] == API_CSP


def test_rate_limit_is_per_client() -> None:
    app = _app(limit=1)
    a = TestClient(app, client=("198.51.100.1", 1))
    b = TestClient(app, client=("198.51.100.2", 1))
    assert a.get("/ping").status_code == 200
    assert a.get("/ping").status_code == 429
    assert b.get("/ping").status_code == 200


def test_declared_oversized_body_rejected() -> None:
    client = TestClient(_app(limit=100))
    res = client.post("/echo", content=b"x" * (get_settings().max_request_bytes + 1))
    assert res.status_code == 413


def test_chunked_body_without_content_length_is_counted() -> None:
    client = TestClient(_app(limit=100))
    limit = get_settings().max_request_bytes

    def chunks():
        for _ in range(limit // 4096 + 2):
            yield b"y" * 4096

    res = client.post("/echo", content=chunks())
    assert res.status_code == 413
    ok = client.post("/echo", content=iter([b"a" * 10, b"b" * 10]))
    assert ok.status_code == 200 and ok.json() == {"size": 20}


def test_forwarded_for_ignored_without_trusted_proxy() -> None:
    settings = Settings(trusted_proxy_count=0)
    scope = {"client": ("10.0.0.1", 1), "headers": [(b"x-forwarded-for", b"203.0.113.5")]}
    assert client_address(scope, settings) == "10.0.0.1"


def test_forwarded_for_uses_trusted_hop_and_ignores_spoofed_prefix() -> None:
    settings = Settings(trusted_proxy_count=1)
    scope = {"client": ("10.0.0.1", 1), "headers": [(b"x-forwarded-for", b"1.1.1.1, 203.0.113.5")]}
    assert client_address(scope, settings) == "203.0.113.5"


def test_production_refuses_in_memory_limiter_without_single_instance_ack() -> None:
    with pytest.raises(RuntimeError):
        validate_rate_limit_configuration(Settings(environment="production", database_mode="sqlite", rate_limit_backend="memory"))
    validate_rate_limit_configuration(
        Settings(environment="production", rate_limit_backend="memory", rate_limit_single_instance=True)
    )
    validate_rate_limit_configuration(Settings(environment="production", rate_limit_backend="firestore"))


def test_swagger_docs_and_openapi_are_served_with_compatible_csp() -> None:
    client = TestClient(real_app)
    docs = client.get("/docs")
    assert docs.status_code == 200
    csp = docs.headers["content-security-policy"]
    assert csp == DOCS_CSP
    # Every external asset the Swagger page references must be allowed.
    assert "https://cdn.jsdelivr.net/npm/swagger-ui-dist" in docs.text
    assert "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" in csp
    assert "https://fastapi.tiangolo.com" in csp
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    assert openapi.json()["info"]["title"] == "AgentShield"
    assert openapi.headers["content-security-policy"] == API_CSP
    assert client.get("/redoc").headers["content-security-policy"] == DOCS_CSP
