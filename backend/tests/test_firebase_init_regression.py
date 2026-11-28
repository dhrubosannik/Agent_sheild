"""Regression: commit 9791375 made ``os`` a local name inside
get_firebase_app(), so any configured project raised UnboundLocalError and
every Firebase token was rejected. Exercise the real function (unmocked)."""

from backend.app.core import firebase as firebase_module
from backend.app.core.config import Settings


def _Settings() -> Settings:
    return Settings(
        firebase_target="emulator",
        firebase_project_id="demo-regression",
        firebase_auth_emulator_host="127.0.0.1:9099",
    )


def test_get_firebase_app_initializes_with_project(monkeypatch) -> None:
    import firebase_admin

    monkeypatch.setattr(firebase_module, "get_settings", _Settings)
    monkeypatch.setattr(firebase_admin, "get_app", lambda *a: (_ for _ in ()).throw(ValueError()))
    created = {}
    monkeypatch.setattr(firebase_admin, "initialize_app", lambda cred, opts: created.setdefault("opts", opts) or "app")
    firebase_module.get_firebase_app.cache_clear()
    try:
        firebase_module.get_firebase_app()
    finally:
        firebase_module.get_firebase_app.cache_clear()
    assert created["opts"] == {"projectId": "demo-regression"}
