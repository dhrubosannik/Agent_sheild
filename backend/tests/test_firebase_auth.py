from backend.app.core.auth import (
    AuthenticatedUser,
    UserRole,
    get_authenticated_user,
    require_roles,
)
from fastapi import HTTPException
from backend.app.core import auth as auth_module


class _ProductionSettings:
    firebase_auth_required = True
    environment = "production"


def test_local_development_identity_is_available() -> None:
    user = get_authenticated_user()
    assert user.uid == "local-demo"
    assert user.role == UserRole.ADMIN


def test_role_dependency_accepts_allowed_role() -> None:
    dependency = require_roles(UserRole.ADMIN, UserRole.REVIEWER)
    user = dependency()
    assert user.role == UserRole.ADMIN


def test_production_missing_token_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())

    try:
        get_authenticated_user(authorization=None)
        assert False, "Missing token must be rejected"
    except HTTPException as exc:
        assert exc.status_code == 401
