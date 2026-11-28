from backend.app.core.auth import (
    AuthenticatedUser,
    UserRole,
    get_authenticated_user,
    require_roles,
)
from fastapi import HTTPException
from backend.app.core import auth as auth_module
from backend.app.core import firebase as firebase_module


class _ProductionSettings:
    firebase_auth_required = True
    environment = "production"
    firebase_project_id = "agentshield-prod"
    firebase_auth_emulator_host = None
    google_application_credentials = None


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


def test_token_verification_extracts_role_and_uid(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())
    monkeypatch.setattr(
        auth_module,
        "verify_firebase_id_token",
        lambda token: {"uid": "user-123", "role": "REVIEWER", "aud": "agentshield-prod", "email_verified": True},
    )

    user = get_authenticated_user(authorization="Bearer valid-token")
    assert user.uid == "user-123"
    assert user.role == UserRole.REVIEWER
    assert user.email_verified is True


def test_token_verification_defaults_unknown_role_to_viewer(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())
    monkeypatch.setattr(
        auth_module,
        "verify_firebase_id_token",
        lambda token: {"uid": "user-456", "aud": "agentshield-prod", "email_verified": True},
    )

    user = get_authenticated_user(authorization="Bearer valid-token")
    assert user.uid == "user-456"
    assert user.role == UserRole.VIEWER
    assert user.email_verified is True


def test_insufficient_role_raises_403(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())
    monkeypatch.setattr(
        auth_module,
        "verify_firebase_id_token",
        lambda token: {"uid": "user-viewer", "role": "VIEWER", "aud": "agentshield-prod", "email_verified": True},
    )

    admin_only = require_roles(UserRole.ADMIN)
    try:
        admin_only(authorization="Bearer valid-token")
        assert False, "VIEWER must not access ADMIN endpoint"
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "Insufficient role permissions" in exc.detail


def test_unverified_email_token_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())
    monkeypatch.setattr(
        auth_module,
        "verify_firebase_id_token",
        lambda token: {"uid": "user-unverified", "role": "ADMIN", "aud": "agentshield-prod", "email_verified": False},
    )

    try:
        get_authenticated_user(authorization="Bearer valid-token")
        assert False, "Unverified email must be rejected with 403"
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "Email verification is required" in exc.detail


def test_token_missing_email_verified_claim_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProductionSettings())
    monkeypatch.setattr(
        auth_module,
        "verify_firebase_id_token",
        lambda token: {"uid": "user-noclaim", "role": "ADMIN", "aud": "agentshield-prod"},
    )

    try:
        get_authenticated_user(authorization="Bearer valid-token")
        assert False, "Missing email_verified claim must default to false and be rejected"
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "Email verification is required" in exc.detail


def test_token_verification_rejects_project_mismatch(monkeypatch) -> None:
    class _MockSettings:
        firebase_project_id = "expected-project"
        firebase_auth_emulator_host = None
        google_application_credentials = None
        environment = "development"

    monkeypatch.setattr(firebase_module, "get_settings", lambda: _MockSettings())
    monkeypatch.setattr(firebase_module, "get_firebase_app", lambda: "mock_app")
    monkeypatch.setattr(
        firebase_module.auth,
        "verify_id_token",
        lambda token, app: {"uid": "user-1", "aud": "different-project"},
    )

    try:
        firebase_module.verify_firebase_id_token("some-token")
        assert False, "Project mismatch must be rejected"
    except firebase_module.FirebaseConfigurationError as exc:
        assert "project identity mismatch" in str(exc).lower()
