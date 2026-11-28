"""Firebase environment selection and validation (shared-project safety)."""

from pathlib import Path

import pytest

from backend.app.core import firebase_config
from backend.app.core.config import Settings
from backend.app.core.firebase_config import (
    FirebaseConfigurationError,
    enforce_firebase_configuration,
    validate_firebase_configuration,
)

SHARED_ID = "shared-proj-123"  # test value; not the real project ID


@pytest.fixture(autouse=True)
def no_emulator_env(monkeypatch):
    monkeypatch.delenv("FIREBASE_AUTH_EMULATOR_HOST", raising=False)
    monkeypatch.delenv("FIRESTORE_EMULATOR_HOST", raising=False)


def _errors(test_mode: bool = False, **kwargs) -> list[str]:
    return validate_firebase_configuration(Settings(**kwargs), test_mode=test_mode).errors


def _cloud(**extra) -> dict:
    return dict(firebase_target="cloud", firebase_project_id=SHARED_ID, firebase_cloud_project_confirm=SHARED_ID, **extra)


def test_default_is_no_firebase_and_valid() -> None:
    report = validate_firebase_configuration(Settings(), test_mode=False)
    assert report.target == "none" and report.ok


def test_none_target_reports_missing_firebase_for_firestore_features() -> None:
    errors = _errors(database_mode="firestore", firebase_auth_required=True)
    assert any("DATABASE_MODE=firestore requires FIREBASE_TARGET" in e for e in errors)
    assert any("FIREBASE_AUTH_REQUIRED=true requires FIREBASE_TARGET" in e for e in errors)
    assert any("Production requires FIREBASE_TARGET=cloud" in e for e in _errors(environment="production"))


def test_project_id_without_explicit_target_never_connects() -> None:
    report = validate_firebase_configuration(Settings(firebase_project_id=SHARED_ID), test_mode=False)
    assert report.ok and report.target == "none"
    assert any("ignored because FIREBASE_TARGET=none" in w for w in report.warnings)


def test_invalid_target_rejected() -> None:
    assert any("FIREBASE_TARGET must be one of" in e for e in _errors(firebase_target="prod"))


def test_emulator_requires_hosts_and_project() -> None:
    errors = _errors(firebase_target="emulator", database_mode="firestore")
    assert any("FIREBASE_PROJECT_ID is required" in e for e in errors)
    assert any("FIREBASE_AUTH_EMULATOR_HOST is required" in e for e in errors)
    assert any("FIRESTORE_EMULATOR_HOST is required" in e for e in errors)
    ok = _errors(
        firebase_target="emulator",
        database_mode="firestore",
        firebase_project_id="demo-agentshield",
        firebase_auth_emulator_host="127.0.0.1:9099",
        firestore_emulator_host="127.0.0.1:8080",
    )
    assert ok == []


def test_emulator_with_non_demo_project_is_error_in_tests_warning_otherwise() -> None:
    settings = dict(firebase_target="emulator", firebase_project_id=SHARED_ID, firebase_auth_emulator_host="127.0.0.1:9099")
    assert any("not a demo-* project" in e for e in _errors(test_mode=True, **settings))
    report = validate_firebase_configuration(Settings(**settings), test_mode=False)
    assert report.ok and any("not a demo-* project" in w for w in report.warnings)


def test_emulator_refused_in_production() -> None:
    assert any("not allowed in production" in e for e in _errors(
        environment="production", firebase_target="emulator", firebase_project_id="demo-agentshield",
        firebase_auth_emulator_host="127.0.0.1:9099",
    ))


def test_cloud_refused_during_tests() -> None:
    assert any("refused during automated tests" in e for e in _errors(test_mode=True, **_cloud()))


def test_cloud_requires_explicit_confirmation_outside_production() -> None:
    errors = _errors(firebase_target="cloud", firebase_project_id=SHARED_ID)
    assert any("FIREBASE_CLOUD_PROJECT_CONFIRM" in e for e in errors)
    assert _errors(**_cloud()) == []
    assert _errors(environment="production", firebase_target="cloud", firebase_project_id=SHARED_ID) == []


def test_cloud_rejects_placeholder_and_invalid_project_ids() -> None:
    placeholder = "your-shared-firebase-project-id"
    errors = _errors(firebase_target="cloud", firebase_project_id=placeholder, firebase_cloud_project_confirm=placeholder)
    assert any("placeholder" in e for e in errors)
    assert any("not a valid" in e for e in _errors(firebase_target="cloud", firebase_project_id="Bad_ID", firebase_cloud_project_confirm="Bad_ID"))


def test_cloud_refuses_mixing_with_emulator_hosts(monkeypatch) -> None:
    assert any("must not be combined" in e for e in _errors(**_cloud(firestore_emulator_host="127.0.0.1:8080")))
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099")
    assert any("must not be combined" in e for e in _errors(**_cloud()))


def test_cloud_credentials_file_checks(tmp_path: Path, monkeypatch) -> None:
    assert any("does not exist" in e for e in _errors(**_cloud(google_application_credentials=str(tmp_path / "missing.json"))))

    outside = tmp_path / "sa.json"
    outside.write_text("{}")
    assert _errors(**_cloud(google_application_credentials=str(outside))) == []

    monkeypatch.setattr(firebase_config, "PROJECT_ROOT", tmp_path)
    assert any("inside the repository" in e for e in _errors(**_cloud(google_application_credentials=str(outside))))


def test_cloud_without_file_uses_adc_with_warning() -> None:
    report = validate_firebase_configuration(Settings(**_cloud()), test_mode=False)
    assert report.ok and any("Application Default Credentials" in w for w in report.warnings)


def test_report_never_contains_credential_contents(tmp_path: Path) -> None:
    secret = tmp_path / "sa.json"
    secret.write_text('{"private_key": "-----BEGIN PRIVATE KEY-----SECRETVALUE"}')
    report = validate_firebase_configuration(Settings(**_cloud(google_application_credentials=str(secret))), test_mode=False)
    rendered = report.render()
    assert "SECRETVALUE" not in rendered and str(secret) not in rendered


def test_enforce_raises_clear_message() -> None:
    with pytest.raises(FirebaseConfigurationError, match="Invalid Firebase configuration") as exc:
        enforce_firebase_configuration(Settings(database_mode="firestore"))
    assert "check_firebase_config.py" in str(exc.value)


def test_test_process_cannot_reach_cloud() -> None:
    """The root conftest sets AGENTSHIELD_TEST_MODE and isolates the env file."""
    import os

    assert os.environ["AGENTSHIELD_TEST_MODE"] == "1"
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ
    with pytest.raises(FirebaseConfigurationError):
        enforce_firebase_configuration(Settings(**_cloud()))
