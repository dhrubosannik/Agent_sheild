from backend.app.core.policy_models import ProtectedValue
from backend.app.models.enums import SecurityDecision
from backend.app.services.redaction_service import REDACTION_MARKER, redact_arguments


def _make_protected_values() -> list[ProtectedValue]:
    return [
        ProtectedValue(
            name="demo_secret",
            value="DEMO_SECRET",
            action=SecurityDecision.BLOCK,
        ),
        ProtectedValue(
            name="api_token",
            value="SECRET_API_TOKEN_999",
            action=SecurityDecision.BLOCK,
        ),
    ]


def test_configured_secrets_are_removed() -> None:
    protected = _make_protected_values()
    original = {"body": "Contact support with DEMO_SECRET for verification"}

    success, sanitized = redact_arguments(original, extra_protected_values=protected)

    assert success is True
    assert sanitized is not None
    assert "DEMO_SECRET" not in sanitized["body"]
    assert sanitized["body"] == f"Contact support with {REDACTION_MARKER} for verification"


def test_nested_values_are_redacted() -> None:
    protected = _make_protected_values()
    original = {
        "envelope": {
            "auth": {
                "token": "Bearer SECRET_API_TOKEN_999",
            },
            "recipients": [
                "user@example.org",
                "DEMO_SECRET@internal.test",
            ],
        }
    }

    success, sanitized = redact_arguments(original, extra_protected_values=protected)

    assert success is True
    assert sanitized is not None
    assert sanitized["envelope"]["auth"]["token"] == f"Bearer {REDACTION_MARKER}"
    assert sanitized["envelope"]["recipients"][1] == f"{REDACTION_MARKER}@internal.test"


def test_unrelated_content_is_preserved() -> None:
    protected = _make_protected_values()
    original = {
        "status": "active",
        "counter": 42,
        "flags": [True, False],
        "metadata": {"tags": ["audit", "demo"]},
        "secret": "contains DEMO_SECRET",
    }

    success, sanitized = redact_arguments(original, extra_protected_values=protected)

    assert success is True
    assert sanitized is not None
    assert sanitized["status"] == "active"
    assert sanitized["counter"] == 42
    assert sanitized["flags"] == [True, False]
    assert sanitized["metadata"] == {"tags": ["audit", "demo"]}
    assert sanitized["secret"] == f"contains {REDACTION_MARKER}"


def test_original_payload_remains_unchanged() -> None:
    protected = _make_protected_values()
    original = {"secret": "DEMO_SECRET"}

    success, sanitized = redact_arguments(original, extra_protected_values=protected)

    assert success is True
    assert sanitized is not None
    # Original dictionary must NOT be mutated
    assert original["secret"] == "DEMO_SECRET"


def test_unsafe_redaction_non_dict_rejected() -> None:
    success, sanitized = redact_arguments("not a dict")  # type: ignore[arg-type]

    assert success is False
    assert sanitized is None


def test_api_key_and_bearer_token_are_redacted() -> None:
    original = {
        "api_key": "sk-" + ("A" * 24),
        "headers": {"Authorization": "Bearer abcDEF123._-"},
    }

    success, sanitized = redact_arguments(original)

    assert success is True
    assert sanitized is not None
    assert sanitized["api_key"] == REDACTION_MARKER
    assert sanitized["headers"]["Authorization"] == REDACTION_MARKER
