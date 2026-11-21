from backend.app.core.policy_models import ProtectedValue
from backend.app.models.enums import SecurityDecision
from backend.app.services.sensitive_data_detector import (
    SensitiveDetectionResult,
    detect_sensitive_data,
)


def _make_demo_policy() -> list[ProtectedValue]:
    return [
        ProtectedValue(
            name="demo_secret",
            value="DEMO_SECRET",
            action=SecurityDecision.BLOCK,
        )
    ]


def test_configured_demo_secret_detection() -> None:
    protected = _make_demo_policy()
    payload = {"message": "Here is DEMO_SECRET for testing"}

    result = detect_sensitive_data(payload, extra_protected_values=protected)

    assert "PROTECTED" in result.data_labels
    assert len(result.findings) >= 1

    finding = next(f for f in result.findings if f.label == "PROTECTED")
    assert finding.location == "message"
    assert finding.detection_type == "configured_secret"
    assert finding.severity == "HIGH"
    assert finding.is_configured_secret is True


def test_secret_detection_in_nested_dictionaries() -> None:
    protected = _make_demo_policy()
    payload = {
        "metadata": {
            "auth": {
                "credential": "DEMO_SECRET",
            }
        }
    }

    result = detect_sensitive_data(payload, extra_protected_values=protected)

    assert "PROTECTED" in result.data_labels
    finding = next(f for f in result.findings if f.label == "PROTECTED")
    assert finding.location == "metadata.auth.credential"


def test_secret_detection_in_lists() -> None:
    protected = _make_demo_policy()
    payload = {
        "items": [
            "benign_item_1",
            {"nested_key": "contains DEMO_SECRET inside string"},
        ]
    }

    result = detect_sensitive_data(payload, extra_protected_values=protected)

    assert "PROTECTED" in result.data_labels
    finding = next(f for f in result.findings if f.label == "PROTECTED")
    assert "items[1]" in finding.location


def test_email_pattern_detection() -> None:
    payload = {"recipient": "synthetic_user@example.com"}

    result = detect_sensitive_data(payload)

    assert "EMAIL" in result.data_labels
    finding = next(f for f in result.findings if f.label == "EMAIL")
    assert finding.location == "recipient"
    assert finding.detection_type == "pattern"
    assert finding.severity == "LOW"
    assert finding.is_configured_secret is False


def test_api_key_pattern_detection() -> None:
    payload = {"api_token": "sk-live1234567890abcdef123456"}

    result = detect_sensitive_data(payload)

    assert "API_KEY" in result.data_labels
    finding = next(f for f in result.findings if f.label == "API_KEY")
    assert finding.detection_type == "pattern"
    assert finding.severity == "HIGH"


def test_auth_token_pattern_detection() -> None:
    payload = {
        "auth_header": "Bearer syntheticTokenValue1234567890abcdef"
    }

    result = detect_sensitive_data(payload)

    assert "AUTH_TOKEN" in result.data_labels
    finding = next(f for f in result.findings if f.label == "AUTH_TOKEN")
    assert finding.severity == "HIGH"


def test_no_secret_value_leakage_in_findings() -> None:
    protected = _make_demo_policy()
    payload = {"secret_field": "DEMO_SECRET"}

    result = detect_sensitive_data(payload, extra_protected_values=protected)

    # Convert finding model to dict / str and confirm DEMO_SECRET is never present
    for finding in result.findings:
        finding_dict = finding.model_dump()
        for k, val in finding_dict.items():
            assert "DEMO_SECRET" not in str(val)
