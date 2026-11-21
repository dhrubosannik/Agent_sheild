from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
)
from backend.app.models.enums import DestinationClass, SecurityDecision
from backend.app.services.destination_classifier import classify_destination


def _make_policy_with_domains(domains: list[str]) -> PolicyConfiguration:
    return PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
        ),
        approved_domains=domains,
        protected_values=[],
        rules=[],
    )


def test_approved_email_domain() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"to": "user@example.org"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.APPROVED


def test_unapproved_email_domain() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"to": "user@unapproved.net"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.UNAPPROVED


def test_approved_https_domain() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"url": "https://example.org/api/v1/resource"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.APPROVED


def test_approved_subdomain() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"endpoint": "https://api.example.org/v1"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.APPROVED


def test_domain_spoofing_suffix_rejected() -> None:
    # user@example.org.attacker.test must NOT be classified as approved
    policy = _make_policy_with_domains(["example.org"])
    args = {"to": "user@example.org.attacker.test"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.UNAPPROVED


def test_domain_spoofing_prefix_rejected() -> None:
    # user@fakeexample.org must NOT be classified as approved
    policy = _make_policy_with_domains(["example.org"])
    args = {"to": "user@fakeexample.org"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.UNAPPROVED


def test_domain_spoofing_in_url_rejected() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"url": "https://example.org.attacker.test/webhook"}

    result = classify_destination(args, policy)

    assert result == DestinationClass.UNAPPROVED


def test_malformed_destination_returns_unknown() -> None:
    policy = _make_policy_with_domains(["example.org"])
    assert classify_destination({"to": "user@@example.org"}, policy) == DestinationClass.UNKNOWN
    assert classify_destination({"url": "http:///"}, policy) == DestinationClass.UNKNOWN
    assert classify_destination({"target": ""}, policy) == DestinationClass.UNKNOWN


def test_missing_destination_returns_unknown() -> None:
    policy = _make_policy_with_domains(["example.org"])
    args = {"query": "synthetic query", "limit": 10}

    result = classify_destination(args, policy)

    assert result == DestinationClass.UNKNOWN


def test_internal_destinations() -> None:
    policy = _make_policy_with_domains(["example.org"])

    assert classify_destination({"url": "http://localhost:8000/api"}, policy) == DestinationClass.INTERNAL
    assert classify_destination({"url": "http://127.0.0.1:8080"}, policy) == DestinationClass.INTERNAL
    assert classify_destination({"to": "admin@service.internal"}, policy) == DestinationClass.INTERNAL
    assert classify_destination({"to": "sys@cluster.local"}, policy) == DestinationClass.INTERNAL


def test_multiple_destinations_precedence() -> None:
    policy = _make_policy_with_domains(["example.org"])

    # If one of multiple recipients is unapproved, the action must be UNAPPROVED
    args = {"recipients": ["user1@example.org", "user2@attacker.test"]}
    assert classify_destination(args, policy) == DestinationClass.UNAPPROVED

    # If all recipients are approved, result is APPROVED
    all_app = {"recipients": ["user1@example.org", "user2@example.org"]}
    assert classify_destination(all_app, policy) == DestinationClass.APPROVED
