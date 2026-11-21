from pathlib import Path
import pytest

from agentshield import (
    AgentShield,
    AgentShieldConfigurationError,
    ShieldConfig,
)
from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import SecurityDecision


def test_client_init_with_default_policy() -> None:
    shield = AgentShield()
    assert shield.policy.version == 1
    assert "example.org" in shield.policy.approved_domains


def test_client_init_with_missing_policy_raises() -> None:
    with pytest.raises(AgentShieldConfigurationError):
        AgentShield(policy_path=Path("non_existent_policy.yaml"))


def test_client_wrap_method() -> None:
    shield = AgentShield()

    def my_plain_tool(to: str, body: str) -> str:
        return f"Sent to {to}: {body}"

    wrapped = shield.wrap(my_plain_tool, tool_name="send_email")
    assert wrapped.__name__ == "my_plain_tool"

    result = wrapped(to="user@example.org", body="Clean message")
    assert result == "Sent to user@example.org: Clean message"
    assert shield.last_result is not None
    assert shield.last_result.decision == SecurityDecision.ALLOW


def test_audit_callback_and_event_recording() -> None:
    callback_events: list[AuditEvent] = []

    def audit_hook(event: AuditEvent) -> None:
        callback_events.append(event)

    shield = AgentShield(audit_callback=audit_hook)

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> str:
        return "sent"

    # Execution 1: Allowed
    send_email(to="user@example.org", body="Safe message")

    assert len(shield.audit_events) == 1
    assert len(callback_events) == 1
    assert shield.audit_events[0].decision == SecurityDecision.ALLOW

    # Execution 2: Blocked
    send_email(to="attacker@unapproved.test", body="Leaking DEMO_SECRET")

    assert len(shield.audit_events) == 2
    assert len(callback_events) == 2
    assert shield.audit_events[1].decision == SecurityDecision.BLOCK

    # Confirm privacy: DEMO_SECRET does not appear in audit event fields
    event2_str = shield.audit_events[1].model_dump_json()
    assert "DEMO_SECRET" not in event2_str
