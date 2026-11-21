from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.app.models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    DestinationClass,
    EvaluationResult,
    ExecutionStatus,
    SecurityDecision,
    ToolCall,
)


def test_valid_tool_call_creation() -> None:
    call = ToolCall(
        tool_name="send_email",
        arguments={"to": "approved@example.org", "body": "Synthetic body"},
        context={"source": "demo_agent"},
    )

    assert call.tool_name == "send_email"
    assert call.request_id is not None


def test_invalid_empty_tool_name() -> None:
    with pytest.raises(ValidationError):
        ToolCall(tool_name="   ", arguments={})


def test_valid_allow_decision() -> None:
    assert SecurityDecision("ALLOW") is SecurityDecision.ALLOW


def test_valid_block_decision() -> None:
    assert SecurityDecision("BLOCK") is SecurityDecision.BLOCK


def test_invalid_decision_rejected() -> None:
    with pytest.raises(ValueError):
        SecurityDecision("DENY")


def test_valid_evaluation_result() -> None:
    result = EvaluationResult(
        event_id="evt-1",
        decision=SecurityDecision.BLOCK,
        policy_id="block-secret-to-unapproved",
        reason_codes=["PROTECTED_DATA", "UNAPPROVED_DESTINATION"],
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=["PROTECTED"],
        payload_fingerprint="sha256:example",
        execution_status=ExecutionStatus.NOT_EXECUTED,
        explanation="Protected data cannot be sent to an unapproved destination.",
    )

    assert result.decision == SecurityDecision.BLOCK


def test_valid_audit_event() -> None:
    event = AuditEvent(
        event_id="evt-2",
        timestamp=datetime.now(UTC),
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        policy_id="default",
        reason_codes=[],
        destination_class=DestinationClass.APPROVED,
        data_labels=[],
        payload_fingerprint="sha256:example",
        execution_status=ExecutionStatus.EXECUTED,
    )

    assert event.destination_class == DestinationClass.APPROVED


def test_valid_approval() -> None:
    approval = Approval(
        approval_id="apr-1",
        event_id="evt-3",
        tool_name="export_file",
        requested_action="External export",
        destination_class=DestinationClass.UNAPPROVED,
        status=ApprovalStatus.PENDING,
        created_at=datetime.now(UTC),
    )

    assert approval.status == ApprovalStatus.PENDING


def test_invalid_approval_status_rejected() -> None:
    with pytest.raises(ValueError):
        ApprovalStatus("WAITING")
