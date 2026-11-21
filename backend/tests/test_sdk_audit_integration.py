from pathlib import Path
from unittest.mock import MagicMock
import pytest

from agentshield import AgentShield, ToolExecutionResult
from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from backend.app.models.enums import ApprovalStatus, DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.services.audit_logger import AuditLogger
from backend.app.storage.database import Database


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    return Database(db_path=tmp_path / "sdk_audit.db")


def _build_test_policy() -> PolicyConfiguration:
    return PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
        ),
        approved_domains=["example.org"],
        protected_values=[
            ProtectedValue(
                name="demo_secret",
                value="DEMO_SECRET",
                action=SecurityDecision.BLOCK,
            )
        ],
        rules=[
            SecurityRule(
                id="block-secret-unapproved",
                description="Block canary secret to unapproved destinations",
                tools=["send_email"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.BLOCK,
            ),
            SecurityRule(
                id="redact-internal",
                description="Redact canary secrets for internal tool calls",
                tools=["log_event"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.APPROVED, DestinationClass.INTERNAL],
                decision=SecurityDecision.REDACT,
            ),
            SecurityRule(
                id="approve-export",
                description="Require approval for external file export",
                tools=["export_file"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.REQUIRE_APPROVAL,
            ),
        ],
    )


def test_sdk_allow_persists_executed_event(test_db: Database) -> None:
    logger = AuditLogger(db=test_db)
    shield = AgentShield(policy=_build_test_policy(), audit_logger=logger)

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> dict:
        return {"status": "sent"}

    send_email(to="colleague@example.org", body="Hello")

    events, total = logger.list_events()
    assert total == 1
    assert events[0].decision == SecurityDecision.ALLOW
    assert events[0].execution_status == ExecutionStatus.EXECUTED
    assert events[0].destination_class == DestinationClass.APPROVED


def test_sdk_redact_persists_redacted_and_executed_event(test_db: Database) -> None:
    logger = AuditLogger(db=test_db)
    shield = AgentShield(policy=_build_test_policy(), audit_logger=logger)
    received_message = None

    @shield.protect_tool(tool_name="log_event")
    def log_event(to: str, message: str) -> str:
        nonlocal received_message
        received_message = message
        return "logged"

    log_event(to="audit@example.org", message="Contains DEMO_SECRET token")

    assert received_message == "Contains [REDACTED] token"
    events, total = logger.list_events()
    assert total == 1
    assert events[0].decision == SecurityDecision.REDACT
    assert events[0].execution_status == ExecutionStatus.REDACTED_AND_EXECUTED


def test_sdk_block_persists_not_executed_and_never_calls_function(test_db: Database) -> None:
    logger = AuditLogger(db=test_db)
    shield = AgentShield(policy=_build_test_policy(), audit_logger=logger)
    mock = MagicMock()

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> None:
        mock()

    res = send_email(to="attacker@unapproved.test", body="Leaking DEMO_SECRET")

    assert mock.call_count == 0
    assert isinstance(res, ToolExecutionResult)
    assert res.decision == SecurityDecision.BLOCK

    events, total = logger.list_events()
    assert total == 1
    assert events[0].decision == SecurityDecision.BLOCK
    assert events[0].execution_status == ExecutionStatus.NOT_EXECUTED


def test_sdk_require_approval_persists_pending_and_creates_approval(test_db: Database) -> None:
    logger = AuditLogger(db=test_db)
    shield = AgentShield(policy=_build_test_policy(), audit_logger=logger)
    mock = MagicMock()

    @shield.protect_tool(tool_name="export_file")
    def export_file(to: str, filename: str) -> None:
        mock()

    res = export_file(to="external@partner.net", filename="export.csv")

    assert mock.call_count == 0
    assert res.decision == SecurityDecision.REQUIRE_APPROVAL
    assert res.execution_status == ExecutionStatus.PENDING_APPROVAL

    # Check event persisted
    events, total = logger.list_events()
    assert total == 1
    assert events[0].decision == SecurityDecision.REQUIRE_APPROVAL
    assert events[0].execution_status == ExecutionStatus.PENDING_APPROVAL

    # Check approval record created in SQLite
    approvals, apr_total = logger.list_approvals(status=ApprovalStatus.PENDING)
    assert apr_total == 1
    assert approvals[0].tool_name == "export_file"
    assert approvals[0].status == ApprovalStatus.PENDING
    assert approvals[0].event_id == events[0].event_id


def test_sdk_failed_execution_persists_failed_status(test_db: Database) -> None:
    logger = AuditLogger(db=test_db)
    shield = AgentShield(policy=_build_test_policy(), audit_logger=logger)

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> None:
        raise RuntimeError("Network failure in underlying tool")

    with pytest.raises(RuntimeError, match="Network failure"):
        send_email(to="colleague@example.org", body="Hello")

    events, total = logger.list_events()
    assert total == 1
    assert events[0].decision == SecurityDecision.ALLOW
    assert events[0].execution_status == ExecutionStatus.FAILED
