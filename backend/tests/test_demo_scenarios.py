from pathlib import Path

from agentshield import AgentShield
from backend.app.models.enums import ApprovalStatus, DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.services.audit_logger import AuditLogger
from backend.app.storage.database import Database
from examples.demo_agent import DemoAgent
from examples.mock_tools import MockTools


def build_demo_shield(tmp_path: Path) -> tuple[AgentShield, AuditLogger]:
    logger = AuditLogger(db=Database(db_path=tmp_path / "demo.db"))
    shield = AgentShield(
        raise_on_block=False,
        raise_on_approval=False,
        return_execution_result=True,
        audit_logger=logger,
    )
    return shield, logger


def test_safe_scenario_allow_and_executes_once(tmp_path: Path) -> None:
    shield, logger = build_demo_shield(tmp_path)
    agent = DemoAgent(shield)

    result = agent.run_safe()

    assert result.decision == SecurityDecision.ALLOW
    assert result.destination_class == DestinationClass.APPROVED
    assert result.execution_status == ExecutionStatus.EXECUTED
    assert agent.tools.call_counts["send_email"] == 1
    event = logger.get_event(result.event_id)
    assert event is not None
    assert event.decision == SecurityDecision.ALLOW


def test_malicious_scenario_blocks_and_never_executes(tmp_path: Path) -> None:
    shield, logger = build_demo_shield(tmp_path)
    agent = DemoAgent(shield)

    result = agent.run_malicious()

    assert result.decision == SecurityDecision.BLOCK
    assert result.policy_id == "block-secret-to-unapproved"
    assert result.destination_class == DestinationClass.UNAPPROVED
    assert "PROTECTED_DATA" in result.reason_codes
    assert "UNAPPROVED_DESTINATION" in result.reason_codes
    assert result.execution_status == ExecutionStatus.NOT_EXECUTED
    assert agent.tools.call_counts["send_email"] == 0
    event = logger.get_event(result.event_id)
    assert event is not None
    assert "DEMO_SECRET" not in str(event.model_dump())


def test_redaction_scenario_sanitizes_tool_arguments(tmp_path: Path) -> None:
    shield, logger = build_demo_shield(tmp_path)
    agent = DemoAgent(shield)

    result = agent.run_redaction()

    assert result.decision == SecurityDecision.REDACT
    assert result.execution_status == ExecutionStatus.REDACTED_AND_EXECUTED
    assert agent.tools.call_counts["send_email"] == 1
    assert "DEMO_SECRET" not in str(agent.tools.last_arguments)
    assert "[REDACTED]" in str(agent.tools.last_arguments)
    assert result.result["status"] == "sent"
    event = logger.get_event(result.event_id)
    assert event is not None
    assert event.decision == SecurityDecision.REDACT
    assert "DEMO_SECRET" not in str(event.model_dump())


def test_approval_scenario_never_executes_export_and_records_reviews(tmp_path: Path) -> None:
    shield, logger = build_demo_shield(tmp_path)
    agent = DemoAgent(shield)

    approved, rejected = agent.run_approval()

    assert approved.decision == SecurityDecision.REQUIRE_APPROVAL
    assert rejected.decision == SecurityDecision.REQUIRE_APPROVAL
    assert approved.execution_status == ExecutionStatus.PENDING_APPROVAL
    assert rejected.execution_status == ExecutionStatus.PENDING_APPROVAL
    assert agent.tools.call_counts["export_file"] == 0

    approved_record = logger.get_approval(approved.approval_id) if approved.approval_id else None
    rejected_record = logger.get_approval(rejected.approval_id) if rejected.approval_id else None
    assert approved_record is not None
    assert rejected_record is not None
    assert approved_record.status == ApprovalStatus.APPROVED
    assert rejected_record.status == ApprovalStatus.REJECTED


def test_all_scenarios_generate_privacy_safe_events(tmp_path: Path) -> None:
    shield, logger = build_demo_shield(tmp_path)
    agent = DemoAgent(shield)

    safe = agent.run_safe()
    malicious = agent.run_malicious()
    redacted = agent.run_redaction()
    approved, rejected = agent.run_approval()

    event_ids = [safe.event_id, malicious.event_id, redacted.event_id, approved.event_id, rejected.event_id]
    events = [logger.get_event(event_id) for event_id in event_ids]

    assert all(event is not None for event in events)
    assert all("DEMO_SECRET" not in str(event.model_dump()) for event in events if event is not None)
