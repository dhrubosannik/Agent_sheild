from datetime import UTC, datetime
from pathlib import Path
import pytest
import sqlite3

from backend.app.models.approval import Approval
from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import ApprovalStatus, DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.storage.approval_repository import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalRepository,
)
from backend.app.storage.audit_repository import AuditRepository
from backend.app.storage.database import Database


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_agentshield.db"
    return Database(db_path=db_file)


def test_database_initializes_successfully(test_db: Database) -> None:
    with test_db.connection() as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert "audit_events" in tables
        assert "approvals" in tables


def test_audit_event_inserted_and_retrieved(test_db: Database) -> None:
    repo = AuditRepository(db=test_db)
    event = AuditEvent(
        event_id="evt-001",
        timestamp=datetime.now(UTC),
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        policy_id="allow-safe-email",
        reason_codes=["SAFE_ACTION"],
        destination_class=DestinationClass.APPROVED,
        data_labels=["CLEAN"],
        risk_signals=[],
        payload_fingerprint="sha256:abc123",
        execution_status=ExecutionStatus.EXECUTED,
    )

    created = repo.create(event)
    assert created.event_id == "evt-001"

    fetched = repo.get_by_id("evt-001")
    assert fetched is not None
    assert fetched.event_id == "evt-001"
    assert fetched.tool_name == "send_email"
    assert fetched.decision == SecurityDecision.ALLOW
    assert fetched.destination_class == DestinationClass.APPROVED


def test_duplicate_event_id_rejected(test_db: Database) -> None:
    repo = AuditRepository(db=test_db)
    event = AuditEvent(
        event_id="evt-dup",
        timestamp=datetime.now(UTC),
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        policy_id="rule-1",
        reason_codes=[],
        destination_class=DestinationClass.APPROVED,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.EXECUTED,
    )

    repo.create(event)

    with pytest.raises(sqlite3.IntegrityError):
        repo.create(event)


def test_pagination_and_decision_filtering(test_db: Database) -> None:
    repo = AuditRepository(db=test_db)

    # Insert 10 events: 5 ALLOW, 5 BLOCK
    for i in range(10):
        decision = SecurityDecision.ALLOW if i % 2 == 0 else SecurityDecision.BLOCK
        repo.create(
            AuditEvent(
                event_id=f"evt-{i:03d}",
                timestamp=datetime.now(UTC),
                tool_name="send_email" if i < 5 else "export_file",
                decision=decision,
                policy_id="test-policy",
                reason_codes=[],
                destination_class=DestinationClass.APPROVED if decision == SecurityDecision.ALLOW else DestinationClass.UNAPPROVED,
                data_labels=[],
                risk_signals=[],
                payload_fingerprint=None,
                execution_status=ExecutionStatus.EXECUTED if decision == SecurityDecision.ALLOW else ExecutionStatus.NOT_EXECUTED,
            )
        )

    # Pagination: limit 3, offset 0
    items, total = repo.list_events(limit=3, offset=0)
    assert total == 10
    assert len(items) == 3

    # Decision filtering: BLOCK only
    block_items, block_total = repo.list_events(decision=SecurityDecision.BLOCK)
    assert block_total == 5
    assert all(e.decision == SecurityDecision.BLOCK for e in block_items)

    # Tool name filtering: export_file only
    export_items, export_total = repo.list_events(tool_name="export_file")
    assert export_total == 5
    assert all(e.tool_name == "export_file" for e in export_items)


def test_approval_creation_and_update(test_db: Database) -> None:
    audit_repo = AuditRepository(db=test_db)
    approval_repo = ApprovalRepository(db=test_db)

    event = AuditEvent(
        event_id="evt-apr-1",
        timestamp=datetime.now(UTC),
        tool_name="export_file",
        decision=SecurityDecision.REQUIRE_APPROVAL,
        policy_id="approve-external-export",
        reason_codes=["POLICY_APPROVAL_RULE"],
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.PENDING_APPROVAL,
    )
    audit_repo.create(event)

    approval = Approval(
        approval_id="apr-001",
        event_id="evt-apr-1",
        tool_name="export_file",
        requested_action="Export sensitive records",
        destination_class=DestinationClass.UNAPPROVED,
        status=ApprovalStatus.PENDING,
        created_at=datetime.now(UTC),
    )
    approval_repo.create(approval)

    fetched = approval_repo.get_by_id("apr-001")
    assert fetched is not None
    assert fetched.status == ApprovalStatus.PENDING

    # Review approval -> APPROVED
    updated = approval_repo.update_decision(
        approval_id="apr-001",
        decision=ApprovalStatus.APPROVED,
        reviewer="sec-admin",
    )
    assert updated.status == ApprovalStatus.APPROVED
    assert updated.reviewer == "sec-admin"
    assert updated.reviewed_at is not None


def test_invalid_approval_transitions_rejected(test_db: Database) -> None:
    audit_repo = AuditRepository(db=test_db)
    approval_repo = ApprovalRepository(db=test_db)

    event = AuditEvent(
        event_id="evt-apr-2",
        timestamp=datetime.now(UTC),
        tool_name="export_file",
        decision=SecurityDecision.REQUIRE_APPROVAL,
        policy_id="approve-export",
        reason_codes=[],
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.PENDING_APPROVAL,
    )
    audit_repo.create(event)

    approval_repo.create(
        Approval(
            approval_id="apr-002",
            event_id="evt-apr-2",
            tool_name="export_file",
            requested_action="Export",
            destination_class=DestinationClass.UNAPPROVED,
            status=ApprovalStatus.PENDING,
            created_at=datetime.now(UTC),
        )
    )

    # First decision works
    approval_repo.update_decision("apr-002", ApprovalStatus.REJECTED, reviewer="reviewer-1")

    # Second decision must raise conflict
    with pytest.raises(ApprovalConflictError):
        approval_repo.update_decision("apr-002", ApprovalStatus.APPROVED, reviewer="reviewer-2")

    # Non-existent approval raises 404 error
    with pytest.raises(ApprovalNotFoundError):
        approval_repo.update_decision("apr-nonexistent", ApprovalStatus.APPROVED, reviewer="reviewer-1")
