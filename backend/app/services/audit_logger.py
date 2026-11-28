"""Audit logging service providing privacy-safe persistence for AgentShield."""

from datetime import UTC, datetime
from typing import Any

from ..models.approval import Approval
from ..models.audit_event import AuditEvent
from ..models.enums import ApprovalStatus, ExecutionStatus, SecurityDecision
from ..models.evaluation import EvaluationResult
from ..storage.approval_repository import ApprovalRepository
from ..storage.audit_repository import AuditRepository
from ..storage.database import Database, get_database


class AuditLogger:
    """Coordinates recording and updating privacy-safe audit records and approval entries."""

    def __init__(
        self,
        audit_repo: AuditRepository | None = None,
        approval_repo: ApprovalRepository | None = None,
        db: Database | None = None,
    ) -> None:
        if audit_repo is not None or approval_repo is not None:
            self.audit_repo = audit_repo or AuditRepository(db=db)
            self.approval_repo = approval_repo or ApprovalRepository(db=db)
        else:
            database = db or get_database()
            self.audit_repo = AuditRepository(db=database)
            self.approval_repo = ApprovalRepository(db=database)

    def log_event(
        self,
        evaluation_result: EvaluationResult,
        execution_status: ExecutionStatus | None = None,
        tool_name: str = "",
        requested_action: str = "",
        actor_uid: str | None = None,
    ) -> AuditEvent:
        """Persists an AuditEvent record from an EvaluationResult.

        If the decision is REQUIRE_APPROVAL, also persists a pending Approval record.
        Never stores raw payloads or secret values.
        """
        final_status = execution_status or evaluation_result.execution_status

        event = AuditEvent(
            event_id=evaluation_result.event_id,
            timestamp=datetime.now(UTC),
            tool_name=tool_name or "unknown_tool",
            decision=evaluation_result.decision,
            policy_id=evaluation_result.policy_id,
            reason_codes=evaluation_result.reason_codes,
            destination_class=evaluation_result.destination_class,
            data_labels=evaluation_result.data_labels,
            risk_signals=evaluation_result.risk_signals,
            payload_fingerprint=evaluation_result.payload_fingerprint,
            execution_status=final_status,
            actor_uid=actor_uid,
        )

        persisted_event = self.audit_repo.create(event)

        # If approval is required, create a corresponding Approval record
        if evaluation_result.decision == SecurityDecision.REQUIRE_APPROVAL:
            approval = Approval(
                approval_id=f"apr-{evaluation_result.event_id}",
                event_id=evaluation_result.event_id,
                tool_name=tool_name or "unknown_tool",
                requested_action=requested_action or f"Execute tool '{tool_name}'",
                destination_class=evaluation_result.destination_class,
                status=ApprovalStatus.PENDING,
                created_at=datetime.now(UTC),
            )
            # Avoid duplicate approval insertion if event already exists
            existing = self.approval_repo.get_by_event_id(evaluation_result.event_id)
            if existing is None:
                self.approval_repo.create(approval)

        return persisted_event

    def update_execution_status(
        self,
        event_id: str,
        execution_status: ExecutionStatus,
    ) -> bool:
        """Appends an EXECUTION_STATUS record; the original event is never modified."""
        return self.audit_repo.record_execution_status(event_id, execution_status)

    def get_event(self, event_id: str) -> AuditEvent | None:
        return self.audit_repo.get_by_id(event_id)

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[AuditEvent], int]:
        return self.audit_repo.list_events(
            limit=limit,
            offset=offset,
            decision=decision,
            tool_name=tool_name,
        )

    def list_events_page(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
        cursor: str | None = None,
    ) -> tuple[list[AuditEvent], int, str | None]:
        return self.audit_repo.list_events_page(
            limit=limit, offset=offset, decision=decision, tool_name=tool_name, cursor=cursor
        )

    def get_approval(self, approval_id: str) -> Approval | None:
        return self.approval_repo.get_by_id(approval_id)

    def list_approvals(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Approval], int]:
        return self.approval_repo.list_approvals(status=status, limit=limit, offset=offset)

    def list_approvals_page(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
        cursor: str | None = None,
    ) -> tuple[list[Approval], int, str | None]:
        return self.approval_repo.list_approvals_page(status=status, limit=limit, offset=offset, cursor=cursor)

    def review_approval(
        self,
        approval_id: str,
        decision: ApprovalStatus | str,
        reviewer: str,
    ) -> Approval:
        """Records a decision and its APPROVAL_DECISION audit record atomically."""
        return self.approval_repo.update_decision(
            approval_id=approval_id,
            decision=decision,
            reviewer=reviewer,
            audit_repo=self.audit_repo,
        )


_global_audit_logger: AuditLogger | None = None


def get_audit_logger(db: Database | None = None) -> AuditLogger:
    """Returns singleton audit logger or creates one with custom DB."""
    global _global_audit_logger
    if db is not None:
        return AuditLogger(db=db)
    if _global_audit_logger is None:
        _global_audit_logger = AuditLogger()
    return _global_audit_logger


def get_audit_service() -> AuditLogger:
    from ..core.config import get_settings
    settings = get_settings()
    """FastAPI dependency for obtaining the AuditLogger service."""
    if settings.database_mode.lower() == "firestore":
        from ..storage.firestore_audit_repository import FirestoreAuditRepository
        from ..storage.firestore_approval_repository import FirestoreApprovalRepository

        audit_repo = FirestoreAuditRepository()
        return AuditLogger(
            audit_repo=audit_repo,
            approval_repo=FirestoreApprovalRepository(client=audit_repo.client, audit_repo=audit_repo),
        )
    return get_audit_logger()



def reset_audit_logger_singleton() -> None:
    """Resets audit logger singleton (useful for testing)."""
    global _global_audit_logger
    _global_audit_logger = None
