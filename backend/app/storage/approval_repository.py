"""Approval records SQLite repository."""

from datetime import UTC, datetime
import sqlite3
from typing import Any

from ..models.approval import Approval
from ..models.audit_event import AuditEvent
from ..models.enums import (
    ApprovalStatus,
    DestinationClass,
    ExecutionStatus,
    RiskLevel,
    SecurityDecision,
)
from .database import Database, get_database

VALID_DECISION_TARGETS = frozenset(
    {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED}
)


class ApprovalNotFoundError(Exception):
    """Raised when an approval record is not found."""


class ApprovalConflictError(Exception):
    """Raised when an approval is not in PENDING state or has already been reviewed."""


class ApprovalAlreadyExistsError(ApprovalConflictError):
    """Raised when attempting to create an approval with an existing approval_id."""


class ApprovalUnauthorizedError(PermissionError):
    """Raised when separation of duties forbids self-approval/self-review."""


class ApprovalRepository:
    """Handles persistence and review transitions for Approval records."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def _row_to_approval(self, row: sqlite3.Row) -> Approval:
        keys = set(row.keys())
        created_at = datetime.fromisoformat(row["created_at"])
        requested_raw = row["requested_at"] if "requested_at" in keys else None
        requested_at = datetime.fromisoformat(requested_raw) if requested_raw else created_at
        reviewed_at = datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None
        reviewed_by = row["reviewed_by"] if "reviewed_by" in keys and row["reviewed_by"] else row["reviewer"]

        return Approval(
            approval_id=row["approval_id"],
            event_id=row["event_id"],
            user_id=(row["user_id"] if "user_id" in keys and row["user_id"] else "system"),
            agent_id=(row["agent_id"] if "agent_id" in keys and row["agent_id"] else "default-agent"),
            tool_name=row["tool_name"],
            requested_action=row["requested_action"],
            destination_class=DestinationClass(row["destination_class"]),
            risk_level=RiskLevel(row["risk_level"]) if "risk_level" in keys and row["risk_level"] else RiskLevel.MEDIUM,
            status=ApprovalStatus(row["status"]),
            requested_at=requested_at,
            created_at=created_at,
            reviewed_by=reviewed_by,
            reviewer=reviewed_by,
            reviewed_at=reviewed_at,
            decision_reason=row["decision_reason"] if "decision_reason" in keys else None,
            correlation_id=(row["correlation_id"] if "correlation_id" in keys and row["correlation_id"] else row["event_id"]),
            version=int(row["version"]) if "version" in keys and row["version"] is not None else 1,
        )

    def create(self, approval: Approval) -> Approval:
        """Creates a new approval record in PENDING state without overwriting existing records."""
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError("New approvals must start in PENDING status.")
        requested_ts = (approval.requested_at or approval.created_at or datetime.now(UTC)).isoformat()
        with self.db.connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO approvals (
                        approval_id, event_id, user_id, agent_id, tool_name, requested_action,
                        destination_class, risk_level, status, requested_at, created_at,
                        reviewed_by, reviewer, reviewed_at, decision_reason, correlation_id, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.approval_id,
                        approval.event_id,
                        approval.user_id,
                        approval.agent_id,
                        approval.tool_name,
                        approval.requested_action,
                        approval.destination_class.value,
                        approval.risk_level.value,
                        approval.status.value,
                        requested_ts,
                        requested_ts,
                        approval.reviewed_by,
                        approval.reviewer,
                        approval.reviewed_at.isoformat() if approval.reviewed_at else None,
                        approval.decision_reason,
                        approval.correlation_id,
                        approval.version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalAlreadyExistsError(
                    f"Approval '{approval.approval_id}' already exists."
                ) from exc
            conn.commit()
        return approval

    def get_by_id(self, approval_id: str) -> Approval | None:
        """Retrieves an approval by its approval_id."""
        with self.db.connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_approval(row)

    def get_by_event_id(self, event_id: str) -> Approval | None:
        """Retrieves an approval by its associated event_id."""
        with self.db.connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM approvals WHERE event_id = ?",
                (event_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_approval(row)

    def list_approvals_page(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
        cursor: str | None = None,
    ) -> tuple[list[Approval], int, str | None]:
        """Lists approvals newest first; ``cursor`` is the last approval_id of
        the previous page (keyset pagination on created_at, approval_id)."""
        where = ["1=1"]
        params: list[Any] = []
        if status is not None:
            where.append("status = ?")
            params.append(status.value if isinstance(status, ApprovalStatus) else str(status))
        limit = max(1, min(int(limit), 100))
        with self.db.connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM approvals WHERE {' AND '.join(where)}", params).fetchone()[0]
            page_where, page_params = list(where), list(params)
            if cursor:
                anchor = conn.execute("SELECT created_at FROM approvals WHERE approval_id = ?", (cursor,)).fetchone()
                if anchor is None:
                    raise ValueError("Invalid pagination cursor")
                page_where.append("(created_at < ? OR (created_at = ? AND approval_id < ?))")
                page_params.extend([anchor["created_at"], anchor["created_at"], cursor])
                offset = 0
            rows = conn.execute(
                f"SELECT * FROM approvals WHERE {' AND '.join(page_where)} "
                "ORDER BY created_at DESC, approval_id DESC LIMIT ? OFFSET ?",
                [*page_params, limit, max(0, offset)],
            ).fetchall()
            approvals = [self._row_to_approval(r) for r in rows]
        next_cursor = approvals[-1].approval_id if len(approvals) == limit else None
        return approvals, total, next_cursor

    def list_approvals(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Approval], int]:
        items, total, _ = self.list_approvals_page(status=status, limit=limit, offset=offset)
        return items, total

    def update_decision(
        self,
        approval_id: str,
        decision: ApprovalStatus | str,
        reviewer: str,
        audit_repo: Any | None = None,
        *,
        decision_reason: str | None = None,
        enforce_separation_of_duties: bool = False,
    ) -> Approval:
        """Records an APPROVED, REJECTED, or EXPIRED decision atomically."""
        target_status = decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        if target_status not in VALID_DECISION_TARGETS:
            raise ValueError(
                f"Invalid review decision: {target_status}. Must be APPROVED, REJECTED, or EXPIRED."
            )
        reviewer_id = reviewer.strip()
        if not reviewer_id:
            raise ValueError("Reviewer identity is required.")
        clean_reason = decision_reason.strip() if isinstance(decision_reason, str) and decision_reason.strip() else None
        reviewed_at = datetime.now(UTC)

        with self.db.write_transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if row is None:
                raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")
            existing = self._row_to_approval(row)
            if existing.status != ApprovalStatus.PENDING:
                raise ApprovalConflictError(
                    f"Approval '{approval_id}' has already been reviewed (current status: {existing.status.value})."
                )
            if (
                enforce_separation_of_duties
                and target_status in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED)
                and existing.user_id == reviewer_id
            ):
                raise ApprovalUnauthorizedError("Users cannot approve or reject their own request.")

            next_version = existing.version + 1
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?, reviewed_by = ?, reviewer = ?, reviewed_at = ?, decision_reason = ?, version = ?
                WHERE approval_id = ? AND status = ? AND version = ?
                """,
                (
                    target_status.value,
                    reviewer_id,
                    reviewer_id,
                    reviewed_at.isoformat(),
                    clean_reason,
                    next_version,
                    approval_id,
                    ApprovalStatus.PENDING.value,
                    existing.version,
                ),
            )
            if cursor.rowcount != 1:
                raise ApprovalConflictError(
                    f"Approval '{approval_id}' has already been reviewed (current status: {row['status']})."
                )
            existing.status = target_status
            existing.reviewed_by = reviewer_id
            existing.reviewer = reviewer_id
            existing.reviewed_at = reviewed_at
            existing.decision_reason = clean_reason
            existing.version = next_version
            if audit_repo is not None:
                audit_repo.append(conn, approval_decision_event(existing, reviewer_id, reviewed_at))
        return existing


def approval_decision_event(approval: Approval, reviewer: str, reviewed_at: datetime) -> AuditEvent:
    """Audit record for a human approval decision. Deterministic event_id, so
    a second decision for the same approval cannot be appended."""
    return AuditEvent(
        event_id=f"{approval.approval_id}~decision",
        timestamp=reviewed_at,
        tool_name=approval.tool_name,
        decision=SecurityDecision.REQUIRE_APPROVAL,
        policy_id="human-approval-decision",
        reason_codes=[f"APPROVAL_{approval.status.value}"],
        destination_class=approval.destination_class,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        actor_uid=reviewer,
        event_type="APPROVAL_DECISION",
        related_event_id=approval.event_id,
    )
