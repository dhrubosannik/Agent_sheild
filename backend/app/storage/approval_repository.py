"""Approval records SQLite repository."""

from datetime import UTC, datetime
import sqlite3
from typing import Any

from ..models.approval import Approval
from ..models.audit_event import AuditEvent
from ..models.enums import ApprovalStatus, DestinationClass, ExecutionStatus, SecurityDecision
from .database import Database, get_database


class ApprovalNotFoundError(Exception):
    """Raised when an approval record is not found."""


class ApprovalConflictError(Exception):
    """Raised when an approval is not in PENDING state or has already been reviewed."""


class ApprovalRepository:
    """Handles persistence and review transitions for Approval records."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def _row_to_approval(self, row: sqlite3.Row) -> Approval:
        created_at = datetime.fromisoformat(row["created_at"])
        reviewed_at = (
            datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None
        )

        return Approval(
            approval_id=row["approval_id"],
            event_id=row["event_id"],
            tool_name=row["tool_name"],
            requested_action=row["requested_action"],
            destination_class=DestinationClass(row["destination_class"]),
            status=ApprovalStatus(row["status"]),
            created_at=created_at,
            reviewer=row["reviewer"],
            reviewed_at=reviewed_at,
        )

    def create(self, approval: Approval) -> Approval:
        """Creates a new approval record in PENDING state."""
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, event_id, tool_name, requested_action,
                    destination_class, status, created_at, reviewer, reviewed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.event_id,
                    approval.tool_name,
                    approval.requested_action,
                    approval.destination_class.value,
                    approval.status.value,
                    approval.created_at.isoformat(),
                    approval.reviewer,
                    approval.reviewed_at.isoformat() if approval.reviewed_at else None,
                ),
            )
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
    ) -> Approval:
        """Records an APPROVED or REJECTED decision.

        Atomic compare-and-set: the row changes only while it is PENDING, inside
        one serialized transaction that also appends the APPROVAL_DECISION audit
        record (when ``audit_repo`` is given), so a decision is never recorded
        without its audit event or vice versa. Concurrent or repeated decisions
        raise ApprovalConflictError.
        """
        target_status = decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        if target_status not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError(f"Invalid review decision: {target_status}. Must be APPROVED or REJECTED.")
        reviewer_id = reviewer.strip()
        if not reviewer_id:
            raise ValueError("Reviewer identity is required.")
        reviewed_at = datetime.now(UTC)

        with self.db.write_transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if row is None:
                raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?, reviewer = ?, reviewed_at = ?
                WHERE approval_id = ? AND status = ?
                """,
                (target_status.value, reviewer_id, reviewed_at.isoformat(), approval_id, ApprovalStatus.PENDING.value),
            )
            if cursor.rowcount != 1:
                raise ApprovalConflictError(
                    f"Approval '{approval_id}' has already been reviewed (current status: {row['status']})."
                )
            approval = self._row_to_approval(row)
            approval.status = target_status
            approval.reviewer = reviewer_id
            approval.reviewed_at = reviewed_at
            if audit_repo is not None:
                audit_repo.append(conn, approval_decision_event(approval, reviewer_id, reviewed_at))
        return approval


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
