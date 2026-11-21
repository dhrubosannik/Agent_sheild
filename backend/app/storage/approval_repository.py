"""Approval records SQLite repository."""

from datetime import UTC, datetime
import sqlite3
from typing import Any

from ..models.approval import Approval
from ..models.enums import ApprovalStatus, DestinationClass
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

    def list_approvals(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Approval], int]:
        """Lists approval records with optional status filtering and pagination."""
        query = "SELECT * FROM approvals WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM approvals WHERE 1=1"
        params: list[Any] = []

        if status is not None:
            stat_val = status.value if isinstance(status, ApprovalStatus) else str(status)
            query += " AND status = ?"
            count_query += " AND status = ?"
            params.append(stat_val)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        exec_params = list(params)
        exec_params.extend([max(1, limit), max(0, offset)])

        with self.db.connection() as conn:
            count_cursor = conn.execute(count_query, params)
            total = count_cursor.fetchone()[0]

            cursor = conn.execute(query, exec_params)
            rows = cursor.fetchall()
            approvals = [self._row_to_approval(r) for r in rows]

        return approvals, total

    def update_decision(
        self,
        approval_id: str,
        decision: ApprovalStatus | str,
        reviewer: str,
    ) -> Approval:
        """Records an APPROVED or REJECTED decision.

        Ensures only PENDING approvals can be reviewed, preventing duplicate
        or conflicting transitions.
        """
        target_status = (
            decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        )
        if target_status not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError(f"Invalid review decision: {target_status}. Must be APPROVED or REJECTED.")

        reviewed_at = datetime.now(UTC)

        with self.db.connection() as conn:
            cursor = conn.execute(
                "SELECT status FROM approvals WHERE approval_id = ?",
                (approval_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found.")

            current_status = row["status"]
            if current_status != ApprovalStatus.PENDING.value:
                raise ApprovalConflictError(
                    f"Approval '{approval_id}' has already been reviewed (current status: {current_status})."
                )

            conn.execute(
                """
                UPDATE approvals
                SET status = ?, reviewer = ?, reviewed_at = ?
                WHERE approval_id = ?
                """,
                (
                    target_status.value,
                    reviewer.strip(),
                    reviewed_at.isoformat(),
                    approval_id,
                ),
            )
            conn.commit()

        updated = self.get_by_id(approval_id)
        if updated is None:
            raise ApprovalNotFoundError(f"Approval record '{approval_id}' not found after update.")
        return updated
