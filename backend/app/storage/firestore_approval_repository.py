"""Cloud Firestore approval repository.

Approval decisions are made only through the backend (Firestore Security
Rules deny all client writes to ``approvals``). Each decision runs in a single
Firestore transaction that re-reads the approval, checks it is still PENDING,
enforces separation of duties when configured, increments ``version``, updates
the decision fields using server timestamps, and appends the
APPROVAL_DECISION audit record atomically so concurrent or repeated decisions
cannot both succeed and a decision is never stored without its audit record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.approval import Approval
from ..models.enums import ApprovalStatus, DestinationClass, RiskLevel
from .approval_repository import (
    VALID_DECISION_TARGETS,
    ApprovalAlreadyExistsError,
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalUnauthorizedError,
    approval_decision_event,
)
from .firestore_audit_repository import APPEND_LOCK, MAX_OFFSET, FirestoreAuditRepository

APPROVALS = "approvals"


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    raise ValueError("Invalid timestamp field in approval document.")


class FirestoreApprovalRepository:
    def __init__(self, client: Any | None = None, audit_repo: Any | None = None) -> None:
        self.client = client or get_firestore_client()
        self.audit_repo = audit_repo or FirestoreAuditRepository(self.client)

    def _to_document(self, approval: Approval, *, use_server_timestamps: bool = True) -> dict[str, Any]:
        req_ts = firestore.SERVER_TIMESTAMP if use_server_timestamps else (approval.requested_at or approval.created_at)
        return {
            "approval_id": approval.approval_id,
            "event_id": approval.event_id,
            "user_id": approval.user_id,
            "agent_id": approval.agent_id,
            "tool_name": approval.tool_name,
            "status": approval.status.value,
            "requested_action": approval.requested_action,
            "destination_class": approval.destination_class.value,
            "risk_level": approval.risk_level.value,
            "requested_at": req_ts,
            "created_at": req_ts,
            "reviewed_by": approval.reviewed_by,
            "reviewer": approval.reviewer,
            "reviewed_at": approval.reviewed_at,
            "decision_reason": approval.decision_reason,
            "correlation_id": approval.correlation_id,
            "version": int(approval.version),
        }

    def _from_document(self, data: dict[str, Any]) -> Approval:
        created_at = _parse_timestamp(data.get("created_at"))
        requested_at = _parse_timestamp(data.get("requested_at")) or created_at
        reviewed_at = _parse_timestamp(data.get("reviewed_at"))
        reviewed_by = data.get("reviewed_by") if data.get("reviewed_by") is not None else data.get("reviewer")

        return Approval(
            approval_id=data["approval_id"],
            event_id=data["event_id"],
            user_id=data.get("user_id") or "system",
            agent_id=data.get("agent_id") or "default-agent",
            tool_name=data["tool_name"],
            requested_action=data["requested_action"],
            destination_class=DestinationClass(data.get("destination_class", DestinationClass.UNKNOWN.value)),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.MEDIUM.value)),
            status=ApprovalStatus(data["status"]),
            requested_at=requested_at,
            created_at=created_at or requested_at,
            reviewed_by=reviewed_by,
            reviewer=reviewed_by,
            reviewed_at=reviewed_at,
            decision_reason=data.get("decision_reason"),
            correlation_id=data.get("correlation_id") or data["event_id"],
            version=int(data.get("version", 1)),
        )

    def get_by_id(self, approval_id: str) -> Approval | None:
        document = self.client.collection(APPROVALS).document(approval_id).get()
        return self._from_document(document.to_dict()) if document.exists else None

    def get_by_event_id(self, event_id: str) -> Approval | None:
        documents = list(
            self.client.collection(APPROVALS)
            .where(filter=FieldFilter("event_id", "==", event_id))
            .limit(1)
            .stream()
        )
        return self._from_document(documents[0].to_dict()) if documents else None

    def create(self, approval: Approval) -> Approval:
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError("New approvals must start in PENDING status.")
        if approval.version != 1:
            raise ValueError("New approvals must start at version 1.")
        ref = self.client.collection(APPROVALS).document(approval.approval_id)
        try:
            ref.create(self._to_document(approval, use_server_timestamps=True))
        except Exception as exc:
            if "AlreadyExists" in type(exc).__name__ or "already exists" in str(exc).lower():
                raise ApprovalAlreadyExistsError(
                    f"Approval '{approval.approval_id}' already exists."
                ) from exc
            raise
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict())

    def list_approvals_page(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
        cursor: str | None = None,
        user_id: str | None = None,
    ) -> tuple[list[Approval], int, str | None]:
        limit = max(1, min(int(limit), 100))
        base = self.client.collection(APPROVALS)
        if status is not None:
            value = status.value if isinstance(status, ApprovalStatus) else str(status)
            base = base.where(filter=FieldFilter("status", "==", value))
        if user_id is not None:
            base = base.where(filter=FieldFilter("user_id", "==", user_id.strip()))
        total = int(base.count().get()[0][0].value)
        query = base.order_by("created_at", direction=firestore.Query.DESCENDING)
        if cursor:
            anchor = self.client.collection(APPROVALS).document(cursor).get()
            if not anchor.exists:
                raise ValueError("Invalid pagination cursor")
            query = query.start_after(anchor)
        elif offset:
            if offset > MAX_OFFSET:
                raise ValueError(f"offset above {MAX_OFFSET} is not supported; use the cursor")
            query = query.offset(offset)
        documents = list(query.limit(limit).stream())
        items = [self._from_document(d.to_dict()) for d in documents]
        next_cursor = documents[-1].id if len(documents) == limit else None
        return items, total, next_cursor

    def list_pending(
        self,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[Approval], int, str | None]:
        return self.list_approvals_page(
            status=ApprovalStatus.PENDING, limit=limit, offset=0, cursor=cursor
        )

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
        decision_enum = decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        if decision_enum not in VALID_DECISION_TARGETS:
            raise ValueError("Invalid approval decision")
        reviewer_id = reviewer.strip()
        if not reviewer_id:
            raise ValueError("Reviewer identity is required.")
        clean_reason = (
            decision_reason.strip()
            if isinstance(decision_reason, str) and decision_reason.strip()
            else None
        )
        if clean_reason is not None and len(clean_reason) > 1000:
            raise ValueError("decision_reason must be 1000 characters or fewer.")

        audit = (
            audit_repo
            if (audit_repo is not None and hasattr(audit_repo, "stage_append") and hasattr(audit_repo, "read_state"))
            else self.audit_repo
        )
        ref = self.client.collection(APPROVALS).document(approval_id)

        @firestore.transactional
        def decide(transaction):
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                raise ApprovalNotFoundError(approval_id)
            approval = self._from_document(snapshot.to_dict())
            if approval.status != ApprovalStatus.PENDING:
                raise ApprovalConflictError(
                    f"Approval '{approval_id}' has already been reviewed (current status: {approval.status.value})."
                )
            if (
                enforce_separation_of_duties
                and decision_enum in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED)
                and approval.user_id == reviewer_id
            ):
                raise ApprovalUnauthorizedError("Users cannot approve or reject their own request.")

            state = audit.read_state(transaction)
            reviewed_at = datetime.now(UTC)
            next_version = int(approval.version) + 1
            approval.status = decision_enum
            approval.reviewed_by = reviewer_id
            approval.reviewer = reviewer_id
            approval.reviewed_at = reviewed_at
            approval.decision_reason = clean_reason
            approval.version = next_version

            transaction.update(
                ref,
                {
                    "status": decision_enum.value,
                    "reviewed_by": reviewer_id,
                    "reviewer": reviewer_id,
                    "reviewed_at": firestore.SERVER_TIMESTAMP,
                    "decision_reason": clean_reason,
                    "version": next_version,
                },
            )
            audit.stage_append(transaction, approval_decision_event(approval, reviewer_id, reviewed_at), state)
            return approval

        with APPEND_LOCK:
            tx = audit.transaction() if hasattr(audit, "transaction") else self.client.transaction()
            decide(tx)

        committed = ref.get()
        return self._from_document(committed.to_dict())

    def approve(
        self,
        approval_id: str,
        reviewer: str,
        *,
        decision_reason: str | None = None,
        audit_repo: Any | None = None,
        enforce_separation_of_duties: bool = False,
    ) -> Approval:
        return self.update_decision(
            approval_id,
            ApprovalStatus.APPROVED,
            reviewer,
            audit_repo=audit_repo,
            decision_reason=decision_reason,
            enforce_separation_of_duties=enforce_separation_of_duties,
        )

    def reject(
        self,
        approval_id: str,
        reviewer: str,
        *,
        decision_reason: str | None = None,
        audit_repo: Any | None = None,
        enforce_separation_of_duties: bool = False,
    ) -> Approval:
        return self.update_decision(
            approval_id,
            ApprovalStatus.REJECTED,
            reviewer,
            audit_repo=audit_repo,
            decision_reason=decision_reason,
            enforce_separation_of_duties=enforce_separation_of_duties,
        )

    def expire(
        self,
        approval_id: str,
        *,
        reviewer: str = "system",
        decision_reason: str | None = "Approval request expired.",
        audit_repo: Any | None = None,
    ) -> Approval:
        return self.update_decision(
            approval_id,
            ApprovalStatus.EXPIRED,
            reviewer,
            audit_repo=audit_repo,
            decision_reason=decision_reason,
            enforce_separation_of_duties=False,
        )
