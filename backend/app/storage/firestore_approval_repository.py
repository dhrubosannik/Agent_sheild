"""Cloud Firestore approval repository.

Approval decisions are made only through the backend (Firestore Security
Rules deny all client writes to ``approvals``). Each decision runs in a single
Firestore transaction that re-reads the approval, checks it is still PENDING,
updates it and appends the APPROVAL_DECISION audit record, so concurrent or
repeated decisions cannot both succeed and a decision is never stored without
its audit record.
"""

from datetime import UTC, datetime
from typing import Any

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.approval import Approval
from ..models.enums import ApprovalStatus, DestinationClass
from .approval_repository import ApprovalConflictError, ApprovalNotFoundError, approval_decision_event
from .firestore_audit_repository import APPEND_LOCK, MAX_OFFSET, FirestoreAuditRepository

APPROVALS = "approvals"


class FirestoreApprovalRepository:
    def __init__(self, client: Any | None = None, audit_repo: FirestoreAuditRepository | None = None) -> None:
        self.client = client or get_firestore_client()
        self.audit_repo = audit_repo or FirestoreAuditRepository(self.client)

    def _to_document(self, approval: Approval) -> dict:
        return {
            "approval_id": approval.approval_id,
            "event_id": approval.event_id,
            "tool_name": approval.tool_name,
            "requested_action": approval.requested_action,
            "destination_class": approval.destination_class.value,
            "status": approval.status.value,
            "created_at": approval.created_at.isoformat(),
            "reviewer": approval.reviewer,
            "reviewed_at": approval.reviewed_at.isoformat() if approval.reviewed_at else None,
        }

    def _from_document(self, data: dict) -> Approval:
        return Approval(
            approval_id=data["approval_id"],
            event_id=data["event_id"],
            tool_name=data["tool_name"],
            requested_action=data["requested_action"],
            destination_class=DestinationClass(data["destination_class"]),
            status=ApprovalStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            reviewer=data.get("reviewer"),
            reviewed_at=datetime.fromisoformat(data["reviewed_at"]) if data.get("reviewed_at") else None,
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
        # create() fails if the document exists: an approval is never overwritten.
        self.client.collection(APPROVALS).document(approval.approval_id).create(self._to_document(approval))
        return approval

    def list_approvals_page(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
        cursor: str | None = None,
    ) -> tuple[list[Approval], int, str | None]:
        limit = max(1, min(int(limit), 100))
        base = self.client.collection(APPROVALS)
        if status is not None:
            value = status.value if isinstance(status, ApprovalStatus) else str(status)
            base = base.where(filter=FieldFilter("status", "==", value))
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
        decision_enum = decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        if decision_enum not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError("Invalid approval decision")
        reviewer_id = reviewer.strip()
        if not reviewer_id:
            raise ValueError("Reviewer identity is required.")
        audit = audit_repo if isinstance(audit_repo, FirestoreAuditRepository) else self.audit_repo
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
            state = audit.read_state(transaction)
            reviewed_at = datetime.now(UTC)
            approval.status = decision_enum
            approval.reviewer = reviewer_id
            approval.reviewed_at = reviewed_at
            transaction.update(
                ref,
                {
                    "status": decision_enum.value,
                    "reviewer": reviewer_id,
                    "reviewed_at": reviewed_at.isoformat(),
                },
            )
            audit.stage_append(transaction, approval_decision_event(approval, reviewer_id, reviewed_at), state)
            return approval

        with APPEND_LOCK:
            return decide(audit.transaction())
