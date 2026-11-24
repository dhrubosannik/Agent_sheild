"""Cloud Firestore approval repository."""

from datetime import datetime
from typing import Any

from ..models.approval import Approval
from ..models.enums import ApprovalStatus, DestinationClass
from .approval_repository import ApprovalConflictError, ApprovalNotFoundError
from ..core.firestore import get_firestore_client


class FirestoreApprovalRepository:
    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

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
        document = self.client.collection("approvals").document(approval_id).get()
        return self._from_document(document.to_dict()) if document.exists else None

    def get_by_event_id(self, event_id: str) -> Approval | None:
        documents = list(
            self.client.collection("approvals")
            .where("event_id", "==", event_id)
            .limit(1)
            .stream()
        )
        return self._from_document(documents[0].to_dict()) if documents else None

    def create(self, approval: Approval) -> Approval:
        ref = self.client.collection("approvals").document(approval.approval_id)
        ref.set(self._to_document(approval), merge=False)
        return approval

    def list_approvals(
        self,
        status: ApprovalStatus | str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Approval], int]:
        query = self.client.collection("approvals")
        if status is not None:
            status_value = status.value if isinstance(status, ApprovalStatus) else str(status)
            query = query.where("status", "==", status_value)
        documents = list(query.stream())
        total = len(documents)
        selected = documents[max(0, offset):max(0, offset) + max(1, limit)]
        return [self._from_document(document.to_dict()) for document in selected], total

    def update_decision(
        self,
        approval_id: str,
        decision: ApprovalStatus | str,
        reviewer: str,
    ) -> Approval:
        ref = self.client.collection("approvals").document(approval_id)
        document = ref.get()
        if not document.exists:
            raise ApprovalNotFoundError(approval_id)
        approval = self._from_document(document.to_dict())
        if approval.status != ApprovalStatus.PENDING:
            raise ApprovalConflictError("Approval has already been reviewed")
        decision_enum = decision if isinstance(decision, ApprovalStatus) else ApprovalStatus(decision)
        if decision_enum not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError("Invalid approval decision")
        approval.status = decision_enum
        approval.reviewer = reviewer
        approval.reviewed_at = datetime.now()
        ref.update({
            "status": decision_enum.value,
            "reviewer": approval.reviewer,
            "reviewed_at": approval.reviewed_at.isoformat(),
        })
        return approval
