"""Cloud Firestore audit repository for production persistence."""

from datetime import datetime
import json
from typing import Any

from google.cloud import firestore

from ..core.firestore import get_firestore_client
from ..models.audit_event import AuditEvent
from ..models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from ..models.risk_signal import RiskSignal


class FirestoreAuditRepository:
    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

    def _to_document(self, event: AuditEvent) -> dict:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "tool_name": event.tool_name,
            "decision": event.decision.value,
            "policy_id": event.policy_id,
            "reason_codes": event.reason_codes,
            "destination_class": event.destination_class.value,
            "data_labels": event.data_labels,
            "risk_signals": [
                signal.model_dump() if isinstance(signal, RiskSignal) else signal
                for signal in event.risk_signals
            ],
            "payload_fingerprint": event.payload_fingerprint,
            "execution_status": event.execution_status.value,
            "sequence": event.sequence,
            "previous_event_hash": event.previous_event_hash,
            "current_event_hash": event.current_event_hash,
            "actor_uid": event.actor_uid,
        }

    def _from_document(self, data: dict) -> AuditEvent:
        return AuditEvent(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            tool_name=data["tool_name"],
            decision=SecurityDecision(data["decision"]),
            policy_id=data["policy_id"],
            reason_codes=data.get("reason_codes", []),
            destination_class=DestinationClass(data["destination_class"]),
            data_labels=data.get("data_labels", []),
            risk_signals=data.get("risk_signals", []),
            payload_fingerprint=data.get("payload_fingerprint"),
            execution_status=ExecutionStatus(data["execution_status"]),
            sequence=data.get("sequence"),
            previous_event_hash=data.get("previous_event_hash"),
            current_event_hash=data.get("current_event_hash"),
            actor_uid=data.get("actor_uid"),
        )

    def get_by_id(self, event_id: str) -> AuditEvent | None:
        document = self.client.collection("audit_events").document(event_id).get()
        return self._from_document(document.to_dict()) if document.exists else None

    def create(self, event: AuditEvent) -> AuditEvent:
        transaction = self.client.transaction()

        @firestore.transactional
        def insert(transaction_obj):
            state_ref = self.client.collection("system_metadata").document("audit_state")
            state = state_ref.get(transaction=transaction_obj)
            state_data = state.to_dict() if state.exists else {}
            sequence = int(state_data.get("sequence", 0)) + 1
            previous_hash = state_data.get("current_event_hash", "GENESIS")
            event.sequence = sequence
            event.previous_event_hash = previous_hash

            from ..services.audit_integrity import compute_event_hash

            event.current_event_hash = compute_event_hash(
                {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "tool_name": event.tool_name,
                    "decision": event.decision.value,
                    "policy_id": event.policy_id,
                    "reason_codes": event.reason_codes,
                    "destination_class": event.destination_class.value,
                    "data_labels": event.data_labels,
                    "risk_signals": [
                        signal.model_dump() if isinstance(signal, RiskSignal) else signal
                        for signal in event.risk_signals
                    ],
                    "payload_fingerprint": event.payload_fingerprint,
                    "execution_status": event.execution_status.value,
                    "sequence": sequence,
                    "actor_uid": event.actor_uid,
                },
                previous_hash,
            )
            event_ref = self.client.collection("audit_events").document(event.event_id)
            transaction_obj.set(event_ref, self._to_document(event))
            transaction_obj.set(
                state_ref,
                {
                    "sequence": sequence,
                    "current_event_hash": event.current_event_hash,
                },
                merge=True,
            )
            return event

        return insert(transaction)

    def update_execution_status(self, event_id: str, execution_status: ExecutionStatus) -> bool:
        ref = self.client.collection("audit_events").document(event_id)
        document = ref.get()
        if not document.exists:
            return False
        ref.update({"execution_status": execution_status.value})
        return True

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[Any], int]:
        collection = self.client.collection("audit_events")
        query = collection.order_by("timestamp", direction=firestore.Query.DESCENDING)
        if decision is not None:
            dec_val = decision.value if isinstance(decision, SecurityDecision) else str(decision)
            query = query.where("decision", "==", dec_val)
        if tool_name:
            query = query.where("tool_name", "==", tool_name)
        documents = list(query.stream())
        total = len(documents)
        selected = documents[max(0, offset):max(0, offset) + max(1, limit)]
        return [self._from_document(document.to_dict()) for document in selected], total
