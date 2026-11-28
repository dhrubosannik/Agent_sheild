"""Cloud Firestore audit repository (append-only, hash-chained v2).

Layout:
* ``audit_events/{event_id}``: DECISION records (legacy v1 documents stay here
  unchanged).
* ``audit_transitions/{event_id}``: EXECUTION_STATUS and APPROVAL_DECISION
  records (kept separate so listing decision events needs no filter on a field
  legacy documents lack).
* ``audit_sequence_v2/{sequence:012d}``: one document per sequence number,
  written with ``create`` so a duplicate sequence fails the transaction. This
  is the database-level uniqueness guarantee.
* ``system_metadata/audit_chain_v2``: chain head (sequence, hash).
* ``audit_event_status/{event_id}``: derived latest execution status (a
  mutable projection, not an audit record).

Every append runs inside a Firestore transaction that reads the head and
creates the record, so concurrent appends are serialized and each record
references the correct previous hash. Documents are written with ``create``
(never ``set``), so an existing record can never be overwritten by this code.

Note: the Firebase Admin SDK bypasses Firestore Security Rules; append-only
behaviour against *privileged* writers relies on this code path plus the
hash chain, sequence ledger and head state for detection.
"""

from datetime import UTC, datetime
import threading
from typing import Any
from uuid import uuid4

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.audit_event import AuditEvent
from ..models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from ..models.risk_signal import RiskSignal
from ..services.audit_integrity import CHAIN_VERSION, GENESIS_V2, compute_event_hash, v2_payload

EVENTS = "audit_events"
TRANSITIONS = "audit_transitions"
SEQUENCES = "audit_sequence_v2"
STATUS_VIEW = "audit_event_status"
STATE_COLLECTION = "system_metadata"
STATE_DOCUMENT = "audit_chain_v2"
MAX_TRANSACTION_ATTEMPTS = 50
MAX_OFFSET = 1000

# The v2 chain is a single serialized sequence whose head lives in one
# document. Serializing appends inside each process means only appends from
# different instances contend in Firestore (lock contention on one hot
# document otherwise causes "Transaction lock timeout" aborts). Throughput is
# bounded by Firestore's per-document write rate; see docs/REMAINING_RISKS.md.
APPEND_LOCK = threading.RLock()


def _signals(event: AuditEvent) -> list[Any]:
    return [s.model_dump() if isinstance(s, RiskSignal) else s for s in event.risk_signals]


class FirestoreAuditRepository:
    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

    # ------------------------------------------------------------ mapping
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
            "risk_signals": _signals(event),
            "payload_fingerprint": event.payload_fingerprint,
            "execution_status": event.execution_status.value,
            "sequence": event.sequence,
            "previous_event_hash": event.previous_event_hash,
            "current_event_hash": event.current_event_hash,
            "actor_uid": event.actor_uid,
            "chain_version": event.chain_version,
            "event_type": event.event_type,
            "related_event_id": event.related_event_id,
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
            chain_version=data.get("chain_version"),
            event_type=data.get("event_type"),
            related_event_id=data.get("related_event_id"),
        )

    def _state_ref(self):
        return self.client.collection(STATE_COLLECTION).document(STATE_DOCUMENT)

    def transaction(self):
        return self.client.transaction(max_attempts=MAX_TRANSACTION_ATTEMPTS)

    # -------------------------------------------------------------- append
    def read_state(self, transaction) -> dict:
        """Must be called inside ``transaction`` before any write."""
        snapshot = self._state_ref().get(transaction=transaction)
        return snapshot.to_dict() if snapshot.exists else {}

    def stage_append(self, transaction, event: AuditEvent, state: dict) -> AuditEvent:
        """Stages the writes for one append. ``state`` must come from
        ``read_state`` in the same transaction."""
        sequence = int(state.get("sequence", 0)) + 1
        previous_hash = state.get("current_event_hash", GENESIS_V2)
        event.chain_version = CHAIN_VERSION
        event.event_type = event.event_type or "DECISION"
        event.sequence = sequence
        event.previous_event_hash = previous_hash
        document = self._to_document(event)
        event.current_event_hash = compute_event_hash(v2_payload(document), previous_hash)
        document["current_event_hash"] = event.current_event_hash

        collection = EVENTS if event.event_type == "DECISION" else TRANSITIONS
        transaction.create(self.client.collection(collection).document(event.event_id), document)
        transaction.create(
            self.client.collection(SEQUENCES).document(f"{sequence:012d}"),
            {
                "event_id": event.event_id,
                "collection": collection,
                "current_event_hash": event.current_event_hash,
            },
        )
        transaction.set(
            self._state_ref(),
            {
                "chain_version": CHAIN_VERSION,
                "sequence": sequence,
                "current_event_hash": event.current_event_hash,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        if event.event_type == "EXECUTION_STATUS" and event.related_event_id:
            transaction.set(
                self.client.collection(STATUS_VIEW).document(event.related_event_id),
                {"execution_status": event.execution_status.value, "sequence": sequence},
            )
        # Keep the caller-visible state in step for multiple appends per transaction.
        state["sequence"] = sequence
        state["current_event_hash"] = event.current_event_hash
        event.effective_execution_status = event.execution_status
        return event

    def create(self, event: AuditEvent) -> AuditEvent:
        @firestore.transactional
        def insert(transaction):
            return self.stage_append(transaction, event, self.read_state(transaction))

        with APPEND_LOCK:
            return insert(self.transaction())

    def record_execution_status(
        self,
        event_id: str,
        execution_status: ExecutionStatus,
        actor_uid: str | None = None,
    ) -> bool:
        @firestore.transactional
        def append_status(transaction):
            snapshot = self.client.collection(EVENTS).document(event_id).get(transaction=transaction)
            if not snapshot.exists:
                return False
            state = self.read_state(transaction)
            original = self._from_document(snapshot.to_dict())
            self.stage_append(
                transaction,
                AuditEvent(
                    event_id=f"{event_id}~status-{uuid4().hex[:12]}",
                    timestamp=datetime.now(UTC),
                    tool_name=original.tool_name,
                    decision=original.decision,
                    policy_id=original.policy_id,
                    reason_codes=["EXECUTION_STATUS_CHANGE"],
                    destination_class=original.destination_class,
                    data_labels=original.data_labels,
                    risk_signals=[],
                    payload_fingerprint=original.payload_fingerprint,
                    execution_status=execution_status,
                    actor_uid=actor_uid,
                    event_type="EXECUTION_STATUS",
                    related_event_id=event_id,
                ),
                state,
            )
            return True

        with APPEND_LOCK:
            return append_status(self.transaction())

    def update_execution_status(self, event_id: str, execution_status: ExecutionStatus) -> bool:
        """Backward-compatible name: appends a status record (never updates)."""
        return self.record_execution_status(event_id, execution_status)

    # ---------------------------------------------------------------- read
    def _with_effective_status(self, events: list[AuditEvent]) -> list[AuditEvent]:
        if not events:
            return events
        refs = [self.client.collection(STATUS_VIEW).document(e.event_id) for e in events]
        latest = {snap.id: snap.to_dict()["execution_status"] for snap in self.client.get_all(refs) if snap.exists}
        for event in events:
            event.effective_execution_status = ExecutionStatus(latest.get(event.event_id, event.execution_status.value))
        return events

    def get_by_id(self, event_id: str) -> AuditEvent | None:
        document = self.client.collection(EVENTS).document(event_id).get()
        if not document.exists:
            return None
        return self._with_effective_status([self._from_document(document.to_dict())])[0]

    def _filtered(self, decision: SecurityDecision | str | None, tool_name: str | None):
        query = self.client.collection(EVENTS)
        if decision is not None:
            value = decision.value if isinstance(decision, SecurityDecision) else str(decision)
            query = query.where(filter=FieldFilter("decision", "==", value))
        if tool_name:
            query = query.where(filter=FieldFilter("tool_name", "==", tool_name))
        return query

    def list_events_page(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
        cursor: str | None = None,
    ) -> tuple[list[AuditEvent], int, str | None]:
        """Bounded, cursor-based listing. ``total`` uses a server-side count
        aggregation instead of reading every document."""
        limit = max(1, min(int(limit), 100))
        base = self._filtered(decision, tool_name)
        total = int(base.count().get()[0][0].value)
        query = base.order_by("timestamp", direction=firestore.Query.DESCENDING)
        if cursor:
            anchor = self.client.collection(EVENTS).document(cursor).get()
            if not anchor.exists:
                raise ValueError("Invalid pagination cursor")
            query = query.start_after(anchor)
        elif offset:
            if offset > MAX_OFFSET:
                raise ValueError(f"offset above {MAX_OFFSET} is not supported; use the cursor")
            query = query.offset(offset)
        documents = list(query.limit(limit).stream())
        events = self._with_effective_status([self._from_document(d.to_dict()) for d in documents])
        next_cursor = documents[-1].id if len(documents) == limit else None
        return events, total, next_cursor

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[AuditEvent], int]:
        items, total, _ = self.list_events_page(limit=limit, offset=offset, decision=decision, tool_name=tool_name)
        return items, total

    def export_chain_records(self) -> list[dict]:
        """All audit records (both collections) for offline verification.
        This is a full read by design and is not used by request handlers."""
        records = [d.to_dict() for d in self.client.collection(EVENTS).stream()]
        records += [d.to_dict() for d in self.client.collection(TRANSITIONS).stream()]
        return records

    def export_sequence_ledger(self) -> list[dict]:
        return [{"id": d.id, **d.to_dict()} for d in self.client.collection(SEQUENCES).stream()]

    def chain_head(self) -> dict | None:
        snapshot = self._state_ref().get()
        return snapshot.to_dict() if snapshot.exists else None
