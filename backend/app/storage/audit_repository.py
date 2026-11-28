"""Audit events SQLite repository (append-only, hash-chained v2)."""

from datetime import UTC, datetime
import json
import sqlite3
from typing import Any
from uuid import uuid4

from ..models.audit_event import AuditEvent
from ..models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from ..models.risk_signal import RiskSignal
from ..services.audit_integrity import CHAIN_VERSION, GENESIS_V2, compute_event_hash, v2_payload
from .database import Database, get_database

LISTED_EVENT_FILTER = "(event_type IS NULL OR event_type = 'DECISION')"


class AuditChainError(RuntimeError):
    """Raised when the chain state is inconsistent and appending is unsafe."""


def _signals_json(event: AuditEvent) -> list[Any]:
    return [s.model_dump() if isinstance(s, RiskSignal) else s for s in event.risk_signals]


class AuditRepository:
    """Append-only persistence of AuditEvent records.

    Existing rows are never updated or deleted (enforced by SQLite triggers).
    Execution-status changes are appended as EXECUTION_STATUS records that
    reference the original event, and surfaced as ``effective_execution_status``.
    """

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    # ------------------------------------------------------------------ read
    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        keys = row.keys()
        raw_signals = json.loads(row["risk_signals"])
        risk_signals: list[str | RiskSignal] = [
            RiskSignal.model_validate(s) if isinstance(s, dict) else str(s) for s in raw_signals
        ]
        return AuditEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            tool_name=row["tool_name"],
            decision=SecurityDecision(row["decision"]),
            policy_id=row["policy_id"],
            reason_codes=json.loads(row["reason_codes"]),
            destination_class=DestinationClass(row["destination_class"]),
            data_labels=json.loads(row["data_labels"]),
            risk_signals=risk_signals,
            payload_fingerprint=row["payload_fingerprint"],
            execution_status=ExecutionStatus(row["execution_status"]),
            sequence=row["sequence"] if "sequence" in keys else None,
            previous_event_hash=row["previous_event_hash"] if "previous_event_hash" in keys else None,
            current_event_hash=row["current_event_hash"] if "current_event_hash" in keys else None,
            actor_uid=row["actor_uid"] if "actor_uid" in keys else None,
            chain_version=row["chain_version"] if "chain_version" in keys else None,
            event_type=row["event_type"] if "event_type" in keys else None,
            related_event_id=row["related_event_id"] if "related_event_id" in keys else None,
        )

    def _with_effective_status(self, conn: sqlite3.Connection, events: list[AuditEvent]) -> list[AuditEvent]:
        if not events:
            return events
        ids = [event.event_id for event in events]
        placeholders = ",".join("?" for _ in ids)
        latest: dict[str, str] = {}
        for row in conn.execute(
            f"SELECT related_event_id, execution_status FROM audit_events "
            f"WHERE event_type = 'EXECUTION_STATUS' AND related_event_id IN ({placeholders}) "
            f"ORDER BY sequence ASC",
            ids,
        ):
            latest[row["related_event_id"]] = row["execution_status"]
        for event in events:
            event.effective_execution_status = ExecutionStatus(latest.get(event.event_id, event.execution_status.value))
        return events

    def get_by_id(self, event_id: str) -> AuditEvent | None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,)).fetchone()
            if row is None:
                return None
            return self._with_effective_status(conn, [self._row_to_event(row)])[0]

    def list_events_page(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
        cursor: str | None = None,
    ) -> tuple[list[AuditEvent], int, str | None]:
        """Lists DECISION events newest first. ``cursor`` is the event_id of the
        last item of the previous page (keyset pagination on timestamp, event_id)."""
        where = [LISTED_EVENT_FILTER]
        params: list[Any] = []
        if decision is not None:
            where.append("decision = ?")
            params.append(decision.value if isinstance(decision, SecurityDecision) else str(decision))
        if tool_name is not None and tool_name.strip():
            where.append("tool_name = ?")
            params.append(tool_name.strip())
        limit = max(1, min(int(limit), 100))

        with self.db.connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM audit_events WHERE {' AND '.join(where)}", params).fetchone()[0]
            page_where = list(where)
            page_params = list(params)
            if cursor:
                anchor = conn.execute("SELECT timestamp FROM audit_events WHERE event_id = ?", (cursor,)).fetchone()
                if anchor is None:
                    raise ValueError("Invalid pagination cursor")
                page_where.append("(timestamp < ? OR (timestamp = ? AND event_id < ?))")
                page_params.extend([anchor["timestamp"], anchor["timestamp"], cursor])
                offset = 0
            query = (
                f"SELECT * FROM audit_events WHERE {' AND '.join(page_where)} "
                "ORDER BY timestamp DESC, event_id DESC LIMIT ? OFFSET ?"
            )
            rows = conn.execute(query, [*page_params, limit, max(0, offset)]).fetchall()
            events = self._with_effective_status(conn, [self._row_to_event(r) for r in rows])
        next_cursor = events[-1].event_id if len(events) == limit else None
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
        """All records as stored, for integrity verification."""
        with self.db.connection() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_events")]

    def chain_head(self) -> dict | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT sequence, current_event_hash FROM audit_chain_state WHERE chain_version = ?",
                (CHAIN_VERSION,),
            ).fetchone()
            return dict(row) if row else None

    # ----------------------------------------------------------------- write
    def append(self, conn: sqlite3.Connection, event: AuditEvent) -> AuditEvent:
        """Appends ``event`` inside an open write transaction.

        Sequence and hashes are always assigned here (caller-supplied values
        are ignored) so that a caller cannot choose its chain position.
        """
        state = conn.execute(
            "SELECT sequence, current_event_hash FROM audit_chain_state WHERE chain_version = ?",
            (CHAIN_VERSION,),
        ).fetchone()
        last = conn.execute(
            "SELECT sequence, current_event_hash FROM audit_events WHERE chain_version = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (CHAIN_VERSION,),
        ).fetchone()
        state_seq = int(state["sequence"]) if state else 0
        last_seq = int(last["sequence"]) if last else 0
        if state_seq != last_seq or (state and last and state["current_event_hash"] != last["current_event_hash"]):
            raise AuditChainError(
                f"Audit chain state mismatch (state={state_seq}, records={last_seq}); refusing to append"
            )

        event.chain_version = CHAIN_VERSION
        event.event_type = event.event_type or "DECISION"
        event.sequence = last_seq + 1
        event.previous_event_hash = last["current_event_hash"] if last else GENESIS_V2
        timestamp_str = event.timestamp.isoformat()

        stored = {
            "event_id": event.event_id,
            "timestamp": timestamp_str,
            "tool_name": event.tool_name,
            "decision": event.decision.value,
            "policy_id": event.policy_id,
            "reason_codes": event.reason_codes,
            "destination_class": event.destination_class.value,
            "data_labels": event.data_labels,
            "risk_signals": _signals_json(event),
            "payload_fingerprint": event.payload_fingerprint,
            "execution_status": event.execution_status.value,
            "sequence": event.sequence,
            "actor_uid": event.actor_uid,
            "chain_version": event.chain_version,
            "event_type": event.event_type,
            "related_event_id": event.related_event_id,
        }
        event.current_event_hash = compute_event_hash(v2_payload(stored), event.previous_event_hash)

        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp, tool_name, decision, policy_id,
                reason_codes, destination_class, data_labels, risk_signals,
                payload_fingerprint, execution_status,
                sequence, previous_event_hash, current_event_hash, actor_uid,
                chain_version, event_type, related_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                timestamp_str,
                event.tool_name,
                event.decision.value,
                event.policy_id,
                json.dumps(event.reason_codes),
                event.destination_class.value,
                json.dumps(event.data_labels),
                json.dumps(stored["risk_signals"]),
                event.payload_fingerprint,
                event.execution_status.value,
                event.sequence,
                event.previous_event_hash,
                event.current_event_hash,
                event.actor_uid,
                event.chain_version,
                event.event_type,
                event.related_event_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_chain_state (chain_version, sequence, current_event_hash, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_version) DO UPDATE SET
                sequence = excluded.sequence,
                current_event_hash = excluded.current_event_hash,
                updated_at = excluded.updated_at
            """,
            (CHAIN_VERSION, event.sequence, event.current_event_hash, datetime.now(UTC).isoformat()),
        )
        event.effective_execution_status = event.execution_status
        return event

    def create(self, event: AuditEvent) -> AuditEvent:
        """Appends an audit event (serialized, transaction-safe)."""
        with self.db.write_transaction() as conn:
            return self.append(conn, event)

    def record_execution_status(
        self,
        event_id: str,
        execution_status: ExecutionStatus,
        actor_uid: str | None = None,
    ) -> bool:
        """Appends an EXECUTION_STATUS record for ``event_id``. The original
        record is not modified."""
        with self.db.write_transaction() as conn:
            row = conn.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,)).fetchone()
            if row is None:
                return False
            original = self._row_to_event(row)
            transition = AuditEvent(
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
            )
            self.append(conn, transition)
            return True

    def update_execution_status(self, event_id: str, execution_status: ExecutionStatus) -> bool:
        """Backward-compatible name: appends a status record (never updates)."""
        return self.record_execution_status(event_id, execution_status)
