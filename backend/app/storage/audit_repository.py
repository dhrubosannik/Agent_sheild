"""Audit events SQLite repository."""

from datetime import datetime
import json
import sqlite3
from typing import Any

from ..models.audit_event import AuditEvent
from ..models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from ..models.risk_signal import RiskSignal
from .database import Database, get_database


class AuditRepository:
    """Handles persistence and retrieval of AuditEvent records."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        # Deserialize structured JSON fields
        reason_codes = json.loads(row["reason_codes"])
        data_labels = json.loads(row["data_labels"])
        raw_signals = json.loads(row["risk_signals"])

        risk_signals: list[str | RiskSignal] = []
        for s in raw_signals:
            if isinstance(s, dict):
                risk_signals.append(RiskSignal.model_validate(s))
            else:
                risk_signals.append(str(s))

        return AuditEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            tool_name=row["tool_name"],
            decision=SecurityDecision(row["decision"]),
            policy_id=row["policy_id"],
            reason_codes=reason_codes,
            destination_class=DestinationClass(row["destination_class"]),
            data_labels=data_labels,
            risk_signals=risk_signals,
            payload_fingerprint=row["payload_fingerprint"],
            execution_status=ExecutionStatus(row["execution_status"]),
        )

    def create(self, event: AuditEvent) -> AuditEvent:
        """Persists an audit event in the database."""
        signals_json = json.dumps(
            [s.model_dump() if isinstance(s, RiskSignal) else s for s in event.risk_signals]
        )
        reasons_json = json.dumps(event.reason_codes)
        labels_json = json.dumps(event.data_labels)
        timestamp_str = event.timestamp.isoformat()

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, tool_name, decision, policy_id,
                    reason_codes, destination_class, data_labels, risk_signals,
                    payload_fingerprint, execution_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    timestamp_str,
                    event.tool_name,
                    event.decision.value,
                    event.policy_id,
                    reasons_json,
                    event.destination_class.value,
                    labels_json,
                    signals_json,
                    event.payload_fingerprint,
                    event.execution_status.value,
                ),
            )
            conn.commit()
        return event

    def get_by_id(self, event_id: str) -> AuditEvent | None:
        """Retrieves a single audit event by its event_id."""
        with self.db.connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_events WHERE event_id = ?",
                (event_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_event(row)

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: SecurityDecision | str | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[AuditEvent], int]:
        """Lists audit events with pagination and optional filtering."""
        query = "SELECT * FROM audit_events WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM audit_events WHERE 1=1"
        params: list[Any] = []

        if decision is not None:
            dec_val = decision.value if isinstance(decision, SecurityDecision) else str(decision)
            query += " AND decision = ?"
            count_query += " AND decision = ?"
            params.append(dec_val)

        if tool_name is not None and tool_name.strip():
            query += " AND tool_name = ?"
            count_query += " AND tool_name = ?"
            params.append(tool_name.strip())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        exec_params = list(params)
        exec_params.extend([max(1, limit), max(0, offset)])

        with self.db.connection() as conn:
            count_cursor = conn.execute(count_query, params)
            total = count_cursor.fetchone()[0]

            cursor = conn.execute(query, exec_params)
            rows = cursor.fetchall()
            events = [self._row_to_event(r) for r in rows]

        return events, total

    def update_execution_status(
        self,
        event_id: str,
        execution_status: ExecutionStatus,
    ) -> bool:
        """Updates the execution status of an existing audit event."""
        with self.db.connection() as conn:
            cursor = conn.execute(
                "UPDATE audit_events SET execution_status = ? WHERE event_id = ?",
                (execution_status.value, event_id),
            )
            conn.commit()
            return cursor.rowcount > 0
