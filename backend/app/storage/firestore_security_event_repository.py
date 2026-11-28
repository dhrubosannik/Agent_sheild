"""Cloud Firestore repository for the ``security_events`` collection.

Documents are keyed by ``event_id`` (``security_events/{event_id}``) and
created exclusively by the FastAPI backend via the Firebase Admin SDK.
Firestore Security Rules deny all browser/client SDK writes, and repository
writes use atomic ``create`` transactions so existing records can never be
overwritten and duplicate submissions can be handled idempotently.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.enums import RiskLevel, SecurityDecision
from ..models.security_event import (
    SECURITY_EVENT_FIELDS,
    SecurityEvent,
    validate_created_at,
    validate_decision,
    validate_identifier,
    validate_non_empty_text,
    validate_risk_level,
    validate_security_metadata,
)

SECURITY_EVENTS = "security_events"
MAX_LIMIT = 100


class SecurityEventValidationError(ValueError):
    """Raised when security event data or filter inputs fail validation."""


class SecurityEventDuplicateError(Exception):
    """Raised when attempting to create an event with an existing event_id."""


class SecurityEventConflictError(Exception):
    """Raised when an idempotent event_id conflicts with an existing record."""


def _is_server_timestamp(value: Any) -> bool:
    return value is firestore.SERVER_TIMESTAMP


def _validate_write_document(doc: dict[str, Any]) -> None:
    if set(doc.keys()) != SECURITY_EVENT_FIELDS:
        missing = sorted(SECURITY_EVENT_FIELDS - set(doc.keys()))
        extra = sorted(set(doc.keys()) - SECURITY_EVENT_FIELDS)
        raise SecurityEventValidationError(
            f"Invalid security_events schema (missing={missing}, extra={extra})."
        )
    validate_identifier(doc["event_id"], field_name="event_id", max_length=128)
    validate_identifier(doc["user_id"], field_name="user_id", max_length=128)
    validate_non_empty_text(doc["agent_id"], field_name="agent_id", max_length=128)
    validate_non_empty_text(doc["tool_name"], field_name="tool_name", max_length=200)
    validate_decision(doc["decision"])
    validate_risk_level(doc["risk_level"])
    validate_non_empty_text(doc["reason"], field_name="reason", max_length=1000)
    validate_non_empty_text(doc["policy_id"], field_name="policy_id", max_length=200)
    validate_identifier(doc["correlation_id"], field_name="correlation_id", max_length=128)
    if not (_is_server_timestamp(doc["created_at"]) or isinstance(doc["created_at"], datetime)):
        raise SecurityEventValidationError("created_at must be a Firestore timestamp.")
    validate_security_metadata(doc["metadata"])


class FirestoreSecurityEventRepository:
    """Backend repository managing ``security_events/{event_id}`` documents."""

    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

    def _doc_ref(self, event_id: str) -> Any:
        try:
            clean_id = validate_identifier(event_id, field_name="event_id", max_length=128)
        except ValueError as exc:
            raise SecurityEventValidationError(str(exc)) from exc
        return self.client.collection(SECURITY_EVENTS).document(clean_id)

    def _from_document(self, data: dict[str, Any]) -> SecurityEvent:
        if not isinstance(data, dict):
            raise SecurityEventValidationError("Security event document must be a mapping.")
        try:
            return SecurityEvent.model_validate(data)
        except Exception as exc:
            raise SecurityEventValidationError(f"Invalid security event schema: {exc}") from exc

    def create_event(
        self,
        *,
        event_id: str | None = None,
        user_id: str,
        agent_id: str = "default-agent",
        tool_name: str,
        decision: SecurityDecision | str,
        risk_level: RiskLevel | str,
        reason: str,
        policy_id: str,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> tuple[SecurityEvent, bool]:
        """Creates an immutable ``security_events/{event_id}`` document.

        Uses a Firestore transaction with ``transaction.create(...)`` so existing
        records are never overwritten. When ``idempotent=True``, an already-
        recorded event with the same ``user_id``, ``tool_name``, ``decision``,
        and ``policy_id`` returns ``(existing_event, False)``.
        """
        resolved_event_id = event_id or f"evt-{uuid4().hex[:12]}"
        resolved_correlation_id = correlation_id or f"corr-{uuid4().hex[:12]}"
        try:
            clean_event_id = validate_identifier(resolved_event_id, field_name="event_id", max_length=128)
            clean_user_id = validate_identifier(user_id, field_name="user_id", max_length=128)
            clean_agent_id = validate_non_empty_text(agent_id, field_name="agent_id", max_length=128)
            clean_tool = validate_non_empty_text(tool_name, field_name="tool_name", max_length=200)
            valid_decision = validate_decision(decision)
            valid_risk = validate_risk_level(risk_level)
            clean_reason = validate_non_empty_text(reason, field_name="reason", max_length=1000)
            clean_policy = validate_non_empty_text(policy_id, field_name="policy_id", max_length=200)
            clean_correlation = validate_identifier(
                resolved_correlation_id, field_name="correlation_id", max_length=128
            )
            clean_metadata = validate_security_metadata(metadata if metadata is not None else {})
        except ValueError as exc:
            raise SecurityEventValidationError(str(exc)) from exc

        doc = {
            "event_id": clean_event_id,
            "user_id": clean_user_id,
            "agent_id": clean_agent_id,
            "tool_name": clean_tool,
            "decision": valid_decision.value,
            "risk_level": valid_risk.value,
            "reason": clean_reason,
            "policy_id": clean_policy,
            "correlation_id": clean_correlation,
            "created_at": firestore.SERVER_TIMESTAMP,
            "metadata": clean_metadata,
        }
        _validate_write_document(doc)

        ref = self._doc_ref(clean_event_id)

        @firestore.transactional
        def _insert_tx(transaction: Any) -> bool:
            snapshot = ref.get(transaction=transaction)
            if snapshot.exists:
                if not idempotent:
                    raise SecurityEventDuplicateError(f"Security event '{clean_event_id}' already exists.")
                existing = self._from_document(snapshot.to_dict())
                if (
                    existing.user_id != clean_user_id
                    or existing.tool_name != clean_tool
                    or existing.decision != valid_decision
                    or existing.policy_id != clean_policy
                ):
                    raise SecurityEventConflictError(
                        f"Idempotency conflict for security event '{clean_event_id}'."
                    )
                return False
            transaction.create(ref, doc)
            return True

        created = _insert_tx(self.client.transaction())
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict()), created

    def get_by_id(self, event_id: str) -> SecurityEvent | None:
        snapshot = self._doc_ref(event_id).get()
        if not snapshot.exists:
            return None
        return self._from_document(snapshot.to_dict())

    def list_events_page(
        self,
        *,
        user_id: str | None = None,
        decision: SecurityDecision | str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecurityEvent], int, str | None]:
        """Lists security events newest-first with filtering and cursor pagination."""
        bounded_limit = max(1, min(int(limit), MAX_LIMIT))
        query: Any = self.client.collection(SECURITY_EVENTS)

        if user_id is not None:
            try:
                clean_uid = validate_identifier(user_id, field_name="user_id", max_length=128)
            except ValueError as exc:
                raise SecurityEventValidationError(str(exc)) from exc
            query = query.where(filter=FieldFilter("user_id", "==", clean_uid))

        if decision is not None:
            try:
                valid_decision = validate_decision(decision)
            except ValueError as exc:
                raise SecurityEventValidationError(str(exc)) from exc
            query = query.where(filter=FieldFilter("decision", "==", valid_decision.value))

        if start_date is not None:
            try:
                clean_start = validate_created_at(start_date)
            except ValueError as exc:
                raise SecurityEventValidationError(str(exc)) from exc
            query = query.where(filter=FieldFilter("created_at", ">=", clean_start))

        if end_date is not None:
            try:
                clean_end = validate_created_at(end_date)
            except ValueError as exc:
                raise SecurityEventValidationError(str(exc)) from exc
            query = query.where(filter=FieldFilter("created_at", "<", clean_end))

        total = int(query.count().get()[0][0].value)
        ordered = query.order_by("created_at", direction=firestore.Query.DESCENDING)
        if cursor:
            anchor = self._doc_ref(cursor).get()
            if not anchor.exists:
                raise SecurityEventValidationError("Invalid pagination cursor.")
            ordered = ordered.start_after(anchor)

        docs = list(ordered.limit(bounded_limit).stream())
        items = [self._from_document(doc.to_dict()) for doc in docs]
        next_cursor = docs[-1].id if len(docs) == bounded_limit else None
        return items, total, next_cursor
