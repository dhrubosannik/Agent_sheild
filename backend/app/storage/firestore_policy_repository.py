"""Cloud Firestore policy repository for the ``policies`` collection.

Policies are stored as ``policies/{policy_id}`` with immutable versioned change
records under ``policies/{policy_id}/history/{version:06d}``. Browser clients
are denied all writes in ``firestore.rules``; every create, update, enable, and
disable flows through ADMIN-authorized FastAPI endpoints using Firestore
transactions with server timestamps and monotonically increasing ``version``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.enums import SecurityDecision
from ..models.policy import (
    POLICY_FIELDS,
    PolicyHistoryEntry,
    PolicyRuleSpec,
    StoredPolicy,
    validate_action,
    validate_created_by,
    validate_non_empty_str,
    validate_policy_id,
    validate_strict_bool,
    validate_strict_int,
)

POLICIES = "policies"
HISTORY = "history"
MAX_LIMIT = 100


class PolicyNotFoundError(Exception):
    """Raised when a requested policy document does not exist."""


class PolicyAlreadyExistsError(Exception):
    """Raised when creating a policy with an existing policy_id."""


class StoredPolicyValidationError(ValueError):
    """Raised when policy data fails schema or rule validation."""


def _serialize_snapshot_for_history(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


class FirestorePolicyRepository:
    """Backend repository managing ``policies/{policy_id}`` and ``history``."""

    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

    def _doc_ref(self, policy_id: str) -> Any:
        try:
            clean_id = validate_policy_id(policy_id)
        except ValueError as exc:
            raise StoredPolicyValidationError(str(exc)) from exc
        return self.client.collection(POLICIES).document(clean_id)

    def _history_ref(self, policy_id: str, version: int) -> Any:
        return self._doc_ref(policy_id).collection(HISTORY).document(f"{version:06d}")

    def _from_document(self, data: dict[str, Any]) -> StoredPolicy:
        if not isinstance(data, dict):
            raise StoredPolicyValidationError("Policy document must be a mapping.")
        try:
            return StoredPolicy.model_validate(data)
        except Exception as exc:
            raise StoredPolicyValidationError(f"Invalid policy document schema: {exc}") from exc

    def _validate_write_doc(self, doc: dict[str, Any]) -> None:
        if set(doc.keys()) != POLICY_FIELDS:
            missing = sorted(POLICY_FIELDS - set(doc.keys()))
            extra = sorted(set(doc.keys()) - POLICY_FIELDS)
            raise StoredPolicyValidationError(f"Invalid policy schema (missing={missing}, extra={extra}).")
        validate_policy_id(doc["policy_id"])
        validate_non_empty_str(doc["name"], field_name="name", max_length=200)
        validate_non_empty_str(doc["description"], field_name="description", max_length=1000)
        validate_strict_bool(doc["enabled"], field_name="enabled")
        validate_strict_int(doc["priority"], field_name="priority", minimum=1, maximum=10000)
        validate_action(doc["action"])
        PolicyRuleSpec.model_validate(doc["rules"])
        validate_created_by(doc["created_by"])
        validate_strict_int(doc["version"], field_name="version", minimum=1, maximum=1_000_000)

    def get_by_id(self, policy_id: str) -> StoredPolicy | None:
        snapshot = self._doc_ref(policy_id).get()
        if not snapshot.exists:
            return None
        return self._from_document(snapshot.to_dict())

    def list_policies_page(
        self,
        *,
        enabled: bool | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[StoredPolicy], int, str | None]:
        bounded_limit = max(1, min(int(limit), MAX_LIMIT))
        query: Any = self.client.collection(POLICIES)
        if enabled is not None:
            query = query.where(filter=FieldFilter("enabled", "==", bool(enabled)))
        total = int(query.count().get()[0][0].value)
        ordered = query.order_by("priority", direction=firestore.Query.ASCENDING)
        if cursor:
            anchor = self._doc_ref(cursor).get()
            if not anchor.exists:
                raise StoredPolicyValidationError("Invalid pagination cursor.")
            ordered = ordered.start_after(anchor)
        docs = list(ordered.limit(bounded_limit).stream())
        items = [self._from_document(d.to_dict()) for d in docs]
        next_cursor = docs[-1].id if len(docs) == bounded_limit else None
        return items, total, next_cursor

    def list_enabled_policies(self) -> list[StoredPolicy]:
        docs = list(
            self.client.collection(POLICIES)
            .where(filter=FieldFilter("enabled", "==", True))
            .order_by("priority", direction=firestore.Query.ASCENDING)
            .stream()
        )
        items = [self._from_document(d.to_dict()) for d in docs]
        items.sort(key=lambda p: (p.priority, p.policy_id))
        return items

    def list_history(self, policy_id: str) -> list[PolicyHistoryEntry]:
        clean_id = validate_policy_id(policy_id)
        docs = list(
            self._doc_ref(clean_id)
            .collection(HISTORY)
            .order_by("version", direction=firestore.Query.ASCENDING)
            .stream()
        )
        return [PolicyHistoryEntry.model_validate(d.to_dict()) for d in docs]

    def create_policy(
        self,
        *,
        policy_id: str,
        name: str,
        description: str,
        enabled: bool = True,
        priority: int = 100,
        action: SecurityDecision | str,
        rules: dict[str, Any],
        created_by: str,
    ) -> StoredPolicy:
        """Creates ``policies/{policy_id}`` at ``version=1`` without overwriting."""
        try:
            clean_id = validate_policy_id(policy_id)
            clean_name = validate_non_empty_str(name, field_name="name", max_length=200)
            clean_desc = validate_non_empty_str(description, field_name="description", max_length=1000)
            clean_enabled = validate_strict_bool(enabled, field_name="enabled")
            clean_priority = validate_strict_int(priority, field_name="priority", minimum=1, maximum=10000)
            valid_action = validate_action(action)
            clean_rules = PolicyRuleSpec.model_validate(rules).to_firestore_map()
            clean_actor = validate_created_by(created_by)
        except ValueError as exc:
            raise StoredPolicyValidationError(str(exc)) from exc

        doc = {
            "policy_id": clean_id,
            "name": clean_name,
            "description": clean_desc,
            "enabled": clean_enabled,
            "priority": clean_priority,
            "action": valid_action.value,
            "rules": clean_rules,
            "created_by": clean_actor,
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
            "version": 1,
        }
        self._validate_write_doc(doc)

        ref = self._doc_ref(clean_id)
        history_ref = self._history_ref(clean_id, 1)

        @firestore.transactional
        def _create_tx(transaction: Any) -> None:
            snapshot = ref.get(transaction=transaction)
            if snapshot.exists:
                raise PolicyAlreadyExistsError(f"Policy '{clean_id}' already exists.")
            transaction.create(ref, doc)
            transaction.create(
                history_ref,
                {
                    "policy_id": clean_id,
                    "version": 1,
                    "change_type": "CREATE",
                    "changed_by": clean_actor,
                    "changed_at": firestore.SERVER_TIMESTAMP,
                    "previous_state": None,
                    "new_state": {k: v for k, v in doc.items() if k not in ("created_at", "updated_at")},
                },
            )

        _create_tx(self.client.transaction())
        return self._from_document(ref.get().to_dict())

    def update_policy(
        self,
        policy_id: str,
        *,
        updated_by: str,
        name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        priority: int | None = None,
        action: SecurityDecision | str | None = None,
        rules: dict[str, Any] | None = None,
        change_type: str = "UPDATE",
    ) -> StoredPolicy:
        """Atomically updates a policy, increments ``version``, and appends audit history."""
        try:
            clean_id = validate_policy_id(policy_id)
            clean_actor = validate_created_by(updated_by)
            updates: dict[str, Any] = {}
            if name is not None:
                updates["name"] = validate_non_empty_str(name, field_name="name", max_length=200)
            if description is not None:
                updates["description"] = validate_non_empty_str(description, field_name="description", max_length=1000)
            if enabled is not None:
                updates["enabled"] = validate_strict_bool(enabled, field_name="enabled")
            if priority is not None:
                updates["priority"] = validate_strict_int(priority, field_name="priority", minimum=1, maximum=10000)
            if action is not None:
                updates["action"] = validate_action(action).value
            if rules is not None:
                updates["rules"] = PolicyRuleSpec.model_validate(rules).to_firestore_map()
        except ValueError as exc:
            raise StoredPolicyValidationError(str(exc)) from exc

        if not updates:
            raise StoredPolicyValidationError("At least one policy field must be provided for update.")

        ref = self._doc_ref(clean_id)

        @firestore.transactional
        def _update_tx(transaction: Any) -> None:
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                raise PolicyNotFoundError(f"Policy '{clean_id}' not found.")
            raw_before = snapshot.to_dict()
            existing = self._from_document(raw_before)
            next_version = existing.version + 1

            tx_updates = {
                **updates,
                "version": next_version,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }
            transaction.update(ref, tx_updates)

            after_preview = {
                **_serialize_snapshot_for_history(raw_before),
                **updates,
                "version": next_version,
            }
            after_preview.pop("updated_at", None)
            history_ref = self._history_ref(clean_id, next_version)
            transaction.create(
                history_ref,
                {
                    "policy_id": clean_id,
                    "version": next_version,
                    "change_type": change_type,
                    "changed_by": clean_actor,
                    "changed_at": firestore.SERVER_TIMESTAMP,
                    "previous_state": _serialize_snapshot_for_history(raw_before),
                    "new_state": after_preview,
                },
            )

        _update_tx(self.client.transaction())
        return self._from_document(ref.get().to_dict())

    def set_enabled(self, policy_id: str, *, enabled: bool, updated_by: str) -> StoredPolicy:
        return self.update_policy(
            policy_id,
            updated_by=updated_by,
            enabled=enabled,
            change_type="ENABLE" if enabled else "DISABLE",
        )
