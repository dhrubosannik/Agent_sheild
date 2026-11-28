"""Unit and API tests for the Firestore ``policies`` collection and engine integration."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
from google.cloud import firestore
import pytest

from backend.app.api import evaluation as eval_api
from backend.app.api import policies as policies_api
from backend.app.core import auth as auth_module
from backend.app.core.policy_loader import load_active_policy
from backend.app.main import app
from backend.app.models.enums import DestinationClass, SecurityDecision
from backend.app.models.policy import PolicyRuleSpec, StoredPolicy
from backend.app.models.tool_call import ToolCall
from backend.app.services.audit_logger import AuditLogger, get_audit_service
from backend.app.services.security_engine import evaluate_tool_call
from backend.app.storage.database import Database
from backend.app.storage.firestore_policy_repository import (
    FirestorePolicyRepository,
    PolicyAlreadyExistsError,
    PolicyNotFoundError,
    StoredPolicyValidationError,
)


class _FakeSnapshot:
    def __init__(self, doc_id: str, data: dict[str, Any] | None) -> None:
        self.id = doc_id
        self._data = deepcopy(data) if data is not None else None

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self._data) if self._data is not None else None


class _FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 11, 28, 12, 0, 0, tzinfo=UTC)

    def tick(self) -> datetime:
        self.current = self.current + timedelta(seconds=1)
        return self.current


class _FakeDocumentRef:
    def __init__(
        self,
        store: dict[str, dict[str, Any]],
        subcollections: dict[str, dict[str, dict[str, Any]]],
        doc_id: str,
        clock: _FakeClock,
    ) -> None:
        self._store = store
        self._subcollections = subcollections
        self.id = doc_id
        self._clock = clock

    def _materialize(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = self._clock.tick()
        out: dict[str, Any] = {}
        for k, v in payload.items():
            out[k] = now if v is firestore.SERVER_TIMESTAMP else deepcopy(v)
        return out

    def collection(self, name: str) -> "_FakeCollection":
        key = f"{self.id}/{name}"
        store = self._subcollections.setdefault(key, {})
        return _FakeCollection(store, {}, self._clock)

    def get(self, transaction: Any | None = None) -> _FakeSnapshot:
        return _FakeSnapshot(self.id, self._store.get(self.id))

    def create(self, data: dict[str, Any]) -> None:
        if self.id in self._store:
            raise RuntimeError("409 Document already exists")
        self._store[self.id] = self._materialize(data)

    def update(self, data: dict[str, Any]) -> None:
        if self.id not in self._store:
            raise RuntimeError("404 Document not found")
        merged = dict(self._store[self.id])
        merged.update(self._materialize(data))
        self._store[self.id] = merged


class _FakeCountQuery:
    def __init__(self, count_value: int) -> None:
        self._count_value = count_value

    def get(self):
        return [[SimpleNamespace(value=self._count_value)]]


class _FakeQuery:
    def __init__(
        self,
        store: dict[str, dict[str, Any]],
        subcollections: dict[str, dict[str, dict[str, Any]]],
        clock: _FakeClock,
        filters: list[tuple[str, str, Any]] | None = None,
        order_field: str | None = None,
        descending: bool = False,
        after_id: str | None = None,
        limit_val: int | None = None,
    ) -> None:
        self._store = store
        self._subcollections = subcollections
        self._clock = clock
        self._filters = filters or []
        self._order_field = order_field
        self._descending = descending
        self._after_id = after_id
        self._limit_val = limit_val

    def _matching_items(self) -> list[tuple[str, dict[str, Any]]]:
        items = list(self._store.items())
        for field, op, val in self._filters:
            if op == "==":
                items = [(k, d) for k, d in items if d.get(field) == val]
        if self._order_field:
            items.sort(key=lambda pair: pair[1].get(self._order_field), reverse=self._descending)
        if self._after_id is not None:
            idx = next((i for i, (k, _) in enumerate(items) if k == self._after_id), None)
            if idx is not None:
                items = items[idx + 1 :]
        if self._limit_val is not None:
            items = items[: self._limit_val]
        return items

    def where(self, *, filter: Any) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._subcollections,
            self._clock,
            filters=[*self._filters, (filter.field_path, filter.op_string, filter.value)],
            order_field=self._order_field,
            descending=self._descending,
            after_id=self._after_id,
            limit_val=self._limit_val,
        )

    def order_by(self, field: str, direction: Any = None) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._subcollections,
            self._clock,
            filters=self._filters,
            order_field=field,
            descending=(direction == firestore.Query.DESCENDING),
            after_id=self._after_id,
            limit_val=self._limit_val,
        )

    def start_after(self, anchor: _FakeSnapshot) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._subcollections,
            self._clock,
            filters=self._filters,
            order_field=self._order_field,
            descending=self._descending,
            after_id=anchor.id,
            limit_val=self._limit_val,
        )

    def limit(self, value: int) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._subcollections,
            self._clock,
            filters=self._filters,
            order_field=self._order_field,
            descending=self._descending,
            after_id=self._after_id,
            limit_val=value,
        )

    def count(self) -> _FakeCountQuery:
        return _FakeCountQuery(len(self._matching_items()))

    def stream(self) -> list[_FakeSnapshot]:
        return [_FakeSnapshot(doc_id, data) for doc_id, data in self._matching_items()]


class _FakeCollection(_FakeQuery):
    def document(self, doc_id: str) -> _FakeDocumentRef:
        return _FakeDocumentRef(self._store, self._subcollections, doc_id, self._clock)


class _FakeTransaction:
    def __init__(self) -> None:
        self._ops: list[tuple[str, _FakeDocumentRef, dict[str, Any]]] = []
        self._max_attempts = 1
        self._read_only = False
        self._id = b"fake-pol-tx"

    def create(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("create", ref, data))

    def update(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("update", ref, data))

    def _begin(self, retry_id: Any = None) -> None:
        self._ops.clear()

    def _clean_up(self) -> None:
        self._ops.clear()

    def _rollback(self) -> None:
        self._ops.clear()

    def _commit(self) -> list[Any]:
        for op, ref, data in self._ops:
            if op == "create":
                ref.create(data)
            elif op == "update":
                ref.update(data)
        self._ops.clear()
        return []


class _FakeFirestoreClient:
    def __init__(self) -> None:
        self._collections: dict[str, dict[str, dict[str, Any]]] = {}
        self._subcollections: dict[str, dict[str, dict[str, Any]]] = {}
        self._clock = _FakeClock()

    def collection(self, name: str) -> _FakeCollection:
        store = self._collections.setdefault(name, {})
        return _FakeCollection(store, self._subcollections, self._clock)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction()


class _ProdSettings:
    firebase_auth_required = True
    environment = "production"
    firebase_project_id = "agentshield-prod"
    firebase_auth_emulator_host = None
    google_application_credentials = None
    database_mode = "firestore"
    rate_limit_backend = "memory"
    rate_limit_requests = 1000000
    rate_limit_window_seconds = 60
    rate_limit_fail_open = False
    max_request_bytes = 262144
    trusted_proxy_count = 0
    dev_auth_identities = ""
    dev_auth_allow_remote = False
    require_approval_separation_of_duties = False


@pytest.fixture
def policies_env(tmp_path: Path, monkeypatch):
    fs_client = _FakeFirestoreClient()
    policy_repo = FirestorePolicyRepository(client=fs_client)
    audit_logger = AuditLogger(db=Database(tmp_path / "policies_audit.db"))
    settings = _ProdSettings()

    tokens = {
        "admin-tok": {"uid": "uid-admin", "role": "ADMIN", "aud": "agentshield-prod", "email_verified": True},
        "reviewer-tok": {"uid": "uid-reviewer", "role": "REVIEWER", "aud": "agentshield-prod", "email_verified": True},
        "viewer-tok": {"uid": "uid-viewer", "role": "VIEWER", "aud": "agentshield-prod", "email_verified": True},
    }
    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_module, "verify_firebase_id_token", lambda tok: tokens[tok])

    app.dependency_overrides[get_audit_service] = lambda: audit_logger
    app.dependency_overrides[policies_api.get_policy_repository] = lambda: policy_repo
    app.dependency_overrides[policies_api.get_optional_policy_repository] = lambda: policy_repo
    app.dependency_overrides[eval_api.get_optional_policy_repository] = lambda: policy_repo
    app.dependency_overrides[eval_api.get_optional_security_event_repository] = lambda: None

    with TestClient(app) as client:
        yield client, policy_repo, fs_client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Validation & repository tests
# ---------------------------------------------------------------------------


def test_policy_rule_spec_rejects_incompatible_and_empty_rules() -> None:
    # Compatible engine rule passes
    valid = PolicyRuleSpec(
        tools=["http_post"],
        data_labels=["PROTECTED"],
        destination_classes=[DestinationClass.INTERNAL, DestinationClass.UNAPPROVED],
    )
    assert valid.tools == ["http_post"]

    # Incompatible / invented fields are rejected
    with pytest.raises(ValueError):
        PolicyRuleSpec(block_private_ip=True)  # type: ignore[call-arg]

    # Empty rules map rejected
    with pytest.raises(ValueError):
        PolicyRuleSpec()


def test_policy_repository_create_no_overwrite_versioning_and_history() -> None:
    fs = _FakeFirestoreClient()
    repo = FirestorePolicyRepository(client=fs)

    created = repo.create_policy(
        policy_id="POLICY_001",
        name="Block Internal Network Access",
        description="Blocks internal destinations for http_post",
        enabled=True,
        priority=1,
        action=SecurityDecision.BLOCK,
        rules={"tools": ["http_post"], "destination_classes": ["INTERNAL"]},
        created_by="uid-admin",
    )
    assert created.policy_id == "POLICY_001"
    assert created.version == 1
    assert created.enabled is True
    assert created.created_by == "uid-admin"

    # Never overwrite existing policy
    with pytest.raises(PolicyAlreadyExistsError):
        repo.create_policy(
            policy_id="POLICY_001",
            name="Overwrite",
            description="Attempt",
            enabled=False,
            priority=99,
            action=SecurityDecision.ALLOW,
            rules={"tools": ["http_post"]},
            created_by="uid-attacker",
        )
    assert repo.get_by_id("POLICY_001").version == 1

    # Update increments version and preserves created_by / created_at
    updated = repo.update_policy(
        "POLICY_001",
        updated_by="uid-admin",
        priority=2,
        description="Updated internal network block rule",
    )
    assert updated.version == 2
    assert updated.priority == 2
    assert updated.created_at == created.created_at
    assert updated.created_by == "uid-admin"

    # Disable and re-enable increment version
    disabled = repo.set_enabled("POLICY_001", enabled=False, updated_by="uid-admin")
    assert disabled.enabled is False
    assert disabled.version == 3

    enabled = repo.set_enabled("POLICY_001", enabled=True, updated_by="uid-admin")
    assert enabled.enabled is True
    assert enabled.version == 4

    history = repo.list_history("POLICY_001")
    assert [h.version for h in history] == [1, 2, 3, 4]
    assert [h.change_type for h in history] == ["CREATE", "UPDATE", "DISABLE", "ENABLE"]

    with pytest.raises(PolicyNotFoundError):
        repo.update_policy("POLICY_MISSING", updated_by="uid-admin", priority=5)


# ---------------------------------------------------------------------------
# API authorization, CRUD, versioning, and engine integration tests
# ---------------------------------------------------------------------------


def test_policies_api_rbac_invalid_and_lifecycle(policies_env) -> None:
    client, repo, _ = policies_env

    payload = {
        "policy_id": "POLICY_001",
        "name": "Block Internal Network Access",
        "description": "Prevents agents from accessing internal destinations",
        "enabled": True,
        "priority": 1,
        "action": "BLOCK",
        "rules": {
            "tools": ["http_post"],
            "destination_classes": ["INTERNAL"],
            "defaults": {
                "unknown_destination": "REQUIRE_APPROVAL",
                "evaluation_error": "BLOCK",
                "internal_destination": "BLOCK",
            },
        },
    }

    # Unauthenticated / VIEWER / REVIEWER cannot create policies
    assert client.post("/api/v1/policies", json=payload).status_code == 401
    assert client.post("/api/v1/policies", headers={"Authorization": "Bearer viewer-tok"}, json=payload).status_code == 403
    assert client.post("/api/v1/policies", headers={"Authorization": "Bearer reviewer-tok"}, json=payload).status_code == 403

    # Invalid policy configurations rejected (422)
    assert (
        client.post(
            "/api/v1/policies",
            headers={"Authorization": "Bearer admin-tok"},
            json={**payload, "rules": {"unsupported_flag": True}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/policies",
            headers={"Authorization": "Bearer admin-tok"},
            json={**payload, "action": "PERMIT"},
        ).status_code
        == 422
    )

    # ADMIN creates POLICY_001
    created = client.post("/api/v1/policies", headers={"Authorization": "Bearer admin-tok"}, json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 1
    assert created.json()["created_by"] == "uid-admin"

    # Duplicate create rejected with 409
    assert client.post("/api/v1/policies", headers={"Authorization": "Bearer admin-tok"}, json=payload).status_code == 409

    # Retrieve policy (list & single)
    listed = client.get("/api/v1/policies", headers={"Authorization": "Bearer viewer-tok"})
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["policy_id"] == "POLICY_001"

    fetched = client.get("/api/v1/policies/POLICY_001", headers={"Authorization": "Bearer viewer-tok"})
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "Block Internal Network Access"

    # Unauthorized update/enable/disable rejected with 403
    assert (
        client.post(
            "/api/v1/policies/POLICY_001/update",
            headers={"Authorization": "Bearer reviewer-tok"},
            json={"priority": 5},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/policies/POLICY_001/disable",
            headers={"Authorization": "Bearer viewer-tok"},
        ).status_code
        == 403
    )

    # Security engine uses active POLICY_001 during /api/v1/evaluate
    eval_blocked = client.post(
        "/api/v1/evaluate",
        headers={"Authorization": "Bearer viewer-tok"},
        json={"tool_name": "http_post", "arguments": {"url": "http://127.0.0.1:8080/secret"}},
    )
    assert eval_blocked.status_code == 200
    assert eval_blocked.json()["decision"] == "BLOCK"
    assert eval_blocked.json()["policy_id"] == "POLICY_001"

    # ADMIN updates policy -> version 2
    upd = client.post(
        "/api/v1/policies/POLICY_001/update",
        headers={"Authorization": "Bearer admin-tok"},
        json={"priority": 2, "description": "Updated description"},
    )
    assert upd.status_code == 200
    assert upd.json()["version"] == 2
    assert upd.json()["priority"] == 2

    # ADMIN disables POLICY_001 -> version 3; engine falls back to base policy
    dis = client.post("/api/v1/policies/POLICY_001/disable", headers={"Authorization": "Bearer admin-tok"})
    assert dis.status_code == 200
    assert dis.json()["enabled"] is False
    assert dis.json()["version"] == 3

    eval_after_disable = client.post(
        "/api/v1/evaluate",
        headers={"Authorization": "Bearer viewer-tok"},
        json={"tool_name": "http_post", "arguments": {"url": "http://127.0.0.1:8080/secret"}},
    )
    assert eval_after_disable.status_code == 200
    assert eval_after_disable.json()["decision"] == "BLOCK"
    assert eval_after_disable.json()["policy_id"] == "internal-destination-boundary"

    # ADMIN re-enables POLICY_001 -> version 4
    ena = client.post("/api/v1/policies/POLICY_001/enable", headers={"Authorization": "Bearer admin-tok"})
    assert ena.status_code == 200
    assert ena.json()["enabled"] is True
    assert ena.json()["version"] == 4

    # History endpoint is ADMIN-only and records all 4 versions
    assert client.get("/api/v1/policies/POLICY_001/history", headers={"Authorization": "Bearer reviewer-tok"}).status_code == 403
    hist = client.get("/api/v1/policies/POLICY_001/history", headers={"Authorization": "Bearer admin-tok"})
    assert hist.status_code == 200
    assert [entry["change_type"] for entry in hist.json()] == ["CREATE", "UPDATE", "DISABLE", "ENABLE"]

    # Direct SecurityEngine call with load_active_policy(repo) also respects priority
    repo.create_policy(
        policy_id="POLICY_002",
        name="Allow Partner Summary",
        description="Explicitly allow read_summary to approved destinations",
        enabled=True,
        priority=1,
        action=SecurityDecision.ALLOW,
        rules={"tools": ["read_summary"], "destination_classes": ["APPROVED"]},
        created_by="uid-admin",
    )
    active = load_active_policy(policy_repo=repo)
    eval_res = evaluate_tool_call(
        ToolCall(tool_name="read_summary", arguments={"to": "partner@example.org"}),
        policy=active,
    )
    assert eval_res.decision == SecurityDecision.ALLOW
    assert eval_res.policy_id == "POLICY_002"
