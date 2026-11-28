"""Unit and API tests for the upgraded Firestore ``approvals`` collection."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
from google.cloud import firestore
import pytest

from backend.app.api import evaluation as eval_api
from backend.app.core import auth as auth_module
from backend.app.main import app
from backend.app.models.approval import Approval
from backend.app.models.enums import ApprovalStatus, DestinationClass, RiskLevel
from backend.app.services.audit_logger import AuditLogger, get_audit_service
from backend.app.storage.approval_repository import (
    ApprovalAlreadyExistsError,
    ApprovalConflictError,
    ApprovalUnauthorizedError,
)
from backend.app.storage.firestore_approval_repository import FirestoreApprovalRepository
from backend.app.storage.firestore_audit_repository import APPEND_LOCK, FirestoreAuditRepository


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
    def __init__(self, store: dict[str, dict[str, Any]], doc_id: str, clock: _FakeClock) -> None:
        self._store = store
        self.id = doc_id
        self._clock = clock

    def _materialize(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = self._clock.tick()
        out: dict[str, Any] = {}
        for k, v in payload.items():
            out[k] = now if v is firestore.SERVER_TIMESTAMP else deepcopy(v)
        return out

    def get(self, transaction: Any | None = None) -> _FakeSnapshot:
        return _FakeSnapshot(self.id, self._store.get(self.id))

    def create(self, data: dict[str, Any]) -> None:
        if self.id in self._store:
            raise RuntimeError("409 Document already exists")
        self._store[self.id] = self._materialize(data)

    def set(self, data: dict[str, Any]) -> None:
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
        clock: _FakeClock,
        filters: list[tuple[str, str, Any]] | None = None,
        order_field: str | None = None,
        descending: bool = False,
        after_id: str | None = None,
        limit_val: int | None = None,
    ) -> None:
        self._store = store
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
        return _FakeDocumentRef(self._store, doc_id, self._clock)


class _FakeTransaction:
    def __init__(self) -> None:
        self._ops: list[tuple[str, _FakeDocumentRef, dict[str, Any]]] = []
        self._max_attempts = 1
        self._read_only = False
        self._id = b"fake-apr-tx"

    def create(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("create", ref, data))

    def set(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("set", ref, data))

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
            elif op == "set":
                ref.set(data)
            elif op == "update":
                ref.update(data)
        self._ops.clear()
        return []


class _FakeFirestoreClient:
    def __init__(self) -> None:
        self._collections: dict[str, dict[str, dict[str, Any]]] = {}
        self._clock = _FakeClock()

    def collection(self, name: str) -> _FakeCollection:
        store = self._collections.setdefault(name, {})
        return _FakeCollection(store, self._clock)

    def get_all(self, refs: list[_FakeDocumentRef]) -> list[_FakeSnapshot]:
        return [ref.get() for ref in refs]

    def transaction(self, max_attempts: int = 1) -> _FakeTransaction:
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


def test_firestore_approval_create_no_overwrite_expire_and_transaction_rollback() -> None:
    fs = _FakeFirestoreClient()
    audit_repo = FirestoreAuditRepository(client=fs)
    repo = FirestoreApprovalRepository(client=fs, audit_repo=audit_repo)

    now = datetime.now(UTC)
    approval = Approval(
        approval_id="apr-evt-1",
        event_id="evt-1",
        user_id="uid-requester",
        agent_id="agent-ops",
        tool_name="export_file",
        requested_action="Export customer CSV",
        destination_class=DestinationClass.UNAPPROVED,
        risk_level=RiskLevel.HIGH,
        status=ApprovalStatus.PENDING,
        requested_at=now,
        correlation_id="corr-apr-1",
        version=1,
    )
    created = repo.create(approval)
    assert created.status == ApprovalStatus.PENDING
    assert created.version == 1
    assert created.reviewed_by is None
    assert created.reviewed_at is None
    assert created.decision_reason is None

    # Re-creating the same approval_id must never overwrite the existing record
    with pytest.raises(ApprovalAlreadyExistsError):
        repo.create(approval)

    # Transaction rollback test: if audit append fails, approval remains PENDING at version 1
    class _FailingAuditRepo:
        def read_state(self, tx):
            return {}

        def stage_append(self, tx, event, state):
            raise RuntimeError("Simulated audit write failure")

        def transaction(self):
            return fs.transaction()

    with pytest.raises(RuntimeError, match="Simulated audit write failure"):
        repo.approve(
            "apr-evt-1",
            reviewer="uid-reviewer",
            decision_reason="Looks fine",
            audit_repo=_FailingAuditRepo(),
        )

    after_rollback = repo.get_by_id("apr-evt-1")
    assert after_rollback is not None
    assert after_rollback.status == ApprovalStatus.PENDING
    assert after_rollback.version == 1
    assert after_rollback.reviewed_by is None
    assert after_rollback.reviewed_at is None
    assert after_rollback.decision_reason is None

    # Separation of duties blocks self-approval when enabled
    with pytest.raises(ApprovalUnauthorizedError):
        repo.approve(
            "apr-evt-1",
            reviewer="uid-requester",
            enforce_separation_of_duties=True,
        )

    # Expire transition increments version to 2 and prevents further decisions
    expired = repo.expire("apr-evt-1", decision_reason="TTL exceeded")
    assert expired.status == ApprovalStatus.EXPIRED
    assert expired.version == 2
    assert expired.reviewed_by == "system"
    assert expired.decision_reason == "TTL exceeded"

    with pytest.raises(ApprovalConflictError):
        repo.approve("apr-evt-1", reviewer="uid-reviewer")


def test_approvals_api_pending_approve_reject_and_audit(monkeypatch) -> None:
    fs = _FakeFirestoreClient()
    audit_repo = FirestoreAuditRepository(client=fs)
    approval_repo = FirestoreApprovalRepository(client=fs, audit_repo=audit_repo)
    audit_logger = AuditLogger(audit_repo=audit_repo, approval_repo=approval_repo)
    settings = _ProdSettings()

    tokens = {
        "admin-tok": {"uid": "uid-admin", "role": "ADMIN", "aud": "agentshield-prod", "email_verified": True},
        "reviewer-tok": {"uid": "uid-reviewer", "role": "REVIEWER", "aud": "agentshield-prod", "email_verified": True},
        "viewer-tok": {"uid": "uid-viewer", "role": "VIEWER", "aud": "agentshield-prod", "email_verified": True},
    }
    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)
    monkeypatch.setattr("backend.app.api.approvals.get_settings", lambda: settings)
    monkeypatch.setattr(auth_module, "verify_firebase_id_token", lambda tok: tokens[tok])

    app.dependency_overrides[get_audit_service] = lambda: audit_logger
    app.dependency_overrides[eval_api.get_optional_security_event_repository] = lambda: None

    try:
        with TestClient(app) as client:
            # 1. Create two pending approvals via /api/v1/evaluate
            apr_ids = []
            for i in range(2):
                res = client.post(
                    "/api/v1/evaluate",
                    headers={"Authorization": "Bearer viewer-tok", "X-Correlation-ID": f"corr-{i}"},
                    json={
                        "tool_name": "export_file",
                        "arguments": {"to": "ops@external.example.net", "filename": f"f{i}.csv"},
                        "context": {"agent_id": "agent-export"},
                    },
                )
                assert res.status_code == 200
                apr_ids.append(f"apr-{res.json()['event_id']}")

            # 2. Retrieve pending approvals with cursor pagination
            page1 = client.get("/api/v1/approvals/pending", headers={"Authorization": "Bearer viewer-tok"}, params={"limit": 1})
            assert page1.status_code == 200
            assert page1.json()["total"] == 2
            assert len(page1.json()["items"]) == 1
            assert page1.json()["items"][0]["version"] == 1
            assert page1.json()["items"][0]["user_id"] == "uid-viewer"
            assert page1.json()["items"][0]["agent_id"] == "agent-export"

            # 3. Unauthorized reviewer (VIEWER) cannot approve or reject
            assert (
                client.post(
                    f"/api/v1/approvals/{apr_ids[0]}/approve",
                    headers={"Authorization": "Bearer viewer-tok"},
                    json={"decision_reason": "Self approve"},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    f"/api/v1/approvals/{apr_ids[0]}/reject",
                    headers={"Authorization": "Bearer viewer-tok"},
                ).status_code
                == 403
            )

            # 4. REVIEWER approves first request via /approve
            app_res = client.post(
                f"/api/v1/approvals/{apr_ids[0]}/approve",
                headers={"Authorization": "Bearer reviewer-tok"},
                json={"decision_reason": "Approved for external partner"},
            )
            assert app_res.status_code == 200, app_res.text
            app_body = app_res.json()
            assert app_body["status"] == "APPROVED"
            assert app_body["reviewed_by"] == "uid-reviewer"
            assert app_body["reviewer"] == "uid-reviewer"
            assert app_body["decision_reason"] == "Approved for external partner"
            assert app_body["version"] == 2
            assert app_body["reviewed_at"] is not None

            # 5. Duplicate decision on approved record returns 409
            dup_res = client.post(
                f"/api/v1/approvals/{apr_ids[0]}/reject",
                headers={"Authorization": "Bearer admin-tok"},
                json={"decision_reason": "Late reject"},
            )
            assert dup_res.status_code == 409

            # 6. ADMIN rejects second request via /reject
            rej_res = client.post(
                f"/api/v1/approvals/{apr_ids[1]}/reject",
                headers={"Authorization": "Bearer admin-tok"},
                json={"decision_reason": "Denied by admin"},
            )
            assert rej_res.status_code == 200, rej_res.text
            rej_body = rej_res.json()
            assert rej_body["status"] == "REJECTED"
            assert rej_body["reviewed_by"] == "uid-admin"
            assert rej_body["version"] == 2

            # 7. Verify corresponding audit events exist for both decisions
            transitions = [
                r for r in audit_repo.export_chain_records() if r.get("event_type") == "APPROVAL_DECISION"
            ]
            assert len(transitions) == 2
            assert {t["actor_uid"] for t in transitions} == {"uid-reviewer", "uid-admin"}
    finally:
        app.dependency_overrides.clear()
