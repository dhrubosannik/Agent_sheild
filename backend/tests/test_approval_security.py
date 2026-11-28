"""Approval authorization and transaction tests, SQLite mode (Phase 13.2, P4).
Firestore-mode equivalents run against the emulator in tests/emulator."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from backend.app.core.config import get_settings
from backend.app.main import app
from backend.app.services.audit_integrity import verify_audit_log
from backend.app.services.audit_logger import AuditLogger, get_audit_service
from backend.app.storage.database import Database

IDENTITIES = "local-admin:ADMIN,local-reviewer:REVIEWER,local-reviewer-2:REVIEWER,local-viewer:VIEWER"


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    logger = AuditLogger(db=Database(tmp_path / "approvals.db"))
    monkeypatch.setattr(get_settings(), "dev_auth_identities", IDENTITIES)
    app.dependency_overrides[get_audit_service] = lambda: logger
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield client, logger
    app.dependency_overrides.clear()


def _as(user: str) -> dict:
    return {"X-AgentShield-Dev-User": user}


def _pending(client: TestClient) -> str:
    res = client.post(
        "/api/v1/evaluate",
        headers=_as("local-admin"),
        json={"tool_name": "export_file", "arguments": {"to": "ops@external.example.net", "filename": "x.csv"}},
    )
    assert res.json()["decision"] == "REQUIRE_APPROVAL"
    return f"apr-{res.json()['event_id']}"


def test_decision_requires_authentication(env) -> None:
    client, _ = env
    approval_id = _pending(client)
    res = client.post(f"/api/v1/approvals/{approval_id}/decision", json={"decision": "APPROVED"})
    assert res.status_code == 401


def test_viewer_cannot_decide(env) -> None:
    client, logger = env
    approval_id = _pending(client)
    res = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=_as("local-viewer"), json={"decision": "APPROVED"})
    assert res.status_code == 403
    assert logger.get_approval(approval_id).status.value == "PENDING"


def test_reviewer_decision_records_authenticated_identity_and_audit_event(env) -> None:
    client, logger = env
    approval_id = _pending(client)
    res = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=_as("local-reviewer"),
        json={"decision": "REJECTED", "reviewer": "spoofed-name"},
    )
    assert res.status_code == 200
    assert res.json()["reviewer"] == "dev:local-reviewer"
    records = logger.audit_repo.export_chain_records()
    decisions = [r for r in records if r["event_type"] == "APPROVAL_DECISION"]
    assert len(decisions) == 1
    assert decisions[0]["actor_uid"] == "dev:local-reviewer"
    assert decisions[0]["related_event_id"] == approval_id.removeprefix("apr-")
    assert verify_audit_log(records, logger.audit_repo.chain_head())["verified"]["valid"] is True


def test_duplicate_decision_conflicts(env) -> None:
    client, logger = env
    approval_id = _pending(client)
    first = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=_as("local-reviewer"), json={"decision": "APPROVED"})
    second = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=_as("local-admin"), json={"decision": "REJECTED"})
    assert (first.status_code, second.status_code) == (200, 409)
    assert logger.get_approval(approval_id).status.value == "APPROVED"


def test_simultaneous_decisions_only_one_succeeds(env) -> None:
    client, logger = env
    approval_id = _pending(client)
    users = ["local-reviewer", "local-reviewer-2", "local-admin"] * 4
    decisions = ["APPROVED", "REJECTED"] * 6

    def decide(i: int) -> int:
        return client.post(
            f"/api/v1/approvals/{approval_id}/decision",
            headers=_as(users[i]),
            json={"decision": decisions[i]},
        ).status_code

    with ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(decide, range(12)))
    assert codes.count(200) == 1
    assert codes.count(409) == 11
    records = logger.audit_repo.export_chain_records()
    assert len([r for r in records if r["event_type"] == "APPROVAL_DECISION"]) == 1
    assert verify_audit_log(records, logger.audit_repo.chain_head())["verified"]["valid"] is True


def test_invalid_transition_values_rejected(env) -> None:
    client, _ = env
    approval_id = _pending(client)
    res = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=_as("local-admin"), json={"decision": "PENDING"})
    assert res.status_code == 422


def test_cursor_pagination_for_events_and_approvals(env) -> None:
    client, _ = env
    for _ in range(7):
        _pending(client)
    seen, cursor = [], None
    while True:
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = client.get("/api/v1/events", headers=_as("local-viewer"), params=params).json()
        seen += [item["event_id"] for item in page["items"]]
        assert page["total"] == 7
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 7

    page = client.get("/api/v1/approvals", headers=_as("local-viewer"), params={"limit": 5}).json()
    assert len(page["items"]) == 5 and page["next_cursor"]
    rest = client.get("/api/v1/approvals", headers=_as("local-viewer"), params={"limit": 5, "cursor": page["next_cursor"]}).json()
    assert len(rest["items"]) == 2 and rest["next_cursor"] is None
    assert client.get("/api/v1/events", headers=_as("local-viewer"), params={"cursor": "bogus"}).status_code == 400
