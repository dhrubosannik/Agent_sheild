"""End-to-end tests for Firestore ``policies`` collection against Auth + Firestore emulators."""

from __future__ import annotations

from datetime import datetime


def test_policies_crud_versioning_and_engine_integration_in_emulator(emulator, api, firestore_client) -> None:
    admin = emulator.verified_user("pol-admin@agentshield.test", "ADMIN")
    reviewer = emulator.verified_user("pol-reviewer@agentshield.test", "REVIEWER")
    admin_h = {"Authorization": f"Bearer {admin['token']}"}
    reviewer_h = {"Authorization": f"Bearer {reviewer['token']}"}

    # Create POLICY_001 blocking unapproved http_post
    create_res = api.post(
        "/api/v1/policies",
        headers=admin_h,
        json={
            "policy_id": "POLICY_001",
            "name": "Block Unapproved HTTP Post",
            "description": "Blocks http_post to unapproved destinations",
            "enabled": True,
            "priority": 1,
            "action": "BLOCK",
            "rules": {
                "tools": ["http_post"],
                "destination_classes": ["UNAPPROVED"],
            },
        },
    )
    assert create_res.status_code == 201, create_res.text
    created = create_res.json()
    assert created["policy_id"] == "POLICY_001"
    assert created["version"] == 1
    assert created["created_by"] == admin["uid"]

    # Raw Firestore doc has server Timestamps and all 11 fields
    raw = firestore_client.collection("policies").document("POLICY_001").get().to_dict()
    assert set(raw.keys()) == {
        "policy_id",
        "name",
        "description",
        "enabled",
        "priority",
        "action",
        "rules",
        "created_by",
        "created_at",
        "updated_at",
        "version",
    }
    assert isinstance(raw["created_at"], datetime)
    assert isinstance(raw["updated_at"], datetime)

    # Unauthorized modification by REVIEWER rejected
    assert (
        api.post("/api/v1/policies/POLICY_001/disable", headers=reviewer_h).status_code == 403
    )

    # Evaluate tool call against active POLICY_001
    ev1 = api.post(
        "/api/v1/evaluate",
        headers=reviewer_h,
        json={"tool_name": "http_post", "arguments": {"url": "https://evil.example.net/hook"}},
    )
    assert ev1.status_code == 200, ev1.text
    assert ev1.json()["decision"] == "BLOCK"
    assert ev1.json()["policy_id"] == "POLICY_001"

    # Disable POLICY_001 -> version 2; evaluation falls back to default-unapproved-destination
    dis = api.post("/api/v1/policies/POLICY_001/disable", headers=admin_h)
    assert dis.status_code == 200, dis.text
    assert dis.json()["enabled"] is False
    assert dis.json()["version"] == 2

    ev2 = api.post(
        "/api/v1/evaluate",
        headers=reviewer_h,
        json={"tool_name": "http_post", "arguments": {"url": "https://evil.example.net/hook"}},
    )
    assert ev2.status_code == 200
    assert ev2.json()["policy_id"] == "default-unapproved-destination"

    # Audit history contains CREATE (v1) and DISABLE (v2)
    hist = api.get("/api/v1/policies/POLICY_001/history", headers=admin_h)
    assert hist.status_code == 200, hist.text
    assert [(h["version"], h["change_type"]) for h in hist.json()] == [(1, "CREATE"), (2, "DISABLE")]
