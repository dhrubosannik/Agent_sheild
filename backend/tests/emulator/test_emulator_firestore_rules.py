"""Firestore Security Rules: browser (client SDK / REST with user ID token)
writes must be denied. Uses the emulator with firestore.rules loaded."""

import pytest


def _doc(fields: dict) -> dict:
    return {"fields": {k: {"stringValue": v} for k, v in fields.items()}}


@pytest.fixture
def seeded(emulator, firestore_client):
    firestore_client.collection("approvals").document("apr-1").set(
        {"approval_id": "apr-1", "event_id": "evt-1", "status": "PENDING", "tool_name": "export_file"}
    )
    firestore_client.collection("audit_events").document("evt-1").set({"event_id": "evt-1", "decision": "REQUIRE_APPROVAL"})
    return emulator


@pytest.mark.parametrize("role", ["REVIEWER", "ADMIN", None])
def test_client_cannot_write_approval_decisions(seeded, role) -> None:
    user = seeded.verified_user(f"rules-{role or 'viewer'}@agentshield.test", role)
    headers = {"Authorization": f"Bearer {user['token']}"}
    url = f"{seeded.firestore_url}/approvals/apr-1?updateMask.fieldPaths=status"
    res = seeded.http.patch(url, headers=headers, json=_doc({"status": "APPROVED"}))
    assert res.status_code == 403, res.text
    create = seeded.http.post(f"{seeded.firestore_url}/approvals?documentId=apr-2", headers=headers, json=_doc({"status": "APPROVED"}))
    assert create.status_code == 403
    delete = seeded.http.delete(f"{seeded.firestore_url}/approvals/apr-1", headers=headers)
    assert delete.status_code == 403
    read = seeded.http.get(f"{seeded.firestore_url}/approvals/apr-1", headers=headers)
    assert read.status_code == 200
    assert read.json()["fields"]["status"]["stringValue"] == "PENDING"


@pytest.mark.parametrize(
    "collection",
    ["audit_events", "audit_transitions", "audit_sequence_v2", "system_metadata", "audit_event_status", "rate_limits"],
)
def test_client_cannot_write_audit_or_chain_state(seeded, collection) -> None:
    user = seeded.verified_user(f"rules-admin-{collection}@agentshield.test", "ADMIN")
    headers = {"Authorization": f"Bearer {user['token']}"}
    res = seeded.http.patch(f"{seeded.firestore_url}/{collection}/evt-1", headers=headers, json=_doc({"decision": "ALLOW"}))
    assert res.status_code == 403, res.text
    assert seeded.http.delete(f"{seeded.firestore_url}/{collection}/evt-1", headers=headers).status_code == 403


def test_unverified_user_cannot_read(seeded) -> None:
    account = seeded.sign_up("unverified-reader@agentshield.test")
    headers = {"Authorization": f"Bearer {account['idToken']}"}
    assert seeded.http.get(f"{seeded.firestore_url}/approvals/apr-1", headers=headers).status_code == 403
    assert seeded.http.get(f"{seeded.firestore_url}/approvals/apr-1").status_code == 403
