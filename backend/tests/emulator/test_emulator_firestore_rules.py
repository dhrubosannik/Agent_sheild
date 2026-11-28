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


def test_users_collection_rules_deny_client_writes_and_restrict_reads(seeded, firestore_client) -> None:
    viewer = seeded.verified_user("rules-user-viewer@agentshield.test")
    other = seeded.verified_user("rules-user-other@agentshield.test")
    admin = seeded.verified_user("rules-user-admin@agentshield.test", "ADMIN")

    for u, role in [(viewer, "VIEWER"), (other, "VIEWER"), (admin, "ADMIN")]:
        firestore_client.collection("users").document(u["uid"]).set(
            {"uid": u["uid"], "email": f"{u['uid']}@agentshield.test", "role": role, "status": "ACTIVE"}
        )

    viewer_headers = {"Authorization": f"Bearer {viewer['token']}"}
    admin_headers = {"Authorization": f"Bearer {admin['token']}"}

    # Owner can read own profile; cannot read another user's profile
    assert seeded.http.get(f"{seeded.firestore_url}/users/{viewer['uid']}", headers=viewer_headers).status_code == 200
    assert seeded.http.get(f"{seeded.firestore_url}/users/{other['uid']}", headers=viewer_headers).status_code == 403

    # Verified admin can read any user profile
    assert seeded.http.get(f"{seeded.firestore_url}/users/{viewer['uid']}", headers=admin_headers).status_code == 200

    # Neither viewer nor admin client SDK can create, update, or delete users/{uid}
    assert (
        seeded.http.patch(
            f"{seeded.firestore_url}/users/{viewer['uid']}?updateMask.fieldPaths=role",
            headers=viewer_headers,
            json=_doc({"role": "ADMIN"}),
        ).status_code
        == 403
    )
    assert (
        seeded.http.patch(
            f"{seeded.firestore_url}/users/{viewer['uid']}?updateMask.fieldPaths=role",
            headers=admin_headers,
            json=_doc({"role": "ADMIN"}),
        ).status_code
        == 403
    )
    assert (
        seeded.http.post(
            f"{seeded.firestore_url}/users?documentId=client-created",
            headers=admin_headers,
            json=_doc({"uid": "client-created", "role": "ADMIN"}),
        ).status_code
        == 403
    )
    assert seeded.http.delete(f"{seeded.firestore_url}/users/{viewer['uid']}", headers=admin_headers).status_code == 403


def test_security_events_collection_rules_deny_all_client_writes(seeded, firestore_client) -> None:
    viewer = seeded.verified_user("rules-se-viewer@agentshield.test")
    admin = seeded.verified_user("rules-se-admin@agentshield.test", "ADMIN")
    firestore_client.collection("security_events").document("se-1").set(
        {"event_id": "se-1", "user_id": viewer["uid"], "decision": "BLOCK", "risk_level": "HIGH"}
    )

    for token in (viewer["token"], admin["token"]):
        headers = {"Authorization": f"Bearer {token}"}
        assert seeded.http.get(f"{seeded.firestore_url}/security_events/se-1", headers=headers).status_code == 200
        assert (
            seeded.http.post(
                f"{seeded.firestore_url}/security_events?documentId=se-client",
                headers=headers,
                json=_doc({"event_id": "se-client", "decision": "ALLOW"}),
            ).status_code
            == 403
        )
        assert (
            seeded.http.patch(
                f"{seeded.firestore_url}/security_events/se-1?updateMask.fieldPaths=decision",
                headers=headers,
                json=_doc({"decision": "ALLOW"}),
            ).status_code
            == 403
        )
        assert seeded.http.delete(f"{seeded.firestore_url}/security_events/se-1", headers=headers).status_code == 403

    # Unauthenticated client cannot read or write security_events
    assert seeded.http.get(f"{seeded.firestore_url}/security_events/se-1").status_code == 403


def test_policies_collection_rules_deny_all_client_writes(seeded, firestore_client) -> None:
    viewer = seeded.verified_user("rules-pol-viewer@agentshield.test")
    admin = seeded.verified_user("rules-pol-admin@agentshield.test", "ADMIN")
    firestore_client.collection("policies").document("POLICY_RULES_1").set(
        {"policy_id": "POLICY_RULES_1", "name": "Test", "enabled": True, "priority": 1, "action": "BLOCK"}
    )
    firestore_client.collection("policies").document("POLICY_RULES_1").collection("history").document("000001").set(
        {"policy_id": "POLICY_RULES_1", "version": 1, "change_type": "CREATE"}
    )

    viewer_h = {"Authorization": f"Bearer {viewer['token']}"}
    admin_h = {"Authorization": f"Bearer {admin['token']}"}

    # Verified users can read policies; only admin can read history
    assert seeded.http.get(f"{seeded.firestore_url}/policies/POLICY_RULES_1", headers=viewer_h).status_code == 200
    assert seeded.http.get(f"{seeded.firestore_url}/policies/POLICY_RULES_1/history/000001", headers=viewer_h).status_code == 403
    assert seeded.http.get(f"{seeded.firestore_url}/policies/POLICY_RULES_1/history/000001", headers=admin_h).status_code == 200

    # Neither viewer nor admin client SDK can create, update, or delete policies or history
    for headers in (viewer_h, admin_h):
        assert (
            seeded.http.post(
                f"{seeded.firestore_url}/policies?documentId=POLICY_CLIENT",
                headers=headers,
                json=_doc({"policy_id": "POLICY_CLIENT", "action": "ALLOW"}),
            ).status_code
            == 403
        )
        assert (
            seeded.http.patch(
                f"{seeded.firestore_url}/policies/POLICY_RULES_1?updateMask.fieldPaths=enabled",
                headers=headers,
                json=_doc({"name": "Tampered"}),
            ).status_code
            == 403
        )
        assert seeded.http.delete(f"{seeded.firestore_url}/policies/POLICY_RULES_1", headers=headers).status_code == 403
        assert (
            seeded.http.delete(
                f"{seeded.firestore_url}/policies/POLICY_RULES_1/history/000001",
                headers=headers,
            ).status_code
            == 403
        )
