"""Approval decisions in Firestore mode through the real API."""

from concurrent.futures import ThreadPoolExecutor

from backend.app.services.audit_integrity import verify_audit_log
from backend.app.storage.firestore_audit_repository import FirestoreAuditRepository


def _h(user):
    return {"Authorization": f"Bearer {user['token']}"}


def _pending(api, admin) -> str:
    res = api.post(
        "/api/v1/evaluate",
        headers=_h(admin),
        json={"tool_name": "export_file", "arguments": {"to": "ops@external.example.net", "filename": "x.csv"}},
    )
    assert res.status_code == 200, res.text
    assert res.json()["decision"] == "REQUIRE_APPROVAL"
    return f"apr-{res.json()['event_id']}"


def _chain(firestore_client):
    repo = FirestoreAuditRepository(firestore_client)
    return repo, verify_audit_log(repo.export_chain_records(), repo.chain_head())


def test_unauthorized_api_decisions(emulator, api) -> None:
    admin = emulator.verified_user("appr-admin@agentshield.test", "ADMIN")
    viewer = emulator.verified_user("appr-viewer@agentshield.test")
    approval_id = _pending(api, admin)
    url = f"/api/v1/approvals/{approval_id}/decision"
    assert api.post(url, json={"decision": "APPROVED"}).status_code == 401
    assert api.post(url, headers=_h(viewer), json={"decision": "APPROVED"}).status_code == 403
    unverified = emulator.sign_up("appr-unverified@agentshield.test")
    emulator.set_role(unverified["localId"], "REVIEWER")
    token = emulator.sign_in("appr-unverified@agentshield.test")["idToken"]
    assert api.post(url, headers={"Authorization": f"Bearer {token}"}, json={"decision": "APPROVED"}).status_code == 403
    pending = api.get("/api/v1/approvals", headers=_h(admin), params={"status": "PENDING"}).json()
    assert [a["approval_id"] for a in pending["items"]] == [approval_id]


def test_decision_duplicate_and_audit_record(emulator, api, firestore_client) -> None:
    admin = emulator.verified_user("dup-admin@agentshield.test", "ADMIN")
    reviewer = emulator.verified_user("dup-reviewer@agentshield.test", "REVIEWER")
    approval_id = _pending(api, admin)
    url = f"/api/v1/approvals/{approval_id}/decision"

    first = api.post(url, headers=_h(reviewer), json={"decision": "APPROVED", "reviewer": "spoof"})
    assert first.status_code == 200, first.text
    assert first.json()["reviewer"] == reviewer["uid"]
    assert api.post(url, headers=_h(admin), json={"decision": "REJECTED"}).status_code == 409

    repo, report = _chain(firestore_client)
    decisions = [r for r in repo.export_chain_records() if r.get("event_type") == "APPROVAL_DECISION"]
    assert len(decisions) == 1 and decisions[0]["actor_uid"] == reviewer["uid"]
    assert report["verified"]["valid"] is True, report


def test_simultaneous_decisions_only_one_succeeds(emulator, api, firestore_client) -> None:
    admin = emulator.verified_user("race-admin@agentshield.test", "ADMIN")
    reviewers = [emulator.verified_user(f"race-r{i}@agentshield.test", "REVIEWER") for i in range(4)]
    approval_id = _pending(api, admin)
    url = f"/api/v1/approvals/{approval_id}/decision"

    def decide(i: int) -> int:
        return api.post(url, headers=_h(reviewers[i % 4]), json={"decision": "APPROVED" if i % 2 else "REJECTED"}).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(decide, range(8)))
    assert codes.count(200) == 1, codes
    assert codes.count(409) == 7, codes
    repo, report = _chain(firestore_client)
    assert len([r for r in repo.export_chain_records() if r.get("event_type") == "APPROVAL_DECISION"]) == 1
    assert report["verified"]["valid"] is True, report


def test_cursor_pagination_in_firestore(emulator, api) -> None:
    admin = emulator.verified_user("page-admin@agentshield.test", "ADMIN")
    for _ in range(7):
        _pending(api, admin)
    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 3, "decision": "REQUIRE_APPROVAL", **({"cursor": cursor} if cursor else {})}
        page = api.get("/api/v1/events", headers=_h(admin), params=params).json()
        assert page["total"] == 7
        seen += [i["event_id"] for i in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and len(seen) == len(set(seen)) == 7
    approvals = api.get("/api/v1/approvals", headers=_h(admin), params={"status": "PENDING", "limit": 4}).json()
    assert approvals["total"] == 7 and len(approvals["items"]) == 4 and approvals["next_cursor"]
