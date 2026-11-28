"""End-to-End integration test for FastAPI with Firebase Auth and Firestore emulators.

Tests:
1. Authentication verification
2. Protected endpoints (401 without token, 200 with valid token)
3. Role enforcement on endpoints
4. Four core AgentShield demo scenarios running against live Firestore
5. Approval workflow review and conflict handling
"""

import os
import sys
import json
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

AUTH_EMULATOR_HOST = "127.0.0.1:9099"
FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080"
PROJECT_ID = "demo-agentshield"

os.environ["FIREBASE_AUTH_EMULATOR_HOST"] = AUTH_EMULATOR_HOST
os.environ["FIRESTORE_EMULATOR_HOST"] = FIRESTORE_EMULATOR_HOST
os.environ["FIREBASE_TARGET"] = "emulator"
os.environ["AGENTSHIELD_TEST_MODE"] = "1"
os.environ["AGENTSHIELD_ENV_FILE"] = "/nonexistent/agentshield-test-env"
os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
os.environ["FIREBASE_PROJECT_ID"] = PROJECT_ID
os.environ["GCLOUD_PROJECT"] = PROJECT_ID
os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_MODE"] = "firestore"
os.environ["FIREBASE_AUTH_REQUIRED"] = "true"

import requests
from fastapi.testclient import TestClient

from backend.app.core.config import get_settings
get_settings.cache_clear()

import firebase_admin
from firebase_admin import auth, credentials
from backend.app.main import app

results = []

def record(name: str, passed: bool, details: str = ""):
    results.append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {details}")

def main():
    print("=" * 60)
    print("AgentShield End-to-End Integration & Demo Verification")
    print("=" * 60)

    try:
        fb_app = firebase_admin.get_app()
    except ValueError:
        fb_app = firebase_admin.initialize_app(None, {"projectId": PROJECT_ID})

    client = TestClient(app)
    auth_base = f"http://{AUTH_EMULATOR_HOST}/identitytoolkit.googleapis.com/v1"

    # Step 1: Register test users (Admin, Reviewer, Viewer)
    ts = int(time.time())
    users = {}
    for role in ("ADMIN", "REVIEWER", "VIEWER"):
        email = f"e2e_{role.lower()}_{ts}@agentshield.test"
        resp = requests.post(
            f"{auth_base}/accounts:signUp?key=fake-key",
            json={"email": email, "password": "TestPassword123!", "returnSecureToken": True},
        )
        data = resp.json()
        uid = data["localId"]
        # Verify the email (the backend rejects unverified accounts)
        requests.post(
            f"{auth_base}/accounts:sendOobCode?key=fake-key",
            json={"requestType": "VERIFY_EMAIL", "idToken": data["idToken"]},
        ).raise_for_status()
        codes = requests.get(f"http://{AUTH_EMULATOR_HOST}/emulator/v1/projects/{PROJECT_ID}/oobCodes").json()["oobCodes"]
        code = [c for c in codes if c["email"].lower() == email.lower() and c["requestType"] == "VERIFY_EMAIL"][-1]
        requests.post(f"{auth_base}/accounts:update?key=fake-key", json={"oobCode": code["oobCode"]}).raise_for_status()
        # Set custom role claim
        auth.set_custom_user_claims(uid, {"role": role}, app=fb_app)
        # Login to refresh token with role claim
        login_resp = requests.post(
            f"{auth_base}/accounts:signInWithPassword?key=fake-key",
            json={"email": email, "password": "TestPassword123!", "returnSecureToken": True},
        )
        token = login_resp.json()["idToken"]
        users[role] = {"uid": uid, "email": email, "token": token}

    admin_header = {"Authorization": f"Bearer {users['ADMIN']['token']}"}
    reviewer_header = {"Authorization": f"Bearer {users['REVIEWER']['token']}"}
    viewer_header = {"Authorization": f"Bearer {users['VIEWER']['token']}"}

    # Step 2: Unauthenticated access test
    # Health should be public
    r = client.get("/health")
    record("Health Endpoint (Public)", r.status_code == 200, f"Status: {r.status_code}")

    # Protected endpoint without auth -> 401
    r = client.get("/api/v1/events")
    record("Unauthenticated Access Rejection (/events)", r.status_code == 401, f"Status: {r.status_code}")

    r = client.get("/api/v1/approvals")
    record("Unauthenticated Access Rejection (/approvals)", r.status_code == 401, f"Status: {r.status_code}")

    r = client.get("/api/v1/policies/current")
    record("Unauthenticated Access Rejection (/policies)", r.status_code == 401, f"Status: {r.status_code}")

    # Step 3: Authenticated access with VIEWER role
    r = client.get("/api/v1/events", headers=viewer_header)
    record("Authenticated Access with VIEWER (/events)", r.status_code == 200, f"Total items: {r.json().get('total')}")

    r = client.get("/api/v1/approvals", headers=viewer_header)
    record("Authenticated Access with VIEWER (/approvals)", r.status_code == 200, f"Total items: {r.json().get('total')}")

    r = client.get("/api/v1/policies/current", headers=viewer_header)
    record("Authenticated Access with VIEWER (/policies)", r.status_code == 200, f"Policy version: {r.json().get('version')}")

    # Step 4: Retest All Four AgentShield Demo Scenarios via Protected API
    # 4.1 Safe Scenario (Benign customer search -> ALLOW)
    r_safe = client.post("/api/v1/demo/run/safe", headers=viewer_header)
    safe_data = r_safe.json()
    safe_ok = (
        r_safe.status_code == 200
        and len(safe_data["results"]) == 1
        and safe_data["results"][0]["decision"] == "ALLOW"
        and safe_data["results"][0]["execution_status"] == "EXECUTED"
    )
    record("Demo Scenario 1: Safe Tool Call (ALLOW & Executed)", safe_ok, f"Decision: {safe_data['results'][0]['decision']}")

    # 4.2 Malicious Scenario (Secret exfiltration -> BLOCK)
    r_mal = client.post("/api/v1/demo/run/malicious", headers=viewer_header)
    mal_data = r_mal.json()
    mal_ok = (
        r_mal.status_code == 200
        and len(mal_data["results"]) == 1
        and mal_data["results"][0]["decision"] == "BLOCK"
        and mal_data["results"][0]["execution_status"] == "NOT_EXECUTED"
    )
    record("Demo Scenario 2: Malicious Tool Call (BLOCK & Not Executed)", mal_ok, f"Decision: {mal_data['results'][0]['decision']}")

    # 4.3 Redaction Scenario (PII Sanitization -> REDACT)
    r_red = client.post("/api/v1/demo/run/redaction", headers=viewer_header)
    red_data = r_red.json()
    red_ok = (
        r_red.status_code == 200
        and len(red_data["results"]) == 1
        and red_data["results"][0]["decision"] == "REDACT"
        and red_data["results"][0]["execution_status"] == "REDACTED_AND_EXECUTED"
    )
    record("Demo Scenario 3: Redaction Tool Call (REDACT & Executed with Sanitized Args)", red_ok, f"Decision: {red_data['results'][0]['decision']}")

    # 4.4 Approval Scenario (High-risk action -> REQUIRE_APPROVAL)
    r_app = client.post("/api/v1/demo/run/approval", headers=viewer_header)
    app_data = r_app.json()
    app_ok = (
        r_app.status_code == 200
        and len(app_data["results"]) == 2
        and all(res["decision"] == "REQUIRE_APPROVAL" and res["execution_status"] == "PENDING_APPROVAL" for res in app_data["results"])
    )
    record("Demo Scenario 4: Approval Tool Call (REQUIRE_APPROVAL & Never Executed)", app_ok, f"Results count: {len(app_data['results'])}")

    # Step 5: Test Approval Review Workflow via Protected API
    # Retrieve pending approvals
    r_list = client.get("/api/v1/approvals?status=PENDING", headers=viewer_header)
    pending_items = r_list.json().get("items", [])
    record("Pending Approvals Query in Firestore", len(pending_items) > 0, f"Found {len(pending_items)} pending items")

    if pending_items:
        target_approval_id = pending_items[0]["approval_id"]

        # Attempt to decide with VIEWER role -> Expect 403 Forbidden
        r_decide_viewer = client.post(
            f"/api/v1/approvals/{target_approval_id}/decision",
            headers=viewer_header,
            json={"decision": "APPROVED", "reviewer": "viewer-hacker"},
        )
        record("Approval Decision by VIEWER Forbidden", r_decide_viewer.status_code == 403, f"Status: {r_decide_viewer.status_code}")

        # Decide with REVIEWER role -> Expect 200 OK
        r_decide_reviewer = client.post(
            f"/api/v1/approvals/{target_approval_id}/decision",
            headers=reviewer_header,
            json={"decision": "APPROVED", "reviewer": users["REVIEWER"]["uid"]},
        )
        record("Approval Decision by REVIEWER Allowed", r_decide_reviewer.status_code == 200 and r_decide_reviewer.json()["status"] == "APPROVED", f"Status: {r_decide_reviewer.status_code}")

        # Attempt duplicate decision -> Expect 409 Conflict
        r_duplicate = client.post(
            f"/api/v1/approvals/{target_approval_id}/decision",
            headers=admin_header,
            json={"decision": "REJECTED", "reviewer": users["ADMIN"]["uid"]},
        )
        record("Approval Conflict on Re-Review (HTTP 409)", r_duplicate.status_code == 409, f"Status: {r_duplicate.status_code}")

    # Step 6: Test Admin Role Assignment API
    # REVIEWER attempting to assign role -> Expect 403 Forbidden
    r_assign_rev = client.post(
        f"/api/v1/admin/users/{users['VIEWER']['uid']}/role",
        headers=reviewer_header,
        json={"role": "ADMIN"},
    )
    record("Role Assignment by Non-Admin Forbidden", r_assign_rev.status_code == 403, f"Status: {r_assign_rev.status_code}")

    # ADMIN assigning role -> Expect 200 OK
    r_assign_adm = client.post(
        f"/api/v1/admin/users/{users['VIEWER']['uid']}/role",
        headers=admin_header,
        json={"role": "REVIEWER"},
    )
    record("Role Assignment by ADMIN Allowed", r_assign_adm.status_code == 200 and r_assign_adm.json()["role"] == "REVIEWER", f"Status: {r_assign_adm.status_code}")

    # ADMIN attempting to self-demote -> Expect 403 Forbidden
    r_self_demote = client.post(
        f"/api/v1/admin/users/{users['ADMIN']['uid']}/role",
        headers=admin_header,
        json={"role": "VIEWER"},
    )
    record("Admin Self-Demotion Prevented", r_self_demote.status_code == 403, f"Status: {r_self_demote.status_code}")

    print("=" * 60)
    passed_count = sum(1 for r in results if r["passed"])
    print(f"Summary: {passed_count}/{len(results)} tests passed.")
    print("=" * 60)

    with open("scripts/e2e_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
