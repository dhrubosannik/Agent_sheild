"""Comprehensive test suite for Firebase Emulator Suite (Auth + Firestore + Rules)."""

import os
import sys
from pathlib import Path
import json
import time
import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure emulator environment variables
PROJECT_ID = "demo-agentshield"
AUTH_EMULATOR_HOST = "127.0.0.1:9099"
FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080"

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

from datetime import datetime, UTC
from backend.app.core.config import get_settings
get_settings.cache_clear()

import firebase_admin
from firebase_admin import auth, credentials, firestore
from backend.app.core.firebase import get_firebase_app, verify_firebase_id_token
from backend.app.core.firestore import get_firestore_client
from backend.app.core.auth import get_authenticated_user, require_roles, UserRole
from backend.app.models.audit_event import AuditEvent
from backend.app.models.approval import Approval
from backend.app.models.enums import SecurityDecision, DestinationClass, ExecutionStatus, ApprovalStatus
from backend.app.storage.firestore_audit_repository import FirestoreAuditRepository
from backend.app.storage.firestore_approval_repository import FirestoreApprovalRepository
from backend.app.storage.approval_repository import ApprovalConflictError, ApprovalNotFoundError

results = []

def record(name: str, passed: bool, details: str = ""):
    results.append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {details}")

def main():
    print("=" * 60)
    print("AgentShield Firebase Emulator Verification Suite")
    print(f"Target Project: {PROJECT_ID}")
    print(f"Auth Emulator: http://{AUTH_EMULATOR_HOST}")
    print(f"Firestore Emulator: http://{FIRESTORE_EMULATOR_HOST}")
    print("=" * 60)

    # 1. Initialize Firebase Admin against emulator
    try:
        try:
            app = firebase_admin.get_app()
        except ValueError:
            app = firebase_admin.initialize_app(
                credentials.ApplicationDefault() if False else None,
                {"projectId": PROJECT_ID},
            )
        record("Firebase Admin initialization", True, f"App initialized: {app.name}")
    except Exception as e:
        record("Firebase Admin initialization", False, str(e))
        return

    # 2. Authentication: Registration via REST API against Auth Emulator
    auth_base_url = f"http://{AUTH_EMULATOR_HOST}/identitytoolkit.googleapis.com/v1"
    
    # Clean up test accounts or use unique emails
    ts = int(time.time())
    admin_email = f"admin_{ts}@agentshield.test"
    reviewer_email = f"reviewer_{ts}@agentshield.test"
    viewer_email = f"viewer_{ts}@agentshield.test"
    test_password = "SecurePassword123!"

    users_data = {}
    for role_name, email in [("ADMIN", admin_email), ("REVIEWER", reviewer_email), ("VIEWER", viewer_email)]:
        # Register
        resp = requests.post(
            f"{auth_base_url}/accounts:signUp?key=fake-api-key",
            json={"email": email, "password": test_password, "returnSecureToken": True},
        )
        if resp.status_code == 200:
            data = resp.json()
            uid = data["localId"]
            id_token = data["idToken"]
            users_data[role_name] = {
                "uid": uid,
                "email": email,
                "id_token": id_token,
                "refresh_token": data["refreshToken"],
            }
            # Verify the email (required by the backend since commit 9791375)
            requests.post(
                f"{auth_base_url}/accounts:sendOobCode?key=fake-api-key",
                json={"requestType": "VERIFY_EMAIL", "idToken": id_token},
            ).raise_for_status()
            codes = requests.get(
                f"http://{AUTH_EMULATOR_HOST}/emulator/v1/projects/{PROJECT_ID}/oobCodes"
            ).json()["oobCodes"]
            code = [c for c in codes if c["email"].lower() == email.lower() and c["requestType"] == "VERIFY_EMAIL"][-1]
            requests.post(
                f"{auth_base_url}/accounts:update?key=fake-api-key", json={"oobCode": code["oobCode"]}
            ).raise_for_status()
            # Assign custom claims
            auth.set_custom_user_claims(uid, {"role": role_name}, app=app)
            record(f"Auth Registration ({role_name})", True, f"UID: {uid}, Email: {email}")
        else:
            record(f"Auth Registration ({role_name})", False, f"Status {resp.status_code}: {resp.text}")

    # 3. Test Login (signInWithPassword) to get refreshed token with claims
    for role_name in ["ADMIN", "REVIEWER", "VIEWER"]:
        email = users_data[role_name]["email"]
        resp = requests.post(
            f"{auth_base_url}/accounts:signInWithPassword?key=fake-api-key",
            json={"email": email, "password": test_password, "returnSecureToken": True},
        )
        if resp.status_code == 200:
            data = resp.json()
            users_data[role_name]["id_token"] = data["idToken"]
            record(f"Auth Login & Token Refresh ({role_name})", True, "Successfully logged in")
        else:
            record(f"Auth Login & Token Refresh ({role_name})", False, f"Status {resp.status_code}: {resp.text}")

    # 4. Test Password Reset Flow
    resp = requests.post(
        f"{auth_base_url}/accounts:sendOobCode?key=fake-api-key",
        json={"requestType": "PASSWORD_RESET", "email": admin_email},
    )
    if resp.status_code == 200:
        record("Auth Password Reset Flow", True, f"OOB Code sent for {admin_email}")
    else:
        record("Auth Password Reset Flow", False, f"Status {resp.status_code}: {resp.text}")

    # 5. Backend Token Verification
    for role_name in ["ADMIN", "REVIEWER", "VIEWER"]:
        token = users_data[role_name]["id_token"]
        try:
            decoded = verify_firebase_id_token(token)
            verified_role = decoded.get("role")
            if verified_role == role_name:
                record(f"Backend Token Verification ({role_name})", True, f"Aud: {decoded.get('aud')}, Role: {verified_role}")
            else:
                record(f"Backend Token Verification ({role_name})", False, f"Expected {role_name}, got {verified_role}")
        except Exception as e:
            record(f"Backend Token Verification ({role_name})", False, str(e))

    # 6. Negative Token Verification Tests
    # Invalid token
    try:
        verify_firebase_id_token("invalid.token.structure")
        record("Invalid Token Rejection", False, "Failed to reject invalid token")
    except Exception:
        record("Invalid Token Rejection", True, "Invalid token properly rejected")

    # Missing authorization header check
    from fastapi import HTTPException
    try:
        get_authenticated_user(authorization=None)
        record("Missing Token Rejection", False, "Did not reject missing token")
    except HTTPException as e:
        record("Missing Token Rejection", True, f"Rejected with HTTP {e.status_code}")

    # 7. Role-Based Authorization
    # Test ADMIN can access all
    admin_auth = f"Bearer {users_data['ADMIN']['id_token']}"
    reviewer_auth = f"Bearer {users_data['REVIEWER']['id_token']}"
    viewer_auth = f"Bearer {users_data['VIEWER']['id_token']}"

    admin_dep = require_roles(UserRole.ADMIN)
    reviewer_dep = require_roles(UserRole.ADMIN, UserRole.REVIEWER)
    viewer_dep = require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)

    # Admin check
    try:
        user = admin_dep(None, admin_auth, None)
        record("Role Auth: ADMIN on Admin endpoint", True, f"Allowed UID {user.uid}")
    except Exception as e:
        record("Role Auth: ADMIN on Admin endpoint", False, str(e))

    # Reviewer on Reviewer endpoint (Allowed)
    try:
        user = reviewer_dep(None, reviewer_auth, None)
        record("Role Auth: REVIEWER on Reviewer endpoint", True, f"Allowed UID {user.uid}")
    except Exception as e:
        record("Role Auth: REVIEWER on Reviewer endpoint", False, str(e))

    # Reviewer on Admin endpoint (Must be 403 Forbidden)
    try:
        admin_dep(None, reviewer_auth, None)
        record("Role Auth: REVIEWER blocked from Admin endpoint", False, "Reviewer was allowed on Admin endpoint")
    except HTTPException as e:
        record("Role Auth: REVIEWER blocked from Admin endpoint", e.status_code == 403, f"Blocked with HTTP {e.status_code}")

    # Viewer on Reviewer endpoint (Must be 403 Forbidden)
    try:
        reviewer_dep(None, viewer_auth, None)
        record("Role Auth: VIEWER blocked from Reviewer endpoint", False, "Viewer was allowed on Reviewer endpoint")
    except HTTPException as e:
        record("Role Auth: VIEWER blocked from Reviewer endpoint", e.status_code == 403, f"Blocked with HTTP {e.status_code}")

    # Viewer on Viewer endpoint (Allowed)
    try:
        user = viewer_dep(None, viewer_auth, None)
        record("Role Auth: VIEWER on Read endpoint", True, f"Allowed UID {user.uid}")
    except Exception as e:
        record("Role Auth: VIEWER on Read endpoint", False, str(e))

    # 8. Firestore Operations (Admin SDK repository integration)
    db = get_firestore_client()
    audit_repo = FirestoreAuditRepository(client=db)
    approval_repo = FirestoreApprovalRepository(client=db)

    # Test audit event insertion & hash chaining
    events = []
    for i in range(1, 4):
        evt = AuditEvent(
            event_id=f"test-evt-{ts}-{i}",
            timestamp=datetime.now(UTC),
            tool_name="test_tool",
            decision=SecurityDecision.ALLOW if i != 2 else SecurityDecision.REQUIRE_APPROVAL,
            policy_id="test_policy",
            reason_codes=["TEST_REASON"],
            destination_class=DestinationClass.INTERNAL,
            data_labels=["TEST_LABEL"],
            risk_signals=[],
            payload_fingerprint="fp123",
            execution_status=ExecutionStatus.EXECUTED,
            actor_uid=users_data["ADMIN"]["uid"],
        )
        created = audit_repo.create(evt)
        events.append(created)

    record("Firestore Audit Chain Creation", True, f"Created 3 chained events (sequences: {[e.sequence for e in events]})")
    
    # Verify hash chain continuity
    from backend.app.services.audit_integrity import verify_audit_log
    raw_events = audit_repo.export_chain_records()
    # Check sequences and hashes
    chain_report = verify_audit_log(raw_events, audit_repo.chain_head())["verified"]
    valid, err = chain_report["valid"], chain_report["error"]
    record("Firestore Hash-Chain Verification", valid, f"Integrity check: {err or 'VALID'} ({chain_report['count']} v2 records)")

    # Test Approval workflow in Firestore
    test_approval = Approval(
        approval_id=f"test-apr-{ts}",
        event_id=events[1].event_id,
        tool_name="test_tool",
        requested_action="Execute test action",
        destination_class=DestinationClass.INTERNAL,
        status=ApprovalStatus.PENDING,
        created_at=datetime.now(UTC),
    )
    approval_repo.create(test_approval)
    fetched_apr = approval_repo.get_by_id(test_approval.approval_id)
    record("Firestore Approval Creation & Read", fetched_apr is not None and fetched_apr.status == ApprovalStatus.PENDING, f"Approval ID: {test_approval.approval_id}")

    # Update approval decision
    updated_apr = approval_repo.update_decision(test_approval.approval_id, ApprovalStatus.APPROVED, reviewer=users_data["REVIEWER"]["uid"])
    record("Firestore Approval Decision Update", updated_apr.status == ApprovalStatus.APPROVED and updated_apr.reviewer == users_data["REVIEWER"]["uid"], f"Status: {updated_apr.status.value}")

    # Conflict test: duplicate review on already reviewed approval
    try:
        approval_repo.update_decision(test_approval.approval_id, ApprovalStatus.REJECTED, reviewer=users_data["ADMIN"]["uid"])
        record("Firestore Approval Conflict Rejection", False, "Allowed duplicate review")
    except ApprovalConflictError:
        record("Firestore Approval Conflict Rejection", True, "Conflict properly raised on already-reviewed approval")

    # 9. Firestore Security Rules direct testing (Client REST calls)
    firestore_base = f"http://{FIRESTORE_EMULATOR_HOST}/v1/projects/{PROJECT_ID}/databases/(default)/documents"
    
    # A. Unauthenticated read on audit_events
    unauth_resp = requests.get(f"{firestore_base}/audit_events/{events[0].event_id}")
    record("Security Rules: Unauthenticated Read Denied", unauth_resp.status_code == 403 or unauth_resp.status_code == 401 or "PERMISSION_DENIED" in unauth_resp.text, f"HTTP {unauth_resp.status_code}")

    # B. Client direct write to audit_events (MUST BE FORBIDDEN even with token)
    auth_header = {"Authorization": f"Bearer {users_data['ADMIN']['id_token']}"}
    client_write_resp = requests.post(
        f"{firestore_base}/audit_events",
        headers=auth_header,
        json={"fields": {"event_id": {"stringValue": "evil-event"}}},
    )
    record("Security Rules: Client Write to audit_events Forbidden", client_write_resp.status_code in (403, 400) or "PERMISSION_DENIED" in client_write_resp.text, f"HTTP {client_write_resp.status_code}")

    # C. Default-deny behavior on unknown collection
    arbitrary_write_resp = requests.post(
        f"{firestore_base}/some_random_secret_collection",
        headers=auth_header,
        json={"fields": {"secret": {"stringValue": "classified"}}},
    )
    record("Security Rules: Default-Deny on Unknown Collection", arbitrary_write_resp.status_code in (403, 400) or "PERMISSION_DENIED" in arbitrary_write_resp.text, f"HTTP {arbitrary_write_resp.status_code}")

    print("=" * 60)
    passed_count = sum(1 for r in results if r["passed"])
    print(f"Summary: {passed_count}/{len(results)} tests passed.")
    print("=" * 60)

    # Save results to json for report generation
    with open("scripts/emulator_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
