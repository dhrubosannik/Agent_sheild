"""Verify AgentShield's Firebase connection for the selected environment file.

    # Emulator mode (start emulators first; full read/write with synthetic data)
    AGENTSHIELD_ENV_FILE=.env.emulator .venv/bin/python scripts/verify_firebase_connection.py

    # Shared cloud mode (read-only by default)
    AGENTSHIELD_ENV_FILE=.env.cloud .venv/bin/python scripts/verify_firebase_connection.py
    # ...optionally also create, verify and delete one synthetic test user:
    AGENTSHIELD_ENV_FILE=.env.cloud .venv/bin/python scripts/verify_firebase_connection.py --allow-cloud-test-user

Checks: configuration, Firebase Admin initialization, Authentication
connection, ID-token verification, Firestore connection, user-document
access (rules), security-event (audit) repository, approval repository.

Safety:
* Shared cloud mode never writes audit events, approvals or existing
  documents (audit records are append-only and permanent), never resets
  data and never migrates. With --allow-cloud-test-user it creates exactly
  one synthetic Auth user and its users/{uid} document, then deletes both.
* Tokens, keys and credential paths are never printed.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import os
from pathlib import Path
import sys
import time
import traceback
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

import httpx  # noqa: E402

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.firebase_config import emulator_hosts, firebase_target, validate_firebase_configuration  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name}{': ' + detail if detail else ''}")


def web_api_key(target: str) -> str | None:
    if target == "emulator":
        return "demo-api-key"
    key = os.environ.get("FIREBASE_WEB_API_KEY")
    if key:
        return key
    env_file = PROJECT_ROOT / "frontend" / ".env.cloud"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.startswith("VITE_FIREBASE_API_KEY="):
                value = line.split("=", 1)[1].strip()
                if value and "<" not in value:
                    return value
    return None


def identity_base(target: str) -> str:
    if target == "emulator":
        host, _ = emulator_hosts(get_settings())
        return f"http://{host}/identitytoolkit.googleapis.com/v1"
    return "https://identitytoolkit.googleapis.com/v1"


def firestore_rest_base(target: str, settings) -> str:
    db = settings.firestore_database_id
    if target == "emulator":
        _, host = emulator_hosts(settings)
        return f"http://{host}/v1/projects/{settings.firebase_project_id}/databases/{db}/documents"
    return f"https://firestore.googleapis.com/v1/projects/{settings.firebase_project_id}/databases/{db}/documents"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-cloud-test-user", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    target = firebase_target(settings)
    print(f"Env file: {os.environ.get('AGENTSHIELD_ENV_FILE', '.env')} | target: {target} | "
          f"project: {settings.firebase_project_id or '(not set)'} | database: {settings.firestore_database_id}")

    # 1. Configuration
    report = validate_firebase_configuration(settings)
    if not report.ok:
        for error in report.errors:
            record("Configuration", "BLOCKED", error)
        return finish()
    record("Configuration", "PASS", f"target={target}" + (f"; {len(report.warnings)} warning(s)" if report.warnings else ""))
    if target == "none":
        record("Firebase", "SKIPPED", "FIREBASE_TARGET=none")
        return finish()

    cloud = target == "cloud"
    write_auth = not cloud or args.allow_cloud_test_user

    # 2. Firebase Admin initialization
    try:
        from firebase_admin import auth

        from backend.app.core.firebase import get_firebase_app, verify_firebase_id_token

        app = get_firebase_app()
        record("Firebase Admin initialization", "PASS", f"app project={app.project_id or settings.firebase_project_id}")
    except Exception as exc:
        record("Firebase Admin initialization", "FAIL", type(exc).__name__ + (f" ({exc.__cause__.__class__.__name__})" if exc.__cause__ else ""))
        return finish()

    # 3. Authentication connection
    uid = f"agentshield-synthetic-{uuid4().hex[:10]}"
    email = f"{uid}@agentshield-synthetic.test"
    password = f"Synthetic-{uuid4().hex}"
    created_user = False
    try:
        if write_auth:
            auth.create_user(uid=uid, email=email, password=password, email_verified=True, app=app)
            created_user = True
            auth.set_custom_user_claims(uid, {"role": "REVIEWER"}, app=app)
            record("Authentication connection", "PASS", f"synthetic user created: {email}")
        else:
            try:
                auth.get_user_by_email(email, app=app)
                record("Authentication connection", "PASS", "user lookup succeeded")
            except auth.UserNotFoundError:
                record("Authentication connection", "PASS", "read-only lookup reached Firebase Auth (synthetic address not found, as expected)")
    except Exception as exc:
        record("Authentication connection", "FAIL", type(exc).__name__)

    http = httpx.Client(timeout=20)
    id_token = None
    try:
        # 4. ID token verification
        key = web_api_key(target)
        if not created_user:
            record("ID token verification", "SKIPPED", "needs the synthetic test user (cloud: --allow-cloud-test-user)")
        elif not key:
            record("ID token verification", "BLOCKED", "web API key missing (VITE_FIREBASE_API_KEY in frontend/.env.cloud)")
        else:
            res = http.post(f"{identity_base(target)}/accounts:signInWithPassword?key={key}",
                            json={"email": email, "password": password, "returnSecureToken": True})
            if res.status_code != 200:
                record("ID token verification", "FAIL", f"sign-in HTTP {res.status_code}")
            else:
                id_token = res.json()["idToken"]
                decoded = verify_firebase_id_token(id_token)
                ok = decoded.get("aud") == settings.firebase_project_id and decoded.get("email_verified") is True and decoded.get("role") == "REVIEWER"
                record("ID token verification", "PASS" if ok else "FAIL",
                       f"aud matches project, email_verified={decoded.get('email_verified')}, role={decoded.get('role')}")

                from fastapi.testclient import TestClient

                from backend.app.main import app as api_app

                with TestClient(api_app) as client:
                    api = client.get("/api/v1/policies/current", headers={"Authorization": f"Bearer {id_token}"})
                record("Backend API with verified token", "PASS" if api.status_code == 200 else "FAIL", f"GET /api/v1/policies/current -> {api.status_code}")

        # 5. Firestore connection
        from backend.app.core.firestore import get_firestore_client

        db = get_firestore_client()
        probe = db.collection("system_metadata").document("audit_chain_v2").get()
        record("Firestore connection", "PASS", f"read system_metadata/audit_chain_v2 (exists={probe.exists})")

        # 6. User document access (Security Rules, as the synthetic user)
        if created_user and id_token:
            user_ref = db.collection("users").document(uid)
            user_ref.create({"uid": uid, "email": email, "synthetic": True, "created_at": datetime.now(UTC).isoformat()})
            base = firestore_rest_base(target, settings)
            own = http.get(f"{base}/users/{uid}", headers={"Authorization": f"Bearer {id_token}"})
            other = http.get(f"{base}/users/someone-else-{uuid4().hex[:6]}", headers={"Authorization": f"Bearer {id_token}"})
            write = http.patch(f"{base}/users/{uid}?updateMask.fieldPaths=role",
                               headers={"Authorization": f"Bearer {id_token}"},
                               json={"fields": {"role": {"stringValue": "ADMIN"}}})
            ok = own.status_code == 200 and other.status_code == 403 and write.status_code == 403
            record("User document access", "PASS" if ok else "FAIL",
                   f"own doc {own.status_code}, other user's doc {other.status_code}, self-write {write.status_code} (expected 200/403/403)")
            user_ref.delete()
        else:
            record("User document access", "SKIPPED", "needs the synthetic test user")

        # 7. Security event (audit) repository
        from backend.app.models.audit_event import AuditEvent
        from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision
        from backend.app.services.audit_integrity import verify_audit_log
        from backend.app.storage.firestore_audit_repository import FirestoreAuditRepository

        audit = FirestoreAuditRepository(db)
        if cloud:
            items, total, _ = audit.list_events_page(limit=1)
            head = audit.chain_head()
            record("Security event repository (read-only)", "PASS",
                   f"listed {len(items)} of {total} events; v2 chain head sequence={head.get('sequence') if head else 'none'}")
        else:
            event = audit.create(AuditEvent(
                event_id=f"evt-synthetic-{uuid4().hex[:10]}", timestamp=datetime.now(UTC), tool_name="connection_check",
                decision=SecurityDecision.ALLOW, policy_id="connection-check", reason_codes=["SYNTHETIC_TEST"],
                destination_class=DestinationClass.APPROVED, execution_status=ExecutionStatus.NOT_EXECUTED,
                actor_uid=uid,
            ))
            fetched = audit.get_by_id(event.event_id)
            chain = verify_audit_log(audit.export_chain_records(), audit.chain_head())["verified"]
            record("Security event repository", "PASS" if fetched and chain["valid"] else "FAIL",
                   f"appended sequence {event.sequence}, read back, chain valid={chain['valid']} ({chain['count']} v2 records)")

        # 8. Approval repository
        from backend.app.models.approval import Approval
        from backend.app.models.enums import ApprovalStatus
        from backend.app.storage.approval_repository import ApprovalConflictError
        from backend.app.storage.firestore_approval_repository import FirestoreApprovalRepository

        approvals = FirestoreApprovalRepository(db, audit_repo=audit)
        if cloud:
            items, total, _ = approvals.list_approvals_page(limit=1)
            record("Approval repository (read-only)", "PASS", f"listed {len(items)} of {total} approvals")
        else:
            approval = approvals.create(Approval(
                approval_id=f"apr-synthetic-{uuid4().hex[:10]}", event_id=event.event_id, tool_name="connection_check",
                requested_action="Synthetic connection check", destination_class=DestinationClass.APPROVED,
                status=ApprovalStatus.PENDING, created_at=datetime.now(UTC),
            ))
            decided = approvals.update_decision(approval.approval_id, ApprovalStatus.APPROVED, reviewer=uid)
            try:
                approvals.update_decision(approval.approval_id, ApprovalStatus.REJECTED, reviewer=uid)
                conflict = False
            except ApprovalConflictError:
                conflict = True
            record("Approval repository", "PASS" if decided.status == ApprovalStatus.APPROVED and conflict else "FAIL",
                   "created PENDING, decided APPROVED in a transaction, second decision rejected (409)")
    except Exception as exc:
        record("Unexpected error", "FAIL", f"{type(exc).__name__}: {str(exc)[:160]}")
        traceback.print_exc(limit=2)
    finally:
        if created_user:
            try:
                auth.delete_user(uid, app=app)
                print(f"Cleanup: synthetic user {email} deleted")
            except Exception as exc:
                print(f"Cleanup FAILED for synthetic user {email}: {type(exc).__name__}")
    return finish()


def finish() -> int:
    failed = [r for r in RESULTS if r[1] in ("FAIL", "BLOCKED")]
    print(f"\nSummary: {sum(r[1] == 'PASS' for r in RESULTS)} PASS, "
          f"{sum(r[1] == 'SKIPPED' for r in RESULTS)} SKIPPED, {len(failed)} FAIL/BLOCKED")
    return 1 if failed else 0


if __name__ == "__main__":
    start = time.time()
    code = main()
    print(f"({time.time() - start:.1f}s)")
    raise SystemExit(code)
