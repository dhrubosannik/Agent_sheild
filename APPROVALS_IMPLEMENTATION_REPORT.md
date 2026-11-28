# AgentShield `approvals` Collection Implementation Report

Date: 2026-11-28 · Status: **Implemented and Verified Locally (Not Deployed)**

## 1. Overview

Upgraded and configured the Cloud Firestore `approvals` collection for AgentShield using the existing Firebase project configuration, preserving compatibility with existing approval records, audit chain verification, and frontend components while adding all required fields, status transitions (`EXPIRED`), optimistic version increments (`version`), server timestamps, separation-of-duties enforcement, and dedicated pending/approve/reject API endpoints.

---

## 2. Firestore `approvals` Schema

- **Collection:** `approvals`
- **Document ID:** `approval_id` (e.g., `apr-{event_id}`)
- **Allowed Statuses:** `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`

| # | Field | Type | Constraints / Behavior |
|---|---|---|---|
| 1 | `approval_id` | String | Unique approval ID; matches document ID |
| 2 | `user_id` | String | Authenticated requester UID (`"system"` fallback for legacy docs) |
| 3 | `agent_id` | String | Agent ID from tool context or `"default-agent"` |
| 4 | `tool_name` | String | Tool identifier requiring human review |
| 5 | `status` | String | `PENDING` (initial), `APPROVED`, `REJECTED`, or `EXPIRED` |
| 6 | `requested_action` | String | Description of proposed action |
| 7 | `risk_level` | String | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| 8 | `requested_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) set at creation |
| 9 | `reviewed_by` | String or Null | Reviewer UID set from verified backend auth on decision |
| 10 | `reviewed_at` | Timestamp or Null | Server timestamp (`firestore.SERVER_TIMESTAMP`) set on decision |
| 11 | `decision_reason` | String or Null | Optional reviewer explanation (`<= 1000` chars) |
| 12 | `correlation_id` | String | Request `X-Correlation-ID` or `request_id` / `event_id` |
| 13 | `version` | Integer | Starts at `1`; incremented atomically (`+1`) on valid transition |

Compatibility fields (`event_id`, `destination_class`, `created_at`, `reviewer`) are retained so existing dashboard views (`Approvals.jsx`), `APPROVAL_DECISION` audit records, and legacy migrated documents continue to deserialize cleanly without overwriting existing records.

---

## 3. Files Changed

- [backend/app/models/enums.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/enums.py) — Added `EXPIRED` to `ApprovalStatus`.
- [backend/app/models/approval.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/approval.py) — Updated `Approval` model with `user_id`, `agent_id`, `risk_level`, `requested_at`, `reviewed_by`, `decision_reason`, `correlation_id`, `version`, and normalized timestamp/reviewer syncing.
- [backend/app/core/config.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/core/config.py) — Added `require_approval_separation_of_duties: bool = False` configuration option.
- [backend/app/storage/database.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/database.py) — Added non-destructive SQLite `approvals` column migrations (`user_id`, `agent_id`, `risk_level`, `requested_at`, `reviewed_by`, `decision_reason`, `correlation_id`, `version`) for parity in local SQLite mode.
- [backend/app/storage/approval_repository.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/approval_repository.py) — Added `ApprovalAlreadyExistsError`, `ApprovalUnauthorizedError`, `EXPIRED` support, `version` optimistic increment (`WHERE status = 'PENDING' AND version = ?`), `decision_reason`, and separation-of-duties enforcement.
- [backend/app/storage/firestore_approval_repository.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/firestore_approval_repository.py) — Updated `FirestoreApprovalRepository` with all 13 fields, non-overwriting `create()` using `firestore.SERVER_TIMESTAMP`, `list_pending()`, cursor pagination, `approve()`, `reject()`, `expire()`, and transactional `update_decision()` that increments `version` and appends the `APPROVAL_DECISION` audit record atomically.
- [backend/app/storage/__init__.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/__init__.py) — Exported `ApprovalAlreadyExistsError` and `ApprovalUnauthorizedError`.
- [backend/app/services/audit_logger.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/services/audit_logger.py) — Populated `user_id`, `agent_id`, `risk_level`, `correlation_id`, and `version=1` when creating `Approval` on `REQUIRE_APPROVAL`, and forwarded `decision_reason` and `enforce_separation_of_duties` in `review_approval()`.
- [backend/app/api/evaluation.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/evaluation.py) — Passed `agent_id` and `correlation_id` into `audit_logger.log_event(...)`.
- [backend/app/api/approvals.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/approvals.py) — Added `GET /api/v1/approvals/pending`, `GET /api/v1/approvals/{approval_id}`, `POST /api/v1/approvals/{approval_id}/approve`, `POST /api/v1/approvals/{approval_id}/reject`, and `decision_reason` support on `POST /api/v1/approvals/{approval_id}/decision` (`ADMIN` and `REVIEWER` only for decisions; server-side reviewer identity).
- [firestore.indexes.json](file:///Users/sayantanisinha/Desktop/agent%20shield/firestore.indexes.json) — Added composite indexes for `approvals` (`(status ASC, requested_at DESC)` and `(user_id ASC, requested_at DESC)`).
- [backend/tests/test_approvals_firestore.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/test_approvals_firestore.py) — Added unit and API tests covering non-overwriting creation, transaction rollback when audit fails, `EXPIRED` transitions, separation of duties, `/pending`, `/approve`, `/reject`, duplicate rejection (`409`), unauthorized reviewer (`403`), and audit trail verification.
- [backend/tests/emulator/test_emulator_approvals.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_approvals.py) — Added emulator tests verifying Firestore server timestamps, `version` increments, `/pending`, `/approve`, `/reject`, duplicate conflict (`409`), unauthorized `VIEWER` (`403`), and valid v2 audit chain integrity.

---

## 4. Security Controls Implemented

- **Client Write Prohibition:** `firestore.rules` enforces `allow write: if false;` on `match /approvals/{approvalId}`, preventing browsers/client SDKs from creating, modifying, or deleting approval documents.
- **RBAC Enforcement:** Only authenticated, email-verified `ADMIN` and `REVIEWER` callers can invoke `/decision`, `/approve`, or `/reject`; `VIEWER` (`403`), unverified (`403`), and unauthenticated (`401`) requests are rejected.
- **Server-Assigned Reviewer Identity:** Client-supplied `reviewer` fields are ignored; `reviewed_by` and audit `actor_uid` are always taken from the verified backend `AuthenticatedUser.uid`.
- **Atomic Transactions & Rollback:** `update_decision()` runs in a single Firestore transaction with `audit.stage_append(...)`; if audit persistence fails, the entire transaction rolls back and the approval remains `PENDING` at `version=1`.
- **Separation of Duties:** Configurable via `REQUIRE_APPROVAL_SEPARATION_OF_DUTIES` (raises `403 Forbidden` if a requester attempts to approve/reject their own request when enabled).
- **Duplicate & Concurrent Decision Protection:** Non-`PENDING` transitions fail with `409 Conflict` (`ApprovalConflictError`), and simultaneous requests allow only one transition (`version: 1 -> 2`).

---

## 5. Tests Executed

| Suite | Command | Result |
|---|---|---|
| Backend & SDK unit/API tests | `.venv/bin/python -m pytest -q` | **323 passed** |
| Firebase Emulator Suite (Auth + Firestore + `firestore.rules`) | `npx -y firebase-tools emulators:exec --only auth,firestore --project demo-agentshield "unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_CLOUD_PROJECT_CONFIRM && AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q"` | **34 passed** |
| Frontend unit tests | `cd frontend && npm test` | **24 passed**, 1 skipped (`auth.emulator.test.ts` requires running emulator) |

---

## 6. Remaining Issues & Notes

1. **Not Deployed:** Changes to `firestore.indexes.json` and backend endpoints are verified locally and in the Firebase Emulator Suite only; nothing was deployed in this task (`Do not deploy.`).
2. **Automatic Expiration Worker:** The `EXPIRED` status, transition validation, and `FirestoreApprovalRepository.expire()` method are implemented, but no background scheduler/Cloud Function runs automatically to expire stale `PENDING` requests after a TTL; an external job or admin trigger must invoke `expire()` if automatic expiration is needed.
3. **Default Separation of Duties Setting:** `require_approval_separation_of_duties` defaults to `False` to preserve compatibility with existing policy (`default_policy.yaml`) and existing tests where an `ADMIN` reviews requests they triggered; set `REQUIRE_APPROVAL_SEPARATION_OF_DUTIES=true` in production environments where strict dual-control is required for `ADMIN` and `REVIEWER` requesters alike.
