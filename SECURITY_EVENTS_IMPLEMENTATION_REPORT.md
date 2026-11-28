# AgentShield `security_events` Collection Implementation Report

Date: 2026-11-28 · Status: **Implemented and Verified Locally**

## 1. Overview

Implemented and configured the Cloud Firestore `security_events` collection for AgentShield using the existing Firebase project configuration without creating a new Firebase project or overwriting existing records.

All `security_events` documents are written exclusively by the FastAPI backend using the Firebase Admin SDK (`FirestoreSecurityEventRepository`), keyed by `event_id` (`security_events/{event_id}`) with atomic `transaction.create(...)` writes and `firestore.SERVER_TIMESTAMP`.

---

## 2. Firestore `security_events` Schema

- **Collection:** `security_events`
- **Document ID:** `event_id` (matches `EvaluationResult.event_id`, e.g., `evt-<12 hex>`, or a validated idempotency key)
- **Allowed Decisions:** `ALLOW`, `BLOCK`, `REDACT`, `REQUIRE_APPROVAL`
- **Allowed Risk Levels:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

| # | Field | Type | Constraints / Behavior |
|---|---|---|---|
| 1 | `event_id` | String | Non-empty, max 128 chars, no `/` or whitespace; matches document ID |
| 2 | `user_id` | String | Authenticated Firebase UID (`user.uid`), non-empty, max 128 chars |
| 3 | `agent_id` | String | Agent identifier from tool context or `"default-agent"`, max 128 chars |
| 4 | `tool_name` | String | Non-empty tool identifier, max 200 chars |
| 5 | `decision` | String | `ALLOW`, `BLOCK`, `REDACT`, or `REQUIRE_APPROVAL` |
| 6 | `risk_level` | String | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| 7 | `reason` | String | Non-empty policy explanation/reason, max 1000 chars |
| 8 | `policy_id` | String | Non-empty matched policy identifier, max 200 chars |
| 9 | `correlation_id` | String | Request `X-Correlation-ID` or `tool_call.request_id` / generated ID |
| 10 | `created_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) set at creation |
| 11 | `metadata` | Map | Validated privacy-safe metadata (no passwords, tokens, private keys, or raw arguments) |

---

## 3. Files Changed

- [backend/app/models/enums.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/enums.py) — Added `RiskLevel` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- [backend/app/models/security_event.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/security_event.py) — Created `SecurityEvent`, `SecurityEventCreateRequest`, `SecurityEventListResponse`, `derive_risk_level`, `build_security_event_input`, and `validate_security_metadata`.
- [backend/app/storage/firestore_security_event_repository.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/firestore_security_event_repository.py) — Created `FirestoreSecurityEventRepository` with transactional non-overwriting `create_event` (supporting `idempotent=True/False`), `get_by_id`, and `list_events_page` (filtering by `user_id`, `decision`, `start_date`/`end_date`, and cursor pagination).
- [backend/app/storage/__init__.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/__init__.py) — Exported `FirestoreSecurityEventRepository` and security event domain exceptions.
- [backend/app/api/security_events.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/security_events.py) — Added `POST /api/v1/security-events`, `GET /api/v1/security-events`, and `GET /api/v1/security-events/{event_id}`.
- [backend/app/api/evaluation.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/evaluation.py) — Updated `POST /api/v1/evaluate` to persist evaluation results to `security_events` when Firestore mode is active.
- [backend/app/main.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/main.py) — Registered `security_events_router`.
- [firestore.indexes.json](file:///Users/sayantanisinha/Desktop/agent%20shield/firestore.indexes.json) — Added composite indexes on `security_events` for `(user_id ASC, created_at DESC)`, `(decision ASC, created_at DESC)`, and `(user_id ASC, decision ASC, created_at DESC)`.
- [backend/tests/test_security_events.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/test_security_events.py) — Added unit and API tests for schema/metadata validation, `ALLOW`/`BLOCK`/`REDACT`/`REQUIRE_APPROVAL`, invalid decisions, idempotency, authorization, filtering, and cursor pagination.
- [backend/tests/emulator/test_emulator_security_events.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_security_events.py) — Added Auth + Firestore emulator end-to-end tests.
- [backend/tests/emulator/test_emulator_firestore_rules.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_firestore_rules.py) — Added `test_security_events_collection_rules_deny_all_client_writes`.

---

## 4. Security Controls Implemented

- **Backend-Only Creation:** `firestore.rules` enforces `allow write: if false;` on `match /security_events/{eventId}` so browser/client SDKs cannot create, update, or delete events (verified against the emulator for `VIEWER`, `ADMIN`, and unauthenticated callers).
- **Authenticated User Association:** `user_id` is always set from the verified Firebase ID token (`user.uid`), never from client request bodies.
- **Metadata Sanitization & Secret Rejection:** `validate_security_metadata` blocks nested depth > 5, > 50 keys, > 16 KB payloads, forbidden credential keys (`password`, `access_token`, `refresh_token`, `id_token`, `api_key`, `private_key`, `secret`, `arguments`, etc.), and raw secret patterns (PEM headers, Bearer tokens, API key prefixes). Evaluation recording stores only privacy-safe metadata (destination class, reason codes, data labels, risk signal names, payload fingerprint).
- **Idempotency & No Overwrites:** `create_event` uses `transaction.create(...)` on `security_events/{event_id}`, raising `SecurityEventDuplicateError` (HTTP 409) for duplicate non-idempotent writes, returning the existing record (HTTP 200) on matching `X-Idempotency-Key` replays, and raising `SecurityEventConflictError` (HTTP 409) on conflicting payloads.
- **Viewer Isolation:** `VIEWER` callers can only query and read their own `security_events`; attempting to filter or fetch another user's events returns `403 Forbidden`.

---

## 5. Tests Executed

| Suite | Command | Result |
|---|---|---|
| Backend & SDK unit/API tests | `.venv/bin/python -m pytest -q` | **321 passed** |
| Firebase Emulator Suite (Auth + Firestore + `firestore.rules`) | `npx -y firebase-tools emulators:exec --only auth,firestore --project demo-agentshield "unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_CLOUD_PROJECT_CONFIRM && AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q"` | **33 passed** |
| Frontend unit tests | `cd frontend && npm test` | **24 passed**, 1 skipped (`auth.emulator.test.ts` requires running emulator) |

---

## 6. Remaining Issues & Notes

1. **Firestore Composite Indexes:** The emulator does not enforce composite indexes; `firestore.indexes.json` must be deployed to the live Firebase project (`agentsheild-febd5`) before running filtered queries (`user_id` / `decision` + `created_at DESC`) in production.
2. **Backend Application Wiring for `GET /api/v1/events` vs `security_events`:** Existing dashboard pages still query `/api/v1/events` (`audit_events` hash-chained log); `security_events` provides the dedicated query/ingestion collection without altering existing `audit_events` integrity guarantees.
3. **Demo Endpoint Persistence:** `POST /api/v1/demo/run/{scenario}` invokes `AgentShield` / `AuditLogger` directly and does not call `/api/v1/evaluate`; demo runs write to `audit_events` rather than `security_events`.
