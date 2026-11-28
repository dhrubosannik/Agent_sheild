# Phase 13.2: Critical Security Remediation Report

Date: 2026-11-28 · Base commit: `9791375` · **Not deployed. Not committed.** Awaiting approval.

Detailed reports:
- [EMAIL_VERIFICATION_FIX_REPORT.md](EMAIL_VERIFICATION_FIX_REPORT.md)
- [DESTINATION_SECURITY_REPORT.md](DESTINATION_SECURITY_REPORT.md)
- [AUDIT_INTEGRITY_REPORT.md](AUDIT_INTEGRITY_REPORT.md)
- [FIRESTORE_APPROVAL_SECURITY_REPORT.md](FIRESTORE_APPROVAL_SECURITY_REPORT.md)
- [REMAINING_RISKS.md](REMAINING_RISKS.md)

The architecture is unchanged: FastAPI, Firebase Authentication, Cloud Firestore, React/Vite, Render and Vercel. No new services were introduced.

## Results

| # | Finding | Status |
|---|---|---|
| 1.1 | Stale ID token after email verification | **PASS** |
| 1.2 | User marked verified without confirmation (`emailVerified: true` fallback) | **PASS** |
| 1.3 | Misleading "verification email sent" message | **PASS** |
| 1.4 | *New:* Firebase Admin init broken by `9791375` (`os` shadowing → every token rejected) | **PASS** |
| 2.1 | Internal, metadata, private and IPv6-local destinations allowed by default | **PASS** |
| 2.2 | Destinations detected only by argument name (`bcc`, `webhook_url` bypass) | **PASS** |
| 2.3 | DNS rebinding / connection-time validation | **PARTIAL** (opt-in guarded client) |
| 3.1 | Status updates mutated hashed records | **PASS** |
| 3.2 | UPDATE/DELETE on audit records | SQLite **PASS** · Firestore **PARTIAL** (privileged writes detected, not prevented) |
| 3.3 | No unique sequence constraint | **PASS** |
| 3.4 | Racy sequence allocation / chain forks | **PASS** |
| 3.5 | Legacy migration strategy | **PASS** |
| 4.1 | Browser writes to approval documents | **PASS** |
| 4.2 | Reviewer identity taken from the request body | **PASS** |
| 4.3 | Non-transactional / duplicate / conflicting decisions | **PASS** |
| 5.1 | In-memory per-IP rate limiting | **PASS** (Firestore shared store) · Render proxy hop count **NOT TESTED** |
| 5.2 | Development mode granted every request ADMIN | **PASS** |
| 5.3 | Firestore indexes missing | **PARTIAL** (declared from queries; not enforceable on emulator; not deployed) |
| 5.4 | Unbounded full-collection reads | **PASS** |
| 5.5 | Security headers vs Swagger `/docs` | **PARTIAL** (headers verified; browser rendering **NOT TESTED**) |
| 5.6 | SDK boundary limitations | **PASS** (documented and asserted by tests; the limitation itself remains) |
| — | Test suite wrote to the real `data/agentshield.db` (pre-existing) | **PASS** (isolated; see disclosure) |

Findings 1–4 are detailed in their own reports. Findings 5.x and the test-isolation issue are below.

## Priority 5 findings

### 5.1 Rate limiting: **PASS** (Render proxy hop count NOT TESTED)

- **Original vulnerability.** A per-IP `dict` in memory: unbounded, per instance, and keyed on the socket peer. Behind Render's proxy, all users likely shared one key. Requests sent chunked without `Content-Length` also bypassed the body-size limit.
- **Root cause.** A `BaseHTTPMiddleware` with local state that trusted only `Content-Length`.
- **Files changed:**
  - `backend/app/core/rate_limit.py` (new)
  - `backend/app/core/security_middleware.py` (rewritten as pure ASGI)
  - `backend/app/core/config.py`
  - `backend/app/main.py`
  - `render.yaml`
  - `.env.example`
- **Fix implemented:**
  - `FirestoreRateLimiter`: transactional fixed-window counters in `rate_limits`, shared by all instances, with an `expires_at` TTL field and striped per-process locks.
  - `InMemoryRateLimiter`: memory-bounded. Production refuses to start with it unless `RATE_LIMIT_SINGLE_INSTANCE=true`.
  - Client address taken from `X-Forwarded-For` only for `TRUSTED_PROXY_COUNT` hops; spoofed entries to the left are ignored.
  - The body limit is enforced on bytes actually received.
  - `Retry-After` header on 429.
  - Fails closed (503) if the store is unavailable.
  - `render.yaml` sets `RATE_LIMIT_BACKEND=firestore` and `TRUSTED_PROXY_COUNT=1`.
- **Tests executed:** `backend/tests/test_security_middleware.py` (8) and `backend/tests/emulator/test_emulator_rate_limit.py` (3):
  - budget shared across limiter instances;
  - 20 concurrent hits on 3 instances allow exactly 7;
  - window reset;
  - 429 per client;
  - chunked 413;
  - `X-Forwarded-For` trust;
  - production configuration guard.

  All pass.
- **Remaining limitations:** see REMAINING_RISKS 5. The Render hop count was not verified on Render.

### 5.2 Development ADMIN bypass: **PASS**

- **Original vulnerability.** With `FIREBASE_AUTH_REQUIRED=false` outside production, every request, from any host and with no credentials, was `local-demo` with ADMIN.
- **Fix implemented** (`backend/app/core/auth.py`):
  - there is no implicit identity;
  - development requests must name an entry of `DEV_AUTH_IDENTITIES` (`uid:ROLE`) in `X-AgentShield-Dev-User`, from a loopback client, and get uid `dev:<name>` with that role;
  - Firebase bearer tokens are verified even in development;
  - production refuses to start if dev identities are set, and ignores the header.
  - `scripts/start_agentshield.sh` exports explicit local identities, so the one-command demo still works. `frontend/.env.example` gains `VITE_DEV_IDENTITY`.
  - `.gitignore` now also ignores `.env.*` (previously `.env.local` would have been committed).
- **Tests executed:** 7 tests in `test_firebase_auth.py`:
  - no identities → 401;
  - missing header → 401;
  - explicit roles;
  - unknown identity → 401;
  - remote client → 401;
  - production ignores dev identities and refuses to start with them;
  - role enforcement.

  All API tests now run as explicit identities. A local stack smoke test gave: dashboard 200, events as `local-admin` 200, anonymous 401.

### 5.3 Firestore indexes: **PARTIAL**

- **Original vulnerability.** `firestore.indexes.json` was empty while the code ran filtered and ordered queries.
- **Fix implemented.** Composite indexes for every query the code runs:
  - `audit_events`: `decision + timestamp desc`, `tool_name + timestamp desc`, and `decision + tool_name + timestamp desc`;
  - `approvals`: `status + created_at desc`.

  Single-field queries (`approvals.event_id`) use automatic indexes. A TTL override for `rate_limits.expires_at` is added, and `firebase.json` now references the file.
- **Why PARTIAL.** The emulator does not enforce composite indexes, and deployment was out of scope. Validation against a real project is required before launch.

### 5.4 Pagination: **PASS**

- **Original vulnerability.** Firestore `list_events` and `list_approvals` streamed the whole collection to count it and then sliced it in memory.
- **Fix implemented:**
  - cursor (keyset) pagination: Firestore `start_after(snapshot)`, and SQLite on `(timestamp, event_id)`;
  - `limit` capped at 100 and `offset` at 1000;
  - `total` from a Firestore server-side `count()` aggregation;
  - the APIs return `next_cursor` and accept `cursor`; an invalid cursor returns 400.
- **Tests executed:** SQLite (`test_cursor_pagination_for_events_and_approvals`) and Firestore emulator (`test_cursor_pagination_in_firestore`): 7 items in pages of 3 give 3 pages, no duplicates, correct totals. All pass.

### 5.5 Security headers and `/docs`: **PARTIAL**

- **Original vulnerability.** The global `content-security-policy: default-src 'none'` blocked Swagger UI's jsDelivr assets and inline bootstrap script.
- **Fix implemented.** `/docs`, `/redoc` and the OAuth redirect get a CSP allowing jsDelivr, the inline bootstrap, and the FastAPI and ReDoc images. Every other response keeps `default-src 'none'; frame-ancestors 'none'`, plus `nosniff`, `DENY`, `no-referrer` and `no-store`.
- **Tests executed:** `/docs` 200 with the documentation CSP; the CSP allows every external asset host the page references; `/openapi.json` 200 with the strict CSP; `/redoc` gets the documentation CSP.
- **Why PARTIAL.** Rendering in a real browser was not tested.

### 5.6 SDK boundary: **PASS** (the limitation remains)

`sdk/tests/test_sdk_boundary.py` asserts that a cooperative call is blocked. It also asserts that each of these bypasses works: `__wrapped__`, policy mutation, evaluator monkeypatching, and execution continuing when audit persistence fails. The required architecture (a separate tool-execution service) is described in REMAINING_RISKS 1.

### Test isolation (pre-existing issue): **PASS**

Several existing tests wrote to the developer's real `data/agentshield.db`. A root `conftest.py` now points the default database at a temporary file. Verified: 1,691 rows before and after a full run.

**Disclosure.** Before the fix, runs in this session migrated that file and appended 168 v2 test records, plus legacy test rows from earlier runs. No legacy record was modified. Details are in AUDIT_INTEGRITY_REPORT.md.

## Test execution summary

| Suite | Command | Result |
|---|---|---|
| Backend + SDK (non-emulator) | `.venv/bin/python -m pytest -q` | **294 passed** (was 153) |
| Frontend unit | `cd frontend && npm test` | **13 passed**, 1 skipped (the emulator E2E) |
| Frontend production build | `npm --prefix frontend run build` | **built** |
| Emulator tier (fresh `firebase emulators:exec`, Java 21) | `./scripts/run_emulator_tests.sh` | exit 0 (breakdown below) |
| ↳ Firebase emulator pytest | `backend/tests/emulator` | **29 passed** |
| ↳ Email-verification E2E (real Firebase JS SDK + real backend) | `src/firebase/auth.emulator.test.ts` | **1 passed** |
| ↳ Older verification scripts | `test_firebase_emulator_suite.py`, `test_e2e_frontend_backend.py` | **26/26 and 18/18 PASS** |
| Destination security | in the backend suite | pass |
| Audit-chain concurrency and tampering | `test_audit_chain_v2.py` + emulator | pass |
| Firestore authorization (rules) | emulator | pass |
| Approval transactions | SQLite + emulator | pass |
| Rate limiting | middleware tests + emulator | pass |
| CLI demo | `examples/demo_agent.py --scenario all` (temporary database) | ALLOW / BLOCK / REDACT / 2 × REQUIRE_APPROVAL, same as before |
| Original review probe, re-run | — | metadata and localhost → BLOCK; `bcc` and `webhook_url` → BLOCK; status change keeps the chain valid; 162 concurrent rows with 162 unique sequences |

**Changes to existing tests (intended behavior changes):**
- `test_policy_evaluator.py`: an un-allowlisted INTERNAL destination now BLOCKs before redaction; redaction is shown with an APPROVED (allowlisted) destination.
- `test_api.py` and `test_firebase_auth.py`: explicit development identities; the reviewer is the authenticated uid.
- `scripts/test_firebase_emulator_suite.py` and `scripts/test_e2e_frontend_backend.py`: their test users now verify their email (required since `9791375`), and they use the v2 chain verifier.

**Tooling notes:**
- `firebase-tools` 15 requires Java 21; the runner uses `/opt/homebrew/opt/openjdk@21`.
- `vitest` was added as a frontend dev dependency.

## Behavior changes to review before approval
1. Internal destinations are blocked unless listed in `allowed_internal_destinations`. Unknown or ambiguous URLs are UNKNOWN, so approval is required by default.
2. Local development without Firebase needs `DEV_AUTH_IDENTITIES` and `VITE_DEV_IDENTITY`; `start_agentshield.sh` sets defaults.
3. The approval API ignores `reviewer` in the body.
4. Audit listings show only decision events and carry `effective_execution_status`. Responses include `next_cursor`.
5. Production startup fails if dev identities are set, or if the in-memory limiter is used without `RATE_LIMIT_SINGLE_INSTANCE=true`.
6. Firestore gains the collections `audit_transitions`, `audit_sequence_v2`, `audit_event_status` and `rate_limits`, and the document `system_metadata/audit_chain_v2`.

## Files changed

**Backend**
- Modified:
  - `api/approvals.py`, `api/events.py`
  - `core/auth.py`, `core/config.py`, `core/firebase.py`, `core/firestore.py`, `core/policy_models.py`, `core/security_middleware.py`
  - `main.py`
  - `models/audit_event.py`
  - `services/__init__.py`, `services/audit_integrity.py`, `services/audit_logger.py`, `services/destination_classifier.py`, `services/policy_evaluator.py`
  - `storage/approval_repository.py`, `storage/audit_repository.py`, `storage/database.py`, `storage/firestore_approval_repository.py`, `storage/firestore_audit_repository.py`
- New: `core/rate_limit.py`, `services/safe_network.py`

**Backend tests**
- Modified: `test_api.py`, `test_firebase_auth.py`, `test_policy_evaluator.py`
- New:
  - `test_destination_security.py`, `test_audit_chain_v2.py`, `test_approval_security.py`, `test_security_middleware.py`, `test_firebase_init_regression.py`
  - `emulator/` (6 files)

**SDK**
- Modified: `shield.py`
- New: `network.py`, `tests/test_sdk_boundary.py`

**Frontend**
- Modified: `App.jsx`, `api/client.js`, `components/AuthScreen.jsx`, `firebase/auth.ts`, `vite.config.js`, `package.json`, `package-lock.json`, `.env.example`
- New: 4 test files

**Configuration**
- `firestore.rules`, `firestore.indexes.json`, `firebase.json`, `render.yaml`, `.env.example`, `.gitignore`, `pytest.ini`
- `conftest.py` (new)

**Scripts**
- Modified: `start_agentshield.sh`, `verify_audit_integrity.py` (read-only), `test_firebase_emulator_suite.py`, `test_e2e_frontend_backend.py`
- New: `run_emulator_tests.sh`
- Regenerated results: `e2e_test_results.json`, `emulator_test_results.json`

**Reports:** the six Phase 13.2 reports above.
