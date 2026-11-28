# Firestore Approval Security Report (Phase 13.2, Priority 4)

## Finding 4.1: Browsers could write approval decisions. **PASS**

**Original vulnerability.** `firestore.rules` contained `allow update: if isAdmin() || isReviewer();` on `approvals`. A reviewer's browser could change any field directly: approve without an audit record, set an arbitrary reviewer, or move APPROVED back to PENDING. This bypassed the backend entirely.

**Fix implemented** (`firestore.rules`):
- `approvals`: `allow write: if false` (create, update and delete);
- reads require `request.auth.token.email_verified == true`, matching the backend;
- all audit, chain-state and rate-limit collections deny client writes;
- unknown collections are default-deny.

**Tests executed** (`backend/tests/emulator/test_emulator_firestore_rules.py`). These are real emulator REST calls with real user ID tokens, with `firestore.rules` loaded:
- PATCH, POST and DELETE on `approvals` as REVIEWER, ADMIN and VIEWER → 403, and the document stays PENDING;
- reads by verified users → 200;
- writes to 6 audit/state collections as ADMIN → 403;
- reads by unverified or anonymous users → 403.

14 tests, all pass. The older script `scripts/test_firebase_emulator_suite.py` (rules section) also passes.

## Finding 4.2: Decisions not bound to the authenticated identity. **PASS**

**Original vulnerability.** In local-demo mode the API stored the `reviewer` from the request body. The dashboard always sent `"demo-reviewer"`.

**Fix implemented** (`backend/app/api/approvals.py`):
- the route requires ADMIN or REVIEWER (`require_roles`);
- the reviewer is always the authenticated `user.uid`;
- a `reviewer` field in the body is accepted for compatibility and ignored.

The frontend no longer sends it. Because Admin SDK writes bypass Rules, these backend checks are mandatory.

**Tests executed**

| Case | SQLite (`test_approval_security.py`) | Firestore emulator (`test_emulator_approvals.py`) |
|---|---|---|
| No credentials → 401 | pass | pass |
| VIEWER → 403, approval still PENDING | pass | pass |
| Unverified REVIEWER → 403 | (dev identities are always verified) | pass |
| Spoofed `reviewer` in body ignored; uid recorded | pass | pass |
| Invalid target state (`PENDING`) → 422 | pass | covered by the shared model |

## Finding 4.3: Non-transactional, conflicting decisions. **PASS**

**Original vulnerability.**
- Firestore `update_decision` read, checked and updated without a transaction, so two reviewers could both "win".
- `reviewed_at` was stored without a time zone.
- No audit record was written for the decision.

**Fix implemented**
- **Firestore** (`firestore_approval_repository.py`): one transaction that:
  - re-reads the approval;
  - requires PENDING, otherwise raises `ApprovalConflictError` (409);
  - reads the audit chain head;
  - updates the approval (status, reviewer uid, UTC `reviewed_at`);
  - appends the `APPROVAL_DECISION` audit record (ledger document plus head).

  Either everything commits or nothing does. Approvals are created with `create()`, never overwritten.
- **SQLite** (`approval_repository.py`): inside `BEGIN IMMEDIATE`, a compare-and-set `UPDATE … WHERE approval_id = ? AND status = 'PENDING'`, then `rowcount == 1` is checked and the audit record appended in the same transaction.
- **Duplicate protection.** The audit record's `event_id` is deterministic (`{approval_id}~decision`). A second decision record for the same approval cannot be created even outside the state check.

**Tests executed**

| Case | SQLite | Firestore emulator |
|---|---|---|
| Duplicate decision → 409, first decision kept | pass | pass |
| Simultaneous decisions (12 threads SQLite; 8 threads, 4 reviewers, Firestore) | exactly 1 × 200, 11 × 409 | exactly 1 × 200, 7 × 409 |
| Exactly one APPROVAL_DECISION record, with the reviewer's uid | pass | pass |
| Audit chain valid afterwards | pass | pass |
| Older E2E script (`scripts/test_e2e_frontend_backend.py`): VIEWER 403, REVIEWER 200, re-review 409 | — | 18/18 pass |

## Remaining limitations
- **Approval does not execute the tool.** This is unchanged MVP scope: an APPROVED record is not wired back to the agent.
- **No separation of duties.** The same person who triggered an action can approve it if they hold REVIEWER or ADMIN. Not implemented.
- `log_event()` creates the decision event and the pending approval in two writes. A crash between them leaves an event without an approval record. This fails safe: nothing executes.
