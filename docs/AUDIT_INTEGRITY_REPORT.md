# Audit Integrity Report (Phase 13.2, Priority 3)

This report replaces the Phase 12 report, which is kept verbatim in the appendix.

## Summary

| Finding | SQLite | Firestore |
|---|---|---|
| 3.1 Records mutated after hashing | **PASS** | **PASS** (application path), see limits |
| 3.2 UPDATE/DELETE not prevented | **PASS** (DB triggers) | **PARTIAL**: clients denied by rules; privileged Admin SDK writes detectable, not preventable |
| 3.3 Sequence numbers not unique | **PASS** (unique index) | **PASS** (sequence-ledger documents created with `create`) |
| 3.4 Racy sequence allocation / chain forks | **PASS** | **PASS** |
| 3.5 Legacy migration | **PASS** | **PASS** |

## Finding 3.1: Status updates broke the chain. **PASS**

**Original vulnerability.** `update_execution_status()` ran `UPDATE audit_events SET execution_status` after the hash was computed. Confirmed: one status update made `verify_chain` report `Modified event at sequence 1`.

**Root cause.** Audit records were treated as mutable rows.

**Fix implemented**
- A status change is now an **appended** `EXECUTION_STATUS` record (with `related_event_id` pointing at the original), in the same hash chain. The original record is never touched.
- Reads expose a derived, unhashed `effective_execution_status`. The dashboard shows it, falling back to `execution_status`.
- Approval decisions append an `APPROVAL_DECISION` record (see the Firestore approval report).

**Files changed:**
- `backend/app/models/audit_event.py`: adds `chain_version`, `event_type`, `related_event_id`, `effective_execution_status`
- `backend/app/storage/audit_repository.py`
- `backend/app/storage/firestore_audit_repository.py`
- `backend/app/services/audit_logger.py`
- `sdk/agentshield/shield.py`
- `frontend/src/App.jsx`

**Tests executed** (`backend/tests/test_audit_chain_v2.py`): the status change appends a record and leaves the original row byte-identical; the effective status is shown; the chain stays valid. Firestore: `test_status_change_appends_record` (emulator). All pass.

## Finding 3.2: UPDATE and DELETE were possible. SQLite **PASS**; Firestore **PARTIAL**

**Fix implemented**
- **SQLite:**
  - `BEFORE UPDATE` and `BEFORE DELETE` triggers on `audit_events` raise `audit_events is append-only`;
  - the same protection applies to `audit_chain_migrations`;
  - no code path updates or deletes audit rows.
- **Firestore:**
  - events are written with `transaction.create()` (fails if the document exists), never `set()`;
  - rules deny every client write to `audit_events`, `audit_transitions`, `audit_sequence_v2`, `system_metadata` and `audit_event_status`;
  - the repository exposes no update or delete operation.

**Tests executed**
- SQLite: `UPDATE` and `DELETE` rejected by the database.
- Emulator:
  - an overwrite of an existing event is rejected (`AlreadyExists`);
  - client PATCH and DELETE on all audit collections return 403 (`test_emulator_firestore_rules.py`, 12 cases).

All pass.

**Why Firestore is PARTIAL.** The Firebase Admin SDK, or anyone with service-account or console access, bypasses Security Rules and can modify or delete documents. Firestore has no server-side trigger that can block that. Such changes are **detected**, not prevented:
- editing a field → `Modified event at sequence 3`;
- deleting a middle record → `Missing or reordered sequence`;
- deleting the newest record → `Chain head mismatch`.

Each case was tested on the emulator.

## Finding 3.3: No database-level unique sequence. **PASS**

**Original vulnerability.** No unique constraint existed. A concurrent-write probe produced 161 rows with only 65 distinct sequence numbers (96 on a later run).

**Fix implemented**
- SQLite: partial unique index `ux_audit_events_v2_sequence ON audit_events(sequence) WHERE chain_version = 2`.
- Firestore: each append also creates `audit_sequence_v2/{sequence:012d}` with `create()`, so a second record for the same sequence fails the whole transaction.
- Sequence and previous hash are always assigned by the repository; values supplied by the caller are ignored.

**Tests executed:**
- direct duplicate INSERT rejected (`UNIQUE`);
- forged sequence and previous hash ignored;
- the verifier detects duplicate and missing sequences;
- emulator: forged ledger document rejected; the ledger holds exactly N unique documents after concurrency.

All pass.

## Finding 3.4: Sequence allocation was not transaction-safe. **PASS**

**Fix implemented**
- **SQLite:**
  - `Database.write_transaction()` holds a process lock and runs `BEGIN IMMEDIATE`, taking the database write lock before reading the head; this also serializes separate processes;
  - an `audit_chain_state` row records the head, and appending refuses to proceed (`AuditChainError`) if the state and records disagree.
- **Firestore:**
  - each append is one transaction: read `system_metadata/audit_chain_v2`, then create the event, create the ledger document and set the head;
  - a per-process lock serializes appends within an instance, because emulator testing showed eight parallel transactions on the single head document hit `Transaction lock timeout` aborts; only cross-instance appends contend in Firestore.

**Tests executed**

| Test | Result |
|---|---|
| SQLite: 200 appends, 16 threads, one `Database` | sequences 1..200, chain valid |
| SQLite: 120 appends, 4 independent `Database` objects (separate connections and locks, like separate workers) | 1..120, chain valid |
| SQLite: mixed concurrent decisions and status changes | chain valid |
| Re-run of the original probe (8 threads × 20) | 162 rows, 162 distinct sequences, chain valid |
| Firestore emulator: 40 appends, 8 threads | 1..40, 40 ledger documents, chain valid |
| Firestore emulator: **3 separate OS processes** × 10 appends | 30 records, chain valid |
| SQLite: delete the newest record → further appends refused | `AuditChainError` |

## Finding 3.5: Migration strategy. **PASS**

**Strategy.** No historical record is modified, re-hashed or deleted.

1. **Schema (additive only).** New nullable columns `chain_version`, `event_type` and `related_event_id`. Legacy rows keep `chain_version = NULL` and every original value, including `event_id`, `timestamp`, `sequence` and hashes.
2. **One-time migration record.** The first time the v2 backend opens a database, it inserts a row into `audit_chain_migrations` recording:
   - the legacy event count;
   - the unsequenced count;
   - the maximum legacy sequence;
   - the legacy head hash;
   - whether the legacy chain was internally consistent (and its error);
   - an explicit note that legacy hashes do not prove historical integrity.

   The table itself is append-only.
3. **Separate chains.** Verified v2 records start a new chain at `GENESIS-V2`, with their own unique sequence space and an explicit hash field list that includes `chain_version`, `event_type` and `related_event_id`.
4. **Firestore.** Legacy documents in `audit_events` remain untouched. The old head document `system_metadata/audit_state` is not reused; the v2 head is `system_metadata/audit_chain_v2`.
5. **Verification.** `verify_audit_log()` and `scripts/verify_audit_integrity.py` (read-only, `mode=ro`) report:
   - `legacy`: count, `internally_consistent`, `proves_historical_integrity: false`;
   - `verified`: count, valid, error, checked against the recorded head.

**Tests executed:**
- a legacy database is upgraded and every legacy column value is unchanged;
- the migration row is correct;
- the first v2 record is `(chain_version 2, sequence 1, GENESIS-V2)`;
- re-opening records no second migration;
- a legacy database with a duplicate sequence is *reported* inconsistent and not rewritten;
- Firestore legacy documents are reported separately and left untouched.

All pass.

**Local database state (disclosure).** During this session the existing test suite wrote to the real `data/agentshield.db`. Several pre-existing SDK and demo tests construct `AgentShield()` with its default audit logger; this behavior predates Phase 13.2.

As a result, the file was migrated at `2026-11-28T10:24:44Z`. It holds:
- 1,523 legacy rows: 370 sequenced (internally consistent) and 1,153 unsequenced;
- 168 v2 records, which are test data.

No legacy row was altered. The test runner is now isolated through a root `conftest.py` that points the default database at a temporary file; this was verified with a row count before and after a full run (1,691 both times). The 168 test records cannot be removed without breaking the append-only rule. If they are unwanted, restore an earlier copy from `data/backups/` (dated 2026-11-24). That decision is yours.

## Remaining limitations
- A hash chain does not stop an attacker who can rewrite **both** the records and the head state. That needs externally anchored signed checkpoints. The signing helpers exist, but checkpoint publication and scheduling are still not implemented.
- Firestore throughput: one global chain means one hot head document, so append throughput is bounded by Firestore's per-document write rate (roughly one sustained write per second is the documented guideline; bursts are higher). This may need sharded chains at scale.
- Firestore verification (`export_chain_records`) reads all audit documents. It is an offline or admin operation and is not used by request handlers.

---

## Appendix: Phase 12 report (historical, unchanged)

> # Audit Integrity Report
>
> Status: PARTIAL
>
> Live SQLite verification passed for 131 integrity-enabled events. The verifier normalizes structured fields and confirms sequence order, previous hashes, and current hashes.
>
> Implemented:
>
> - Sequence fields in SQLite audit events.
> - Previous/current SHA-256 hash fields.
> - Canonical JSON hash helper.
> - Chain verification command.
> - Ed25519/RSA signing helper support.
>
> Not yet implemented or executed:
>
> - External public verification-key publication.
> - Live checkpoint creation.
> - Periodic checkpoint scheduling.
> - Deleted and inserted Firestore document verification against external checkpoints.
> - Signing-key rotation workflow.
