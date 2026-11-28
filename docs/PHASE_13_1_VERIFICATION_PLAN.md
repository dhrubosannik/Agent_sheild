# PHASE 13.1 — FIREBASE LIVE INTEGRATION & MIGRATION VERIFICATION PLAN

**Project:** AgentShield  
**Phase:** 13.1  
**Date:** November 24, 2026  
**Status:** In Progress  

---

## 1. Executive Summary & Context

Phase 13 implemented the architectural transition of AgentShield from a local-only SQLite prototype to a cloud-ready architecture utilizing:
- **Backend Persistence & Logic:** FastAPI on Render with Google Cloud Firestore repositories.
- **Identity & Authentication:** Firebase Authentication (email/password, ID tokens, custom role claims).
- **Frontend Hosting & UI:** Vite + React on Vercel with official Firebase JS SDK.
- **Data Integrity:** SHA-256 hash chaining of audit events, cryptographic signed checkpoints (Ed25519/RSA), and SQLite-to-Firestore export utilities.

The Phase 13 local milestone verified 147 unit/integration tests and confirmed code compilation. However, **no live Firebase project integration, Firestore emulator validation, end-to-end cloud authentication, or external checkpoint publication was executed**. Furthermore, an unexplained disparity exists between exported SQLite records (1,258 audit events) and verified hash-chain records (131 events).

This plan establishes the exact test matrix, verification procedures, reconciliation strategy, and validation criteria for Phase 13.1 before any public deployment can be authorized.

---

## 2. Phase 13 Source Code & Architecture Inspection

An inspection of the Phase 13 implementation reveals the following subsystem details:

### 2.1 Firebase Initialization
- **Frontend (`frontend/src/firebase/firebase.ts`):** Evaluates `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, and `VITE_FIREBASE_APP_ID`. Exposes boolean `firebaseConfigured` and singleton `getFirebaseApp()`.
- **Backend (`backend/app/core/firebase.py`):** Configures Firebase Admin SDK via `firebase_admin.initialize_app()`. Supports service account credentials via `GOOGLE_APPLICATION_CREDENTIALS` or `ApplicationDefault()` in non-development environments, constrained by `settings.firebase_project_id`.

### 2.2 Authentication Implementation
- **Frontend Auth (`frontend/src/firebase/auth.ts`, `AuthScreen.jsx`):** Wraps Firebase SDK functions for email/password registration, login, signout, and password reset. Exposes `getCurrentIdToken()`.
- **Backend Auth Dependency (`backend/app/core/auth.py`):** Resolves user identity via `get_authenticated_user()`.
  - When `FIREBASE_AUTH_REQUIRED=false` in development, defaults to synthetic `local-demo` (UID: `local-demo`, role: `ADMIN`).
  - When `FIREBASE_AUTH_REQUIRED=true` (or in `production`), requires a valid `Authorization: Bearer <id_token>` header.

### 2.3 Token Verification
- **Token Verification Logic (`backend/app/core/firebase.py`):** Invokes official `firebase_admin.auth.verify_id_token(id_token, app=app)`.
- **Audience & Project Integrity:** Validates that `decoded.get("aud") == settings.firebase_project_id` to prevent cross-project token reuse.
- **Error Mapping:** Maps configuration faults to HTTP 503 and expired/invalid/malformed tokens to HTTP 401.

### 2.4 Role-Based Authorization
- **Role Model (`UserRole`):** Defines `ADMIN`, `REVIEWER`, `VIEWER`.
- **Claims Extraction:** Reads custom claim `role` (falling back to `VIEWER` if absent).
- **Route Enforcements (`require_roles`):**
  - Read Events (`GET /api/v1/events`): `ADMIN`, `REVIEWER`, `VIEWER`.
  - Read Approvals (`GET /api/v1/approvals`): `ADMIN`, `REVIEWER`, `VIEWER`.
  - Review Approvals (`POST /api/v1/approvals/{id}/decision`): `ADMIN`, `REVIEWER`.
  - Evaluation (`POST /api/v1/evaluate`): `ADMIN`, `REVIEWER`, `VIEWER`.
  - Demo Scenarios (`POST /api/v1/demo/run/{scenario}`): `ADMIN`, `REVIEWER`, `VIEWER`.
  - Role Administration (`POST /api/v1/admin/users/{uid}/role`): `ADMIN` only (self-demotion forbidden).

### 2.5 Firestore Repositories
- **Audit Repository (`backend/app/storage/firestore_audit_repository.py`):** Stores documents in collection `audit_events`. Uses Firestore atomic transaction on `system_metadata/audit_state` to obtain monotonically increasing sequence numbers and link `previous_event_hash` to `current_event_hash`.
- **Approval Repository (`backend/app/storage/firestore_approval_repository.py`):** Stores documents in collection `approvals`. Manages lifecycle states: `PENDING` -> `APPROVED` | `REJECTED`. Enforces conflict detection (HTTP 409) if an approval is already reviewed.

### 2.6 Audit-Chain Implementation
- **Canonical Serialization & Hash (`backend/app/services/audit_integrity.py`):** `canonical_json()` performs sorted-key JSON serialization without whitespace. `compute_event_hash()` calculates SHA-256 over normalized event fields concatenated with `previous_event_hash`.
- **Verification Engine (`verify_chain`):** Sequentially verifies uninterrupted sequence order, genesis hash (`GENESIS`), and exact SHA-256 match for each event payload.

### 2.7 Signed-Checkpoint Implementation
- **Cryptographic Helpers (`sign_checkpoint`, `verify_checkpoint_signature`):** Implements asymmetric signature creation and verification supporting both Ed25519 and RSA (PKCS#1 v1.5 with SHA-256).
- **Architectural Gap:** Functions exist as purely static Python helpers. There is **no persistent external storage, no scheduled checkpoint job, and no independent public verifier service**.

### 2.8 SQLite Migration Utilities
- **Export Script (`scripts/migrate_sqlite_to_firestore.py`):** Backs up `agentshield.db` and exports JSON data. Does not upload to Firestore.
- **Root-Cause Analysis of Disparity:** Inspection of `data/agentshield.db` reveals:
  - Total audit events: 1,315 (1,258 at Phase 13 kickoff).
  - Events with sequence and hashes: 162 (131 at Phase 13 kickoff).
  - Legacy events lacking sequence/hashes: 1,153.
  - Reason: Hash-chain columns were introduced during Phase 13 via schema migration (`ALTER TABLE ADD COLUMN sequence...`). Historical events created in Phases 1–12 predate the cryptographic hash-chain mechanism.

### 2.9 Firestore Security Rules (`firestore.rules`)
- Matches collections: `users`, `security_events`, `audit_events`, `audit_checkpoints`, `approvals`, `policies`, `system_metadata`.
- Default-deny rule: `match /{document=**} { allow read, write: if false; }`.
- Client writes strictly forbidden for `audit_events`, `security_events`, `audit_checkpoints`, and `system_metadata` (writes occur via server-side Admin SDK).
- `approvals` updates restricted to `ADMIN` or `REVIEWER`.

### 2.10 Render Configuration (`render.yaml`)
- Service: `agentshield-api` (Python uvicorn).
- Production settings: `ENVIRONMENT=production`, `DATABASE_MODE=firestore`, `FIREBASE_AUTH_REQUIRED=true`.
- Health check: `/health`.

### 2.11 Vercel Configuration (`vercel.json`)
- Build command: `npm --prefix frontend run build`.
- Single-page application route rewrites to `/index.html`.

---

## 3. Verification Plan & Test Strategy

### 3.1 Firebase Emulator Suite Testing
1. **Emulator Harness Setup:**
   - Launch Firebase Auth and Firestore emulators using `firebase-tools` or an in-process local emulator mock conforming to the Firebase Emulator Suite API (`FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST`).
2. **Authentication Flow Verification:**
   - User Registration (`createUserWithEmailAndPassword`).
   - User Login (`signInWithEmailAndPassword`) and ID token retrieval.
   - User Logout (`signOut`).
   - Password reset initiation (`sendPasswordResetEmail`).
   - ID Token verification by FastAPI backend.
   - Negative tests: Malformed token rejection (401), expired token rejection (401), missing header rejection (401).
   - Role Claim tests: ADMIN (access all), REVIEWER (approve/reject), VIEWER (read-only, 403 on decisions).
3. **Firestore Security Rules Verification:**
   - Test read/write permissions directly against Firestore emulator rules.
   - Verify unauthenticated client rejection.
   - Verify non-admin rejection on `/policies` write.
   - Verify client rejection on `/audit_events` direct creation.
   - Verify default-deny on arbitrary collections.

### 3.2 Live Firebase Authentication Verification
1. **Live Environment Credential Inspection:**
   - Check availability of live Firebase project configurations (`FIREBASE_PROJECT_ID`, credentials).
   - If available: Execute live registration, token issuance, Admin SDK token verification, custom claim validation.
   - If live project credentials are not supplied by the environment: Formally document status as **NOT TESTED** and provide exact reproducible validation protocols.

### 3.3 Firestore Integration Verification
1. **Repository Operations (using Firestore client connected to emulator/live):**
   - User record creation and authorized read.
   - Synthetic security event creation and retrieval.
   - Pending approval record creation.
   - Decision update (`PENDING` -> `APPROVED`) via authorized reviewer/admin.
   - Conflict check: Re-updating an already-reviewed approval (expect HTTP 409).
   - Multi-event atomic hash chain creation (sequence 1, 2, 3...) verifying transaction locking on `system_metadata/audit_state`.
   - Backend restart persistence check.

### 3.4 SQLite Migration Investigation & Reconciliation
1. **Detailed Disparity Investigation:**
   - Audit all 1,315 records in `data/agentshield.db`.
   - Group records by legacy (sequence IS NULL) vs integrity-enabled (sequence IS NOT NULL).
   - Confirm legacy timestamp ranges and schema evolution.
2. **Safe Migration & Provenance Strategy:**
   - **Requirement:** Original SQLite database must remain untouched and intact.
   - **Historical Preservation:** Preserve original `event_id`, `timestamp`, `tool_name`, `decision`, `payload_fingerprint`, `data_labels`, `reason_codes`, `risk_signals`.
   - **Provenance Attribution:** Tag legacy records with `migration_provenance: "legacy_sqlite_unhashed"`.
   - **Integrity Boundary:** Do not forge backdated hashes claiming historical records were cryptographically secured before migration.
   - **Verifiable Chain:** Anchor the migrated integrity chain starting from sequence 1 (or the sequence of the first hashed event) and establish an explicit migration checkpoint document.
3. **Migration Execution Test (Dedicated Test Collection):**
   - Run migration into test collections (`migration_audit_events_test`, `migration_approvals_test`).
   - Verify counts: 1,315 audit events, 142 approvals.
   - Verify zero duplicates, zero data loss, exact timestamp matching.
   - Verify hash-chain integrity of the integrity-enabled segment.

### 3.5 External Checkpoint Verification
1. **Cryptographic Test Suite:**
   - Ed25519 checkpoint generation and signature verification.
   - RSA (2048-bit) checkpoint generation and signature verification.
   - Tampered checkpoint detection (modified sequence, modified root hash, modified timestamp).
   - Invalid signature detection (corrupted signature bytes).
   - Wrong public key detection.
   - Key rotation test (verifying checkpoint signed with new key against new public key).
   - Independent verification test (verifying checkpoint strictly with public key without access to private key).
2. **Infrastructure Completeness Assessment:**
   - Evaluate whether external storage (e.g. public transparency log, Cloud Storage bucket with WORM/Object Lock, or public git repo) is configured.
   - Report gaps honestly.

### 3.6 Frontend and Backend Integration
1. **End-to-End Auth & API Flow:**
   - Test UI with token pass-through in `client.js`.
   - Verify protected endpoints require token.
   - Verify dashboard data rendering upon valid auth.
2. **Re-Test Four Core Demo Scenarios:**
   - Scenario 1: `safe` (Benign customer search -> ALLOW).
   - Scenario 2: `malicious` (Secret exfiltration -> BLOCK).
   - Scenario 3: `redaction` (PII sanitization -> REDACT).
   - Scenario 4: `approval` (High-risk data export -> REQUIRE_APPROVAL).

### 3.7 Deployment Configuration Review
1. Inspect `render.yaml`, `vercel.json`, `firestore.rules`, `.env.example`, `.gitignore`.
2. Verify zero secrets or private keys committed in repo.
3. Verify CORS configurations.
4. Verify production configuration strictly prevents falling back to SQLite or bypassing Firebase Auth.

---

## 4. Deliverables Matrix

| Report File | Topic |
|---|---|
| `FIREBASE_EMULATOR_TEST_REPORT.md` | Emulator suite test results (Auth, Firestore, Rules) |
| `FIREBASE_LIVE_AUTH_REPORT.md` | Live Firebase auth status, token checks, claims |
| `FIRESTORE_LIVE_INTEGRATION_REPORT.md` | Firestore operations, transaction checks, persistence |
| `SQLITE_MIGRATION_VERIFICATION_REPORT.md` | Disparity investigation, migration reconciliation & test |
| `AUDIT_CHECKPOINT_VERIFICATION_REPORT.md` | Checkpoint crypto verification, key rotation, external gap |
| `PHASE_13_1_FINAL_REPORT.md` | Complete Phase 13.1 synthesis and deployment verdict |
