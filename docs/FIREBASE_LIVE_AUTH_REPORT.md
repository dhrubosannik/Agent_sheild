# Firebase Live Authentication Report

**Project:** AgentShield  
**Phase:** 13.1 — Cloud Integration & Verification  
**Date:** November 24, 2026  
**Status:** NOT TESTED (Pending Live Project Configuration)  

---

## 1. Overview & Current Status

In Phase 13.1, complete automated testing was conducted against the Firebase Emulator Suite (`FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099`). However, **no active live Firebase project configuration or production service-account credentials were provided in this execution environment**.

Running `firebase projects:list` confirmed:
`Error: Failed to authenticate, have you run firebase login?`

In strict adherence to project verification standards, live cloud operations are marked **NOT TESTED** rather than fabricated or assumed.

---

## 2. Capability & Verification Matrix

| Capability | Implementation Status | Tested Locally | Tested with Emulator | Tested Live Firebase | Live Verdict |
|---|---|---|---|---|---|
| **Firebase JS SDK Setup** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Email/Password Registration** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Email/Password Login** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Password Reset Flow** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **ID Token Issuance** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **FastAPI Bearer Token Pass-Through** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Firebase Admin Token Verification** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **UID Identity Verification** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Custom Claims Role Authorization** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |
| **Invalid / Expired Token Rejection** | Implemented | Yes | Yes | Not tested | **NOT TESTED** |

---

## 3. Verified Code Readiness for Live Deployment

Although live project execution has not yet occurred, the codebase has been audited and prepared:

1. **Frontend Architecture (`frontend/src/firebase/`):**
   - Environment variables `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, and `VITE_FIREBASE_APP_ID` initialize the live Firebase client.
   - `getCurrentIdToken()` automatically extracts valid, refreshed ID tokens from `auth.currentUser`.
   - `api/client.js` attaches `Authorization: Bearer <token>` to all protected FastAPI calls.
2. **Backend Admin SDK (`backend/app/core/firebase.py`):**
   - Uses `credentials.Certificate` when `GOOGLE_APPLICATION_CREDENTIALS` is provided, or falls back to Google Cloud `credentials.ApplicationDefault()` in non-development environments.
   - Verifies project audience matching (`aud == settings.firebase_project_id`) to prevent cross-tenant identity spoofing.
3. **Role Authorization (`backend/app/core/auth.py`):**
   - Automatically maps `decoded.get("role")` custom claims to `UserRole.ADMIN`, `UserRole.REVIEWER`, or `UserRole.VIEWER`.
   - Restricts sensitive routes via `require_roles()`.

---

## 4. Live Verification Protocol (For Deployment Stage)

Once the production Firebase project is provisioned, the following protocol must be executed before opening public traffic:

1. **Step 1: Environment Provisioning**
   - Set `FIREBASE_PROJECT_ID=<your-production-project-id>`
   - Place service account JSON in secure location and set `GOOGLE_APPLICATION_CREDENTIALS` on backend.
   - Populate `frontend/.env` with corresponding `VITE_FIREBASE_*` keys.
2. **Step 2: Synthetic Account Provisioning**
   - Register a synthetic test administrator: `synthetic_admin@agentshield.internal`.
   - Run `python scripts/provision_admin.py --uid <ADMIN_UID> --project-id <PROJECT_ID>` to set `role: ADMIN`.
3. **Step 3: Live Token Exchange Verification**
   - Log in through the React frontend at `/`.
   - Inspect network request to FastAPI `/api/v1/events` and confirm HTTP 200 response.
   - Verify that requests with malformed tokens or tokens from another project receive HTTP 401.
4. **Step 4: Role Boundary Test**
   - Register a viewer account: `synthetic_viewer@agentshield.internal`.
   - Attempt to call `POST /api/v1/approvals/{id}/decision`; verify HTTP 403 Forbidden.

*Security Note: Synthetic test accounts must be deleted or disabled prior to production go-live. No credentials or ID tokens may be logged to console or persisted in artifacts.*
