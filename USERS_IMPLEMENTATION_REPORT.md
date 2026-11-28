# AgentShield `users` Collection Implementation Report

Date: 2026-11-28 · Status: **Implemented and Verified Locally (Not Deployed)**

## 1. Overview

Implemented and configured the Cloud Firestore `users` collection for AgentShield using the existing Firebase project configuration (no new Firebase project created, no deployment performed, and no existing user records overwritten).

All writes to `users/{uid}` flow exclusively through the FastAPI backend via the Firebase Admin SDK, while `firestore.rules` denies all direct client SDK writes (`allow write: if false;`) and restricts client reads to verified owners and administrators.

---

## 2. Firestore `users` Schema

- **Collection:** `users`
- **Document ID:** Firebase Authentication UID (`uid`)
- **Allowed Roles:** `ADMIN`, `REVIEWER`, `VIEWER` (default: `VIEWER`)
- **Allowed Statuses:** `ACTIVE`, `DISABLED`, `SUSPENDED` (default: `ACTIVE`)

| # | Field | Type | Constraints / Behavior |
|---|---|---|---|
| 1 | `uid` | String | Non-empty, max 128 chars, no `/` or whitespace; matches document ID |
| 2 | `email` | String | Valid email format, normalized lowercase, synchronized from Firebase Auth |
| 3 | `display_name` | String | Non-null string, max 200 chars (defaults to `""` when unset in Auth) |
| 4 | `role` | String | `ADMIN`, `REVIEWER`, or `VIEWER`; hardcoded `VIEWER` on registration |
| 5 | `email_verified` | Boolean | Strict boolean, synchronized from Firebase Auth |
| 6 | `status` | String | `ACTIVE`, `DISABLED`, or `SUSPENDED`; defaults to `ACTIVE` |
| 7 | `created_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) set once at creation |
| 8 | `updated_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) updated on every write |
| 9 | `last_login_at` | Timestamp or Null | `null` on registration; `firestore.SERVER_TIMESTAMP` on login |

Passwords, password hashes, and tokens are explicitly forbidden by schema validation (`FORBIDDEN_CREDENTIAL_FIELDS`) and never stored in Firestore.

---

## 3. Files Changed

### Backend
- [backend/app/models/enums.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/enums.py) — Added `UserRole` (`ADMIN`, `REVIEWER`, `VIEWER`) and `UserStatus` (`ACTIVE`, `DISABLED`, `SUSPENDED`).
- [backend/app/models/user.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/user.py) — Added `UserProfile` and `UserSyncRequest` (`extra="forbid"`) plus strict type/value validators and forbidden credential field checks.
- [backend/app/storage/firestore_user_repository.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/firestore_user_repository.py) — Created `FirestoreUserRepository` with transactional `create_user_on_registration`, `create_user`, `sync_from_auth`, `update_role`, `update_status`, `get_by_uid`, `get_by_email`, and `list_users_page`. Uses `firestore.SERVER_TIMESTAMP` and never overwrites existing user records.
- [backend/app/storage/__init__.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/__init__.py) — Exported `FirestoreUserRepository` and user domain exceptions.
- [backend/app/core/auth.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/core/auth.py) — Imported shared `UserRole`, extracted `_verify_bearer_claims`, added `email` and `display_name` to `AuthenticatedUser`, and added `get_firebase_session_user` for pre-verification user registration/sync while preserving `email_verified == True` enforcement on all protected operational routes.
- [backend/app/api/users.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/users.py) — Added `POST /api/v1/users/register`, `POST /api/v1/users/login`, `POST /api/v1/users/sync`, and `GET /api/v1/users/me`. Resolves authoritative `email`, `email_verified`, and `display_name` from verified Firebase tokens / Firebase Admin `auth.get_user`.
- [backend/app/api/admin.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/admin.py) — Hardened `POST /api/v1/admin/users/{uid}/role` to prevent any user (including admins) from modifying their own role (`403`), synchronize role changes to Firestore `users/{uid}` alongside Firebase Auth custom claims, and added `GET /api/v1/admin/users`, `GET /api/v1/admin/users/{uid}`, and `POST /api/v1/admin/users/{uid}/status`.
- [backend/app/main.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/main.py) — Registered `users` router.

### Security Rules
- [firestore.rules](file:///Users/sayantanisinha/Desktop/agent%20shield/firestore.rules) — Hardened `match /users/{uid}` to allow reads only for verified owners or verified admins (`allow read: if signedIn() && (request.auth.uid == uid || isAdmin());`) and deny all client writes (`allow write: if false;`).

### Frontend
- [frontend/src/api/client.js](file:///Users/sayantanisinha/Desktop/agent%20shield/frontend/src/api/client.js) — Added `registerUser`, `loginUser`, `syncUser`, and `getCurrentUser` API helpers (no client-supplied roles or Admin credentials).
- [frontend/src/components/AuthScreen.jsx](file:///Users/sayantanisinha/Desktop/agent%20shield/frontend/src/components/AuthScreen.jsx) — Wired registration (`api.registerUser()`), login (`api.loginUser()`), and email verification confirmation (`api.syncUser()`) into the existing authentication UI flow without changing existing auth guarantees.

### Tests
- [backend/tests/test_users.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/test_users.py) — Unit and API tests covering schema validation, password rejection, registration with default `VIEWER`, non-overwriting re-registration, email verification sync, `last_login_at` updates, disabled-user blocking, unauthorized role escalation (`401`/`403`/`422`), and admin role/status management.
- [backend/tests/emulator/test_emulator_users.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_users.py) — End-to-end Firebase Auth + Firestore emulator tests verifying real Firestore `Timestamp` creation, non-overwrite guarantee, verification sync, login timestamp updates, and admin role assignment.
- [backend/tests/emulator/test_emulator_firestore_rules.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_firestore_rules.py) — Added `test_users_collection_rules_deny_client_writes_and_restrict_reads` verifying Firestore rules block direct client writes even by admins and restrict reads to verified owners/admins.
- [frontend/src/api/client.test.js](file:///Users/sayantanisinha/Desktop/agent%20shield/frontend/src/api/client.test.js) — Added unit test confirming user lifecycle requests target the expected endpoints and never transmit `role`, `status`, or `password`.

---

## 4. Security Controls Implemented

- **Backend Token Verification:** All `/api/v1/users/*` and `/api/v1/admin/*` endpoints verify Firebase ID tokens via `verify_firebase_id_token` (signature, expiration, and `aud` project check).
- **No Frontend Role Trust:** `UserSyncRequest` uses `ConfigDict(extra="forbid")` and only permits `display_name`. Client payloads containing `role`, `status`, `uid`, `email`, or `email_verified` fail with `422 Unprocessable Entity`.
- **Default Least Privilege:** Registration always assigns `VIEWER` and `ACTIVE`.
- **Self-Role Modification Blocked:** `POST /api/v1/admin/users/{uid}/role` rejects `uid == user.uid` with `403 Forbidden`, and non-admins are blocked by `require_roles(UserRole.ADMIN)`.
- **Client-Side Writes Denied:** `firestore.rules` enforces `allow write: if false;` on `users/{uid}` so client SDKs cannot bypass validation, self-escalate, or write passwords.
- **No Admin Credentials in Frontend:** Frontend code uses only `firebase/auth` Web SDK and backend HTTP APIs.

---

## 5. Tests Executed

| Suite | Command | Result |
|---|---|---|
| Backend & SDK unit/API tests | `.venv/bin/python -m pytest -q` | **316 passed** |
| Firebase Emulator Suite (Auth + Firestore + `firestore.rules`) | `npx -y firebase-tools emulators:exec --only auth,firestore --project demo-agentshield "unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_CLOUD_PROJECT_CONFIRM && AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q"` | **31 passed** |
| Frontend unit tests | `cd frontend && npm test` | **24 passed**, 1 skipped (`auth.emulator.test.ts` requires running emulator) |
| Frontend production build | `npm --prefix frontend run build` | **Built cleanly** |

---

## 6. Remaining Issues & Operational Notes

1. **Not Deployed:** `firestore.rules` and backend/frontend changes are verified locally and in the Firebase Emulator Suite only; they have not been deployed to the live Firebase project, Render, or Vercel.
2. **Role Claim Propagation Delay:** When an administrator changes a user's role via `POST /api/v1/admin/users/{uid}/role`, both Firebase Auth custom claims and Firestore `users/{uid}` are updated immediately, but the target user's existing ID token remains cached until refreshed (`getIdToken(true)` or next token refresh/sign-in).
3. **Existing Cloud Users Without `users` Documents:** Pre-existing Firebase Auth users who registered before the `users` collection was added will have their `users/{uid}` document initialized automatically on their next login/sync (`sync_from_auth` with default `VIEWER` role) or when an admin updates their role (`create_if_missing_from_auth`); however, if an existing user already has a non-`VIEWER` custom claim in Firebase Auth and signs in for the first time without a Firestore `users/{uid}` doc, `sync_from_auth` initializes the Firestore doc as `VIEWER` unless reconciled by an admin or migration script.
4. **Disabled/Suspended Enforcement Scope:** `POST /api/v1/users/login` and `/sync` block `DISABLED` and `SUSPENDED` users via Firestore status checks, and `POST /api/v1/admin/users/{uid}/status` sets `disabled=True` in Firebase Auth for `DISABLED` accounts; however, `get_authenticated_user()` on general API endpoints relies on stateless ID token verification without querying Firestore on every request, so a `SUSPENDED` user with an unexpired ID token retains API access until token expiration unless Auth revocation or per-request status lookup is added.
5. **SQLite Mode Fallback:** When `DATABASE_MODE=sqlite` (local development without Firestore), `/api/v1/users/*` endpoints return `503 User repository requires Firestore database mode.` and `AuthScreen.jsx` logs a warning while preserving existing Firebase Auth login/verification behavior.
