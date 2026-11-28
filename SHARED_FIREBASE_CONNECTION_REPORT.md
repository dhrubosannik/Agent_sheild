# Shared Firebase Connection Report

Date: 2026-11-28 · Branch: `abjoraj` (local changes below are **not committed**) · Nothing was deployed.

## Summary

| Mode | Status |
|---|---|
| **A. Firebase Emulator mode** | **PASS**: 9/9 connection checks with a synthetic user and synthetic documents |
| **B. Shared Firebase development mode** | **BLOCKED**: this laptop has no credentials for the shared project yet, and the web app config is missing |

No shared Firebase data was read or written. No SQLite data was migrated, no project was created, and the Project ID was not changed.

## 1. Configuration files checked

| File | Finding |
|---|---|
| `.firebaserc` | Default project **`agentsheild-febd5`** (committed in `9791375`; unchanged). This is the only real project ID in the repository. |
| `firebase.json` | Auth emulator 9099, Firestore emulator 8080, UI 4000, `singleProjectMode`, rules `firestore.rules`, indexes `firestore.indexes.json` |
| `firestore.rules` / `firestore.indexes.json` | Phase 13.2 versions (client read-only, approvals and audit records backend-only). Not deployed. |
| `backend/app/core/firebase_config.py`, `firebase.py`, `firestore.py`, `config.py` | Target selection (`none` / `emulator` / `cloud`), validation, Admin SDK initialization, Firestore client |
| `frontend/src/firebase/config.js`, `firebase.ts`, `auth.ts` | Frontend target selection, validation, Admin-credential leak guard |
| `.env.example`, `.env.emulator.example`, `.env.cloud.example`, `frontend/*.example` | Templates (tracked, no secrets) |
| `render.yaml` | Production `FIREBASE_TARGET=cloud`; project ID and credentials are Render secrets |
| Local machine | No `.env*` files existed. No gcloud CLI, no Application Default Credentials, Firebase CLI not logged in, no service-account files. No `FIREBASE_*` / `GOOGLE_*` variables in the shell. |
| Public hosting probe | `https://agentsheild-febd5.firebaseapp.com/__/firebase/init.json` and `.web.app` return **404 "Site Not Found"**. Firebase Hosting is not deployed, so the web config cannot be obtained publicly. This neither confirms nor rules out the project. |

**Project ID expected by the code:** `agentsheild-febd5`. Note the spelling "sheild", which matches the repository name. The owner should confirm that this is the shared project.

**Firestore database ID:** the code has always used the **`(default)`** database, implicitly. I added an explicit setting, `FIRESTORE_DATABASE_ID`, which defaults to `(default)`, so behavior is unchanged. A named database can be configured later if the owner uses one.

**Admin SDK initialization (checked):**
- `FIREBASE_TARGET=emulator`: points the Admin SDK at the emulators and uses anonymous Firestore credentials.
- `FIREBASE_TARGET=cloud`: uses `credentials.Certificate(GOOGLE_APPLICATION_CREDENTIALS)` when a key file is set, otherwise `credentials.ApplicationDefault()`. It then verifies each ID token's `aud` against `FIREBASE_PROJECT_ID`.
- Initialization is refused unless the configuration validates.

## 2. Required environment variables

### Backend: `.env.cloud` (created locally, git-ignored)

| Variable | Value / status |
|---|---|
| `FIREBASE_TARGET` | `cloud` ✔ |
| `FIREBASE_PROJECT_ID` | `agentsheild-febd5` (from `.firebaserc`) ✔ |
| `FIREBASE_CLOUD_PROJECT_CONFIRM` | **empty on purpose.** Set it to the same ID once the owner confirms the project. This is the explicit opt-in. |
| `GOOGLE_APPLICATION_CREDENTIALS` | empty (use Application Default Credentials), **or** an absolute path to a key outside the repository. **Missing:** neither exists on this laptop. |
| `FIRESTORE_DATABASE_ID` | `(default)` |
| `DATABASE_MODE` / `FIREBASE_AUTH_REQUIRED` / `RATE_LIMIT_BACKEND` | `firestore` / `true` / `firestore` |
| `FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST` | must stay empty (also in the shell) |

### Frontend: `frontend/.env.cloud` (created locally, git-ignored)

| Variable | Value / status |
|---|---|
| `VITE_FIREBASE_TARGET` | `cloud` ✔ |
| `VITE_FIREBASE_PROJECT_ID` | `agentsheild-febd5` ✔ |
| `VITE_FIREBASE_AUTH_DOMAIN` | `agentsheild-febd5.firebaseapp.com` (standard; the owner should confirm) |
| `VITE_FIREBASE_API_KEY` | **missing** (placeholder) |
| `VITE_FIREBASE_APP_ID` | **missing** (placeholder) |
| `VITE_FIREBASE_AUTH_EMULATOR_URL` | must stay empty |

### Emulator mode: `.env.emulator` and `frontend/.env.emulator` (created locally, complete)

`FIREBASE_TARGET=emulator`, `FIREBASE_PROJECT_ID=demo-agentshield`, `FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099`, `FIRESTORE_EMULATOR_HOST=127.0.0.1:8080`, with the matching `VITE_*` values. Using a `demo-*` project means the emulator never contacts Google Cloud. Automated tests always use emulator mode, and cloud mode is refused during tests.

## 3. Emulator connection status: PASS

Command (fresh emulators):
```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21 firebase emulators:exec --only auth,firestore --project demo-agentshield \
  "AGENTSHIELD_ENV_FILE=.env.emulator .venv/bin/python scripts/verify_firebase_connection.py"
```

| Check | Result |
|---|---|
| Configuration | PASS |
| Firebase Admin initialization | PASS (`demo-agentshield`) |
| Authentication connection | PASS: synthetic user `agentshield-synthetic-…@agentshield-synthetic.test` created with role REVIEWER |
| ID token verification | PASS: `aud` matches, `email_verified=true`, role claim present |
| Backend API with the verified token | PASS: `GET /api/v1/policies/current` → 200 |
| Firestore connection | PASS |
| User document access (Security Rules, as the synthetic user) | PASS: own `users/{uid}` 200, another user's document 403, self-write of `role` 403 |
| Security event (audit) repository | PASS: synthetic event appended, read back, v2 chain valid |
| Approval repository | PASS: synthetic approval created, decided in a transaction, second decision → conflict |
| Cleanup | synthetic user deleted (emulator data is discarded on exit) |

Regression check: backend suite 310 passed; frontend 23 passed.

## 4. Shared Firebase connection status: BLOCKED

| Step | Result |
|---|---|
| `.env.cloud` as created | **BLOCKED** by design: `FIREBASE_CLOUD_PROJECT_CONFIRM` not set |
| With the confirmation set (in-process only; the file was not changed) | Configuration PASS; Admin SDK object created locally (no network call yet) |
| Authentication connection | **FAIL: `DefaultCredentialsError`.** No credentials on this laptop. |
| ID token verification, user documents, Firestore, repositories | not reached |
| Frontend config validation | **BLOCKED:** API key and app ID are placeholders |

**Behavior of the shared mode once it is unblocked** (`scripts/verify_firebase_connection.py` with `AGENTSHIELD_ENV_FILE=.env.cloud`):
- **Read-only by default:**
  - an Auth lookup of a non-existent synthetic address;
  - one Firestore document read;
  - one page of events and approvals.
- **Never:**
  - appends to the shared audit chain (records there are permanent);
  - writes approvals;
  - modifies existing documents;
  - resets data;
  - migrates.
- **Optional `--allow-cloud-test-user`:** creates **one** synthetic Auth user and its `users/{uid}` document. With them it verifies the ID token, the API call and the rules, then deletes both. Use this only with your teammate's agreement.

## 5. Missing configuration

1. **Backend credentials for the shared project.** Either:
   - **preferred:** your teammate grants your Google account *Cloud Datastore User* (plus *Firebase Authentication Admin* to create the synthetic user and manage roles). You install the gcloud CLI, then run `gcloud auth application-default login` and `gcloud auth application-default set-quota-project agentsheild-febd5`;
   - **or:** a dedicated service-account key, stored outside the repository (for example `~/.config/agentshield/firebase-admin.json`, `chmod 600`).
2. **Web app config** from your teammate's Firebase Console (Project settings → Your apps → Web): `apiKey` and `appId`. Please also confirm `authDomain`.
3. **Confirmation that `agentsheild-febd5` is the shared project.** Then set `FIREBASE_CLOUD_PROJECT_CONFIRM=agentsheild-febd5` in `.env.cloud`.
4. **Confirmation of the Firestore database ID** (the code expects `(default)`).

## 6. Remaining blockers and notes

- **Rules not deployed.** The shared project's deployed Firestore rules and indexes are unknown from this laptop. The repository versions must be deployed by the owner before the cloud user-document and approval checks reflect this code.
- **Email/Password sign-in** must be enabled in the shared project, with `localhost` as an authorized domain, for the dashboard sign-in to work.
- **gcloud CLI is not installed** on this laptop (`brew install --cask google-cloud-sdk`).
- **Firebase CLI not logged in.** That is only needed if you will run CLI commands against the shared project; it isn't needed for the app.

## 7. Changes made in this step (uncommitted)

| File | Change |
|---|---|
| `backend/app/core/config.py`, `firestore.py`, `firebase_config.py` | Optional `FIRESTORE_DATABASE_ID` (default `(default)`, so behavior is unchanged); shown in the config report |
| `.env.example`, `.env.emulator.example`, `.env.cloud.example` | Document `FIRESTORE_DATABASE_ID` |
| `scripts/verify_firebase_connection.py` | New. Connection verification (emulator: full; cloud: read-only unless opted in) |
| `.env.emulator`, `.env.cloud`, `frontend/.env.emulator`, `frontend/.env.cloud` | Created locally, **git-ignored** (verified); no secrets in them |
| `SHARED_FIREBASE_CONNECTION_REPORT.md` | This report |

No private keys, tokens or credential paths were printed or written to any report.

---

## Update: after `gcloud auth application-default login` (2026-11-28, 16:57)

The developer installed the gcloud CLI and created Application Default Credentials. `set-quota-project agentsheild-febd5` failed with *"account does not have the `serviceusage.services.use` permission"*.

Read-only checks with those credentials:

| Check | Result |
|---|---|
| ADC credentials | valid |
| Project `agentsheild-febd5` (Cloud Resource Manager) | **exists and is visible to this account (HTTP 200).** The Project ID is confirmed. |
| Firestore `(default)` database | **reachable**: a read returned 404 *document not found* (not 403). The database ID is confirmed as `(default)`. |
| `verify_firebase_connection.py` (cloud, read-only; opt-in passed for one run, `.env.cloud` unchanged) | Configuration PASS · Admin init PASS · **Auth: `PermissionDeniedError`** · Firestore PASS · audit repository read PASS (0 events, no v2 chain yet) · approval repository read PASS (0 approvals) |
| Gcloud CLI account (`gcloud auth login`) | not logged in. Not needed by the app; ADC is a separate login. |

**Remaining blockers**

1. The account needs these IAM roles on `agentsheild-febd5`, granted by the owner in Google Cloud Console → IAM:
   - **Service Usage Consumer** (`roles/serviceusage.serviceUsageConsumer`): fixes the quota-project error;
   - **Firebase Authentication Admin** (`roles/firebaseauth.admin`): fixes `PermissionDeniedError` (token-related admin calls, roles, synthetic user);
   - **Cloud Datastore User** (`roles/datastore.user`): Firestore writes by the backend. Reads already work; write permission is unverified.
2. Web app `apiKey` and `appId` for `frontend/.env.cloud`.
3. After the roles are granted, rerun `gcloud auth application-default set-quota-project agentsheild-febd5`, then the verification script.

## Update 2: recheck after IAM changes (2026-11-28)

| Check | Result |
|---|---|
| IAM permissions (`testIamPermissions`) | **all granted:** serviceusage.services.use, firebaseauth.users.get/create/update, datastore.entities.get/create/update, resourcemanager.projects.get |
| `gcloud auth application-default set-quota-project agentsheild-febd5` | **done** (quota project added to ADC) |
| Firestore `(default)` | PASS (read); audit repository PASS (0 events); approval repository PASS (0 approvals) |
| Firebase Authentication | **FAIL: `ConfigurationNotFoundError`.** The Identity Toolkit admin config returns `404 CONFIGURATION_NOT_FOUND`, meaning **Firebase Authentication has never been initialized in this project.** |
| Web app config (`frontend/.env.cloud`) | still placeholders (`apiKey`, `appId`) |

**Remaining owner actions**
1. Firebase Console → **Authentication → Get started**, enable **Email/Password**, and keep `localhost` in Authorized domains.
2. Firebase Console → Project settings → Your apps → register a **Web app** if none exists, and share `apiKey` and `appId`.
3. Deploy this repository's `firestore.rules` and `firestore.indexes.json`.

## Update 3: web config received, Authentication enabled (2026-11-28)

- **`frontend/.env.cloud`** (git-ignored) filled with the owner's web app config: `apiKey`, `authDomain=agentsheild-febd5.firebaseapp.com`, `projectId=agentsheild-febd5`, `appId=1:60620246319:web:…`. Analytics, storage and messaging fields are not used by the dashboard and were not added. The frontend validator reports it valid.
- **`.env.cloud`** (git-ignored): `FIREBASE_CLOUD_PROJECT_CONFIRM=agentsheild-febd5` set. The project ID is confirmed by the owner's web config. `check_firebase_config.py`: Configuration OK, using ADC.
- **Firebase Authentication**: initialized; Email/Password **enabled**; authorized domains `localhost`, `agentsheild-febd5.firebaseapp.com`, `agentsheild-febd5.web.app`.

### Shared-project verification (`--allow-cloud-test-user`)

| Check | Result |
|---|---|
| Configuration | PASS |
| Firebase Admin initialization | PASS |
| Authentication connection | PASS: one synthetic user created |
| ID token verification | PASS: real token from the shared project; `aud` matches, `email_verified=true`, role claim REVIEWER |
| Backend API with verified token | PASS: `GET /api/v1/policies/current` → 200 |
| Firestore connection | PASS |
| User document access (client SDK path) | **FAIL (expected): own doc 403**, other doc 403, self-write 403 |
| Security event repository (read-only) | PASS: 0 events, no v2 chain yet |
| Approval repository (read-only) | PASS: 0 approvals |
| Cleanup | synthetic Auth user and its `users/{uid}` document deleted; verified that none remain |

**Why the user-document check fails.** The deployed Firestore rules (release updated 2026-11-24T13:11:29Z) are Firebase's default *locked mode*: `match /{document=**} { allow read, write: if false; }`. They do **not** match this repository's `firestore.rules`. This is secure (all client access denied) and does not affect the dashboard, which reads only through the backend API (Admin SDK). However, browser reads of `users/{uid}`, `audit_events` and `approvals` will be denied until the owner deploys the repository rules, and the indexes are not deployed either.

No audit events, approvals or existing documents were written. Nothing was migrated or deployed.

### Remaining
1. The owner deploys `firestore.rules` and `firestore.indexes.json` from this branch (`firebase deploy --only firestore:rules,firestore:indexes --project agentsheild-febd5`). Then rerun the verification and expect user-document access 200/403/403.
2. Optional: a cloud end-to-end run of the dashboard (`AGENTSHIELD_PROFILE=cloud ./scripts/start_agentshield.sh`). It will create real shared data (accounts, audit events), so agree on it with the owner first.

## Update 4: rules and indexes deployed by the developer; full pass (2026-11-28)

- The first deploy attempt failed on the TTL field override (`rate_limits.expires_at`) because **TTL requires billing**. The override was removed from `firestore.indexes.json`; the composite indexes were unchanged. The always-true `uid != null` was removed from the `users` rule, which cleared the compiler warning without changing behavior. Emulator rules tests: 10/10 pass.
- Second deploy: **Deploy complete.** The rules release was updated `2026-11-28T11:41:17Z`, and the **deployed rules match the repository's `firestore.rules`**.
- Composite indexes, all `READY`:
  - `approvals(status, created_at)`
  - `audit_events(decision, timestamp)`
  - `audit_events(tool_name, timestamp)`
  - `audit_events(decision, tool_name, timestamp)`

### Final shared-project verification: **9/9 PASS**

| Check | Result |
|---|---|
| Configuration | PASS |
| Firebase Admin initialization | PASS |
| Authentication connection | PASS (synthetic user) |
| ID token verification | PASS (real token; `aud`, `email_verified`, role claim) |
| Backend API with verified token | PASS (200) |
| Firestore connection | PASS |
| User document access (deployed rules) | **PASS**: own doc 200, other user's doc 403, self-write 403 |
| Security event repository (read-only) | PASS |
| Approval repository (read-only) | PASS |
| Cleanup | synthetic user and document deleted |

**Status: Emulator mode PASS · Shared Firebase development mode PASS.** No existing shared records were modified, nothing was migrated, and nothing was deployed by the assistant. The developer ran the rules and index deploy.
