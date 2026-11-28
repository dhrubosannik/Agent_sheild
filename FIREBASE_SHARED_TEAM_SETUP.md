# Shared Firebase Project: Team Setup

AgentShield uses **one shared cloud Firebase project**. A teammate (the **Project Owner**) owns it under their Google account on their laptop. Other developers work on separate laptops **without Firebase Console access**.

This document describes who does what, and how two developers can use the same project without damaging each other's data.

> Nothing in this repository creates a Firebase project or changes its Project ID. Until the owner supplies the real values, every template uses placeholders such as `<shared-firebase-project-id>`.
>
> Note: the committed `.firebaserc` names `agentsheild-febd5` as the Firebase CLI default. It is unchanged. The owner should confirm whether that is the shared project. Emulator commands in this repo always pass `--project demo-agentshield`, so they never use it.

## 1. Roles

| Task | Project Owner (has Console) | Developer (no Console) |
|---|---|---|
| Enable Email/Password sign-in and keep `localhost` in Authorized domains | ✔ | |
| Register the web app and share its public web config | ✔ | |
| Grant the developer access (§3) | ✔ | |
| Deploy `firestore.rules` / `firestore.indexes.json` (after review and emulator tests) | ✔ | proposes changes via PR |
| Assign the first ADMIN (`scripts/provision_admin.py`) | ✔ | |
| Later role changes | ADMIN via `POST /api/v1/admin/users/{uid}/role` | same, if ADMIN |
| Day-to-day development and all automated tests | | ✔ on the **emulator** |
| Cloud integration checks (explicit, occasional) | ✔ | ✔ with `FIREBASE_TARGET=cloud` |

## 2. What the owner sends the developer

Send through a private channel (password manager, or a direct message the owner deletes afterwards). Never via git, issues or public chat.

1. **Project ID** (public identifier).
2. **Web app config**, from *Project settings → General → Your apps → Web app*: `apiKey`, `authDomain`, `projectId`, `appId`. These are public identifiers that browsers receive anyway, but keep them in git-ignored files.
3. **Backend access.** Preferred: IAM roles for the developer's Google account (§3a). Fallback: a dedicated service-account key (§3b).
4. Confirmation that `firestore.rules` and `firestore.indexes.json` from this repository have been deployed, and which commit they came from.

## 3. Backend (Firebase Admin) access for the developer

### 3a. Preferred: IAM roles plus Application Default Credentials (no key file)

Owner, in Google Cloud Console → IAM for the project, grants the developer's Google account:
- **Cloud Datastore User** (`roles/datastore.user`): Firestore read/write for the backend.
- **Firebase Authentication Admin** (`roles/firebaseauth.admin`): only needed for role assignment (custom claims). Token verification itself needs no role.

Developer, once on their laptop:
```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <shared-firebase-project-id>
```
Then leave `GOOGLE_APPLICATION_CREDENTIALS` empty in `.env.cloud`. Access is revoked by removing the IAM roles; nothing needs rotating.

### 3b. Fallback: a dedicated service-account key

- The owner creates a service account **for this developer only**, with the same roles, and generates one JSON key.
- The developer stores it **outside the repository**, for example `~/.config/agentshield/firebase-admin.json` with `chmod 600`, and sets an absolute `GOOGLE_APPLICATION_CREDENTIALS` path in `.env.cloud`.
- The backend refuses to start if that path is inside the repository.
- Revoke by deleting the key in Cloud Console when it is no longer needed.

**Never:**
- commit keys;
- copy them into `frontend/` or any `VITE_*` variable (the frontend build fails if it detects one);
- share one key between people.

## 4. Working safely against the same project

1. **The emulator is the default workspace.** All development and **all automated tests** run on the local emulator (`demo-agentshield`). Each laptop's emulator data is private, so nothing a developer does locally affects the shared project.
2. **Cloud is an explicit opt-in.** The backend connects to the shared project only when:
   - `FIREBASE_TARGET=cloud` is set;
   - `FIREBASE_CLOUD_PROJECT_CONFIRM` repeats the project ID;
   - no emulator host variable is set.

   A project ID alone never connects anything.
3. **Tests can never reach the cloud.**
   - The test runner sets `AGENTSHIELD_TEST_MODE=1`, so the backend refuses `FIREBASE_TARGET=cloud`;
   - it ignores the developer's `.env` files and removes `GOOGLE_APPLICATION_CREDENTIALS` from the test process;
   - emulator tests refuse any non-`demo-*` project ID.
4. **Everything written in cloud mode is real and shared.** Both developers' backends write to the same collections (`audit_events`, `audit_transitions`, `approvals`, `rate_limits` and others). Therefore:
   - Do not run demo scenarios, load tests or the SQLite migration against the cloud. The migration script refuses to write to the cloud without `--allow-cloud`.
   - Do not create, edit or delete audit documents in the Console. The audit log is an append-only hash chain, so any manual change shows up as a verification failure.
   - Concurrent backends are safe: audit appends and approval decisions use Firestore transactions with unique sequence documents. This was tested with multiple processes on the emulator.
5. **One person deploys rules and indexes.** Changes to `firestore.rules` or `firestore.indexes.json` go through a PR and `./scripts/run_emulator_tests.sh`. Then the owner deploys them. The developer does not deploy.
6. **Roles are managed through the backend**, not by editing claims ad hoc. A user picks up a new role after their ID token refreshes (sign out and in, or wait up to an hour).
7. **Coordinate cloud sessions** when testing approvals or roles together, because you will see each other's records.
8. **When someone leaves:** remove their IAM roles, or delete their service-account key.

## 5. Quick checks

```bash
# What would the backend connect to? (prints no secrets)
AGENTSHIELD_ENV_FILE=.env.cloud python scripts/check_firebase_config.py
AGENTSHIELD_ENV_FILE=.env.emulator python scripts/check_firebase_config.py
```

See [FIREBASE_DEVELOPMENT_GUIDE.md](FIREBASE_DEVELOPMENT_GUIDE.md) for the day-to-day commands.
