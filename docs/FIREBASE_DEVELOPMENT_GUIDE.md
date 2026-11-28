# Firebase Development Guide

The backend and the dashboard each choose **one** Firebase target explicitly:

| Target | Backend `FIREBASE_TARGET` | Frontend `VITE_FIREBASE_TARGET` | Data | Use for |
|---|---|---|---|---|
| none (default) | `none` | `none` | local SQLite | quick UI and policy work, no Firebase |
| emulator | `emulator` | `emulator` | local emulator (`demo-agentshield`) | normal development and **all tests** |
| cloud | `cloud` | `cloud` | **shared project, real data** | explicit integration checks only |

The configuration for each target lives in its own git-ignored file:

| | Backend (repo root) | Frontend (`frontend/`) |
|---|---|---|
| none | `.env` (from `.env.example`) | `.env` (from `.env.example`) |
| emulator | `.env.emulator` (from `.env.emulator.example`) | `.env.emulator` (from `.env.emulator.example`) |
| cloud | `.env.cloud` (from `.env.cloud.example`) | `.env.cloud` (from `.env.cloud.example`) |

- The backend picks its file with `AGENTSHIELD_ENV_FILE` (default `.env`).
- The frontend picks its file by Vite mode: `npm run dev:emulator` / `npm run dev:cloud`.

## Prerequisites
- Python venv: `python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt`
- `npm --prefix frontend install`
- Firebase CLI (`npm i -g firebase-tools`). **firebase-tools 15 needs Java 21+.** On macOS: `brew install openjdk@21`, then `export JAVA_HOME=/opt/homebrew/opt/openjdk@21`.
- No Firebase login is needed for the emulator.

## A. No Firebase (default)
```bash
cp .env.example .env            # optional; defaults already work
./scripts/start_agentshield.sh  # http://127.0.0.1:5173
```
Requests use the explicit local identities from `DEV_AUTH_IDENTITIES` (loopback only).

## B. Local Emulator Suite (isolated)
```bash
cp .env.emulator.example .env.emulator
cp frontend/.env.emulator.example frontend/.env.emulator

# terminal 1: emulators (Auth 9099, Firestore 8080, UI 4000); rules from firestore.rules
firebase emulators:start --only auth,firestore --project demo-agentshield

# terminal 2: backend + dashboard
AGENTSHIELD_PROFILE=emulator ./scripts/start_agentshield.sh
```
- Register in the dashboard. Verification links appear in the emulator UI (http://127.0.0.1:4000/auth) and in the emulator log.
- To make an emulator user ADMIN, use the Emulator UI to edit the user's custom claims: `{"role":"ADMIN"}`.
- Emulator data disappears when the emulators stop. Add `--import ./.emulator-data --export-on-exit` to keep it locally (git-ignore that folder).

## C. Shared cloud project (explicit)
First get the values listed in [FIREBASE_SHARED_TEAM_SETUP.md](FIREBASE_SHARED_TEAM_SETUP.md) §2 from the Project Owner.
```bash
cp .env.cloud.example .env.cloud                     # set FIREBASE_PROJECT_ID and FIREBASE_CLOUD_PROJECT_CONFIRM
cp frontend/.env.cloud.example frontend/.env.cloud   # paste the web app config
gcloud auth application-default login                # or set GOOGLE_APPLICATION_CREDENTIALS (outside the repo)
unset FIREBASE_AUTH_EMULATOR_HOST FIRESTORE_EMULATOR_HOST

AGENTSHIELD_ENV_FILE=.env.cloud .venv/bin/python scripts/check_firebase_config.py
AGENTSHIELD_PROFILE=cloud ./scripts/start_agentshield.sh
```
Everything you do in this mode reads and writes the **shared** data. Read §4 of the team setup document first.

## Tests
```bash
.venv/bin/python -m pytest -q          # backend + SDK; Firebase disabled, cloud refused
npm --prefix frontend test             # frontend unit tests
./scripts/run_emulator_tests.sh        # fresh emulators: emulator pytest, real-backend E2E, legacy scripts
```
The test runner:
- sets `AGENTSHIELD_TEST_MODE=1`, so `FIREBASE_TARGET=cloud` is refused;
- ignores your `.env` files;
- strips `GOOGLE_APPLICATION_CREDENTIALS`;
- uses a throwaway SQLite file.

Emulator tests refuse non-`demo-*` project IDs. **No test can write to the shared project.**

## Configuration validation
Startup fails with a list of exactly what is missing or unsafe. To see the same report without starting anything:
```bash
AGENTSHIELD_ENV_FILE=.env.emulator .venv/bin/python scripts/check_firebase_config.py
```

**Backend rules enforced**

| Situation | Result |
|---|---|
| `DATABASE_MODE=firestore`, `RATE_LIMIT_BACKEND=firestore` or `FIREBASE_AUTH_REQUIRED=true` without a Firebase target | error |
| Production without `FIREBASE_TARGET=cloud` | error |
| Emulator target without `FIREBASE_PROJECT_ID`, `FIREBASE_AUTH_EMULATOR_HOST` or (with Firestore) `FIRESTORE_EMULATOR_HOST` | error |
| Non-`demo-*` emulator project | warning; error during tests |
| Cloud target with a missing, invalid or placeholder project ID | error |
| Cloud target combined with emulator hosts | error |
| Cloud target without `FIREBASE_CLOUD_PROJECT_CONFIRM` outside production | error |
| Credentials file that does not exist, or lies inside the repository | error |
| Cloud target during tests | error |
| `FIREBASE_PROJECT_ID` set while the target is `none` | ignored, with a warning |

**Frontend rules enforced.** The dashboard shows a "Firebase configuration is incomplete" screen naming each problem:
- a cloud target missing any of the four web-config values, or still holding placeholders;
- a cloud target with an emulator URL;
- an emulator target without an emulator URL;
- an unknown target.

`vite dev` and `vite build` fail outright if any `VITE_*` variable looks like Admin or service-account credentials.

## Security boundaries (unchanged)
- `firestore.rules`: clients are read-only, need a verified email, and cannot write approvals or audit records.
- The backend verifies Firebase ID tokens for the configured project ID, requires `email_verified`, and enforces roles. The Admin SDK bypasses rules, so backend authorization is mandatory in every target.
