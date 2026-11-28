#!/usr/bin/env bash
# Runs every test that needs the Firebase Emulator Suite, against freshly
# started Auth + Firestore emulators (rules from firestore.rules):
#   1. backend/tests/emulator (pytest)
#   2. a real backend (uvicorn, Firestore mode, Firebase auth required) plus the
#      frontend email-verification E2E test using the real Firebase JS SDK
#   3. the legacy verification scripts
# Requires Java 21+ (firebase-tools). Never contacts a real Firebase project.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@21 ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@21
  export PATH="$JAVA_HOME/bin:$PATH"
fi

firebase emulators:exec --only auth,firestore --project demo-agentshield '
  set -euo pipefail
  export GCLOUD_PROJECT=demo-agentshield
  unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_CLOUD_PROJECT_CONFIRM
  AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q

  AGENTSHIELD_ENV_FILE=/nonexistent AGENTSHIELD_TEST_MODE=1 FIREBASE_TARGET=emulator FIREBASE_PROJECT_ID=demo-agentshield ENVIRONMENT=development DATABASE_MODE=firestore \
    FIREBASE_AUTH_REQUIRED=true DEV_AUTH_IDENTITIES= \
    .venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --log-level warning &
  API_PID=$!
  trap "kill $API_PID 2>/dev/null || true" EXIT
  for _ in $(seq 1 60); do curl -sf http://127.0.0.1:8001/health >/dev/null && break; sleep 0.5; done
  (cd frontend && AGENTSHIELD_API_URL=http://127.0.0.1:8001 npx vitest run src/firebase/auth.emulator.test.ts)

  .venv/bin/python scripts/test_firebase_emulator_suite.py | grep -E "\[(PASS|FAIL)\]"
  .venv/bin/python scripts/test_e2e_frontend_backend.py | grep -E "\[(PASS|FAIL)\]"
'
