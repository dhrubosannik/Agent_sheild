#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

cleanup() {
  if [[ -n "${BACKEND_PID:-}" && "${BACKEND_STARTED:-false}" == "true" ]]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${FRONTEND_PID:-}" && "${FRONTEND_STARTED:-false}" == "true" ]]; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -x ".venv/bin/uvicorn" ]]; then
  echo "Missing .venv. Create it and install backend/requirements.txt first."
  exit 1
fi

if [[ ! -d "frontend/node_modules" ]]; then
  echo "Missing frontend/node_modules. Run: npm --prefix frontend install"
  exit 1
fi

# Profile: none (default, no Firebase) | emulator | cloud.
#   AGENTSHIELD_PROFILE=emulator ./scripts/start_agentshield.sh   (start emulators first)
#   AGENTSHIELD_PROFILE=cloud    ./scripts/start_agentshield.sh   (shared project, real data)
PROFILE="${AGENTSHIELD_PROFILE:-none}"
FRONTEND_SCRIPT="dev"
case "$PROFILE" in
  none)
    # Explicit local identities (loopback-only, refused in production).
    if [[ -z "${DEV_AUTH_IDENTITIES:-}" ]] && ! grep -qs '^DEV_AUTH_IDENTITIES=' .env; then
      export DEV_AUTH_IDENTITIES="local-admin:ADMIN,local-reviewer:REVIEWER,local-viewer:VIEWER"
    fi
    if [[ -z "${VITE_DEV_IDENTITY:-}" ]] && ! grep -qs '^VITE_DEV_IDENTITY=' frontend/.env frontend/.env.local; then
      export VITE_DEV_IDENTITY="local-admin"
    fi
    ;;
  emulator|cloud)
    export AGENTSHIELD_ENV_FILE=".env.$PROFILE"
    FRONTEND_SCRIPT="dev:$PROFILE"
    for file in "$AGENTSHIELD_ENV_FILE" "frontend/.env.$PROFILE"; do
      if [[ ! -f "$file" ]]; then
        echo "Missing $file. Copy it from $file.example and fill it in (see FIREBASE_DEVELOPMENT_GUIDE.md)."
        exit 1
      fi
    done
    if [[ "$PROFILE" == "cloud" ]]; then
      unset FIREBASE_AUTH_EMULATOR_HOST FIRESTORE_EMULATOR_HOST
      echo "WARNING: connecting to the SHARED cloud Firebase project. Reads and writes are real."
    fi
    .venv/bin/python scripts/check_firebase_config.py || exit 1
    ;;
  *)
    echo "AGENTSHIELD_PROFILE must be none, emulator or cloud."
    exit 1
    ;;
esac

if curl --fail --silent "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
  echo "Backend already running: http://127.0.0.1:8000"
else
  .venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 &
  BACKEND_PID=$!
  BACKEND_STARTED=true
fi

if curl --fail --silent "http://127.0.0.1:5173/" >/dev/null 2>&1; then
  echo "Dashboard already running: http://127.0.0.1:5173"
else
  npm --prefix frontend run "$FRONTEND_SCRIPT" -- --host 127.0.0.1 &
  FRONTEND_PID=$!
  FRONTEND_STARTED=true
fi

for _ in {1..30}; do
  BACKEND_READY=false
  FRONTEND_READY=false
  curl --fail --silent "http://127.0.0.1:8000/health" >/dev/null 2>&1 && BACKEND_READY=true
  curl --fail --silent "http://127.0.0.1:5173/" >/dev/null 2>&1 && FRONTEND_READY=true
  if [[ "$BACKEND_READY" == "true" && "$FRONTEND_READY" == "true" ]]; then
    break
  fi
  sleep 0.2
done

if ! curl --fail --silent "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
  echo "Backend did not become ready on http://127.0.0.1:8000"
  exit 1
fi
if ! curl --fail --silent "http://127.0.0.1:5173/" >/dev/null 2>&1; then
  echo "Dashboard did not become ready on http://127.0.0.1:5173"
  exit 1
fi

echo "AgentShield backend: http://127.0.0.1:8000"
echo "AgentShield dashboard: http://127.0.0.1:5173"
echo "Press Ctrl+C to stop both services."

wait
