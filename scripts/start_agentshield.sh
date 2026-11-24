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
  npm --prefix frontend run dev -- --host 127.0.0.1 &
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
