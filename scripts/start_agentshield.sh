#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${FRONTEND_PID:-}" ]]; then
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

.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

npm --prefix frontend run dev -- --host 127.0.0.1 &
FRONTEND_PID=$!

echo "AgentShield backend: http://127.0.0.1:8000"
echo "AgentShield dashboard: http://127.0.0.1:5173"
echo "Press Ctrl+C to stop both services."

wait
