# Running AgentShield

## Prerequisites

- Python 3.11 or newer
- Node.js and npm
- A POSIX shell

## Setup

From the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend install
cp .env.example .env
cp frontend/.env.example frontend/.env
```

`frontend/.env` may leave `VITE_API_BASE_URL` empty because Vite proxies `/api` and `/health` to the local backend.

## Start both services

```bash
chmod +x scripts/start_agentshield.sh
./scripts/start_agentshield.sh
```

Stop both services with `Ctrl+C`.

The script reuses a backend or dashboard already listening on ports 8000 or 5173. It starts only missing services and stops only services that it started itself.

## Start services separately

Backend:

```bash
.venv/bin/uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend:

```bash
npm --prefix frontend run dev -- --host 127.0.0.1
```

## URLs

- Dashboard: http://127.0.0.1:5173
- API health: http://127.0.0.1:8000/health
- Swagger API: http://127.0.0.1:8000/docs
- Audit events: http://127.0.0.1:8000/api/v1/events
- Approvals: http://127.0.0.1:8000/api/v1/approvals

## Demo scenarios

CLI:

```bash
.venv/bin/python examples/demo_agent.py --scenario safe
.venv/bin/python examples/demo_agent.py --scenario malicious
.venv/bin/python examples/demo_agent.py --scenario redaction
.venv/bin/python examples/demo_agent.py --scenario approval
.venv/bin/python examples/demo_agent.py --scenario all
```

Or use the Demo Scenarios page in the dashboard.

## Reset local data

Stop the backend before resetting:

```bash
rm -f data/agentshield.db data/agentshield.db-shm data/agentshield.db-wal
```
