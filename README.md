# AgentShield — AI Agent Tool-Call Security Gateway

AgentShield is a lightweight security gateway that evaluates AI-agent tool calls before sensitive tools execute. It is a hackathon MVP focused on deterministic policy enforcement, privacy-safe audit events, and explainable decisions.

## Technology stack

- Python 3.11+
- FastAPI
- Pydantic
- YAML policy configuration
- SQLite or JSONL audit storage planned for later phases
- React with Vite for the dashboard
- pytest

## Initial setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
cp .env.example .env
```

Frontend preparation:

```bash
cd frontend
npm install
npm run build
```

## Run the backend

From the project root:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Health endpoint:

```text
http://127.0.0.1:8000/health
```

## Run the complete application

After backend dependencies and frontend packages are installed:

```bash
chmod +x scripts/start_agentshield.sh
./scripts/start_agentshield.sh
```

The dashboard is available at `http://127.0.0.1:5173` and the API at `http://127.0.0.1:8000`.

## Directory structure

```text
backend/
  app/
    api/
    models/
    core/
    services/
    storage/
  policies/
  tests/
sdk/
  agentshield/
  tests/
frontend/
examples/
scenarios/
data/
```

## Security boundary

Deterministic tool, destination, and protected-data checks are the primary enforcement mechanism. Prompt-injection detection is supplementary and imperfect. No tool should execute before the gateway decision.

## Dashboard theme

The dashboard includes a reference-style security console with light and dark themes, IBM Plex Mono and Inter typography, and live AgentShield event data.

## Documentation

All project documentation lives in [`docs/`](docs/). Start with the [documentation index](docs/README.md). Key documents:

- [Firebase development guide](docs/FIREBASE_DEVELOPMENT_GUIDE.md): no-Firebase, emulator and shared-cloud modes
- [Shared Firebase team setup](docs/FIREBASE_SHARED_TEAM_SETUP.md)
- [Phase 13.2 security remediation report](docs/PHASE_13_2_SECURITY_REMEDIATION_REPORT.md)
- [Shared Firebase connection report](docs/SHARED_FIREBASE_CONNECTION_REPORT.md)
- [Remaining risks](docs/REMAINING_RISKS.md)
- [API documentation](docs/API_DOCUMENTATION.md)
