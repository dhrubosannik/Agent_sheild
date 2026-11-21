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
