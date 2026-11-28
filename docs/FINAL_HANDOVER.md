# AgentShield Final Handover

## Project Structure

- `backend/app`: FastAPI application, models, policy engine, SDK-facing services, audit storage
- `sdk/agentshield`: Python wrapper/decorator SDK
- `frontend/src`: React reference console
- `examples`: Mock tools, demo agent, vendor document
- `backend/tests` and `sdk/tests`: Regression suites
- `data`: Local SQLite database

## Technology Stack

- Python
- FastAPI
- Pydantic
- PyYAML
- SQLite
- pytest
- React
- Vite
- IBM Plex Mono
- Inter

## Startup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend install
./scripts/start_agentshield.sh
```

Backend: `http://127.0.0.1:8000`

Dashboard: `http://127.0.0.1:5173`

## Test Commands

```bash
.venv/bin/python -m pytest -q
npm --prefix frontend run build
```

## Demo Commands

```bash
.venv/bin/python examples/demo_agent.py --scenario safe
.venv/bin/python examples/demo_agent.py --scenario malicious
.venv/bin/python examples/demo_agent.py --scenario redaction
.venv/bin/python examples/demo_agent.py --scenario approval
.venv/bin/python examples/demo_agent.py --scenario all
```

## Important Configuration

- `backend/policies/default_policy.yaml`
- `.env.example`
- `frontend/.env.example`
- `scripts/start_agentshield.sh`
- `backend/app/core/config.py`

## Known Limitations

- No API authentication or authorization
- No cryptographic audit tamper evidence
- Prompt-injection detection is heuristic
- Unwrapped tools bypass the SDK
- Approval records do not resume execution
- Only custom Python tool integrations are implemented

## Next Developer

1. Add authentication and reviewer authorization before network exposure.
2. Add tamper-evident audit storage.
3. Add data-classification expansion.
4. Add explicit framework adapters.
5. Add approval resume as a separate, traceable mechanism only after approval security is implemented.
