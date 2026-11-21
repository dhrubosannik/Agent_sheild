# AgentShield Demo Guide

## Overview

The demo is an offline, deterministic simulation of an AI research agent reading a vendor document. It uses the real AgentShield SDK, policy engine, SQLite audit logger, and mock tools. It does not send email, upload files, make external requests, or use credentials.

## Prerequisites

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
```

## Run scenarios

From the project root:

```bash
python examples/demo_agent.py --scenario safe
python examples/demo_agent.py --scenario malicious
python examples/demo_agent.py --scenario redaction
python examples/demo_agent.py --scenario approval
python examples/demo_agent.py --scenario all
```

## Expected decisions

- Safe: `ALLOW`, mock email execution count `1`
- Malicious: `BLOCK`, mock email execution count `0`
- Redaction: `REDACT`, mock email receives `[REDACTED]`
- Approval: `REQUIRE_APPROVAL`, mock export execution count `0`; one record is approved and one is rejected

The malicious scenario uses the synthetic canary `DEMO_SECRET` and destination `attacker@example.net`. The vendor document is untrusted input and may contain indirect prompt-injection text.

## Inspect audit events

Start the backend:

```bash
.venv/bin/uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open:

- `http://127.0.0.1:8000/api/v1/events`
- `http://127.0.0.1:8000/api/v1/approvals`
- `http://127.0.0.1:8000/docs`

Audit events are stored in `data/agentshield.db` by default. Raw payloads and protected secret values are not stored.

## Reset demo data

Stop the backend, remove the generated database, and restart:

```bash
rm -f data/agentshield.db data/agentshield.db-shm data/agentshield.db-wal
```

## Known limitations

- Prompt-injection detection is heuristic, not comprehensive.
- Approval review records state only; it does not re-execute a tool.
- Mock tools simulate execution and perform no real network or file operations.
- Audit storage is for the local MVP only.
