# AgentShield Final Demo Validation

## Start the Application

```bash
cd /Users/abjorajbiswasmacbookair/Desktop/Programming/Agent_sheild
./scripts/start_agentshield.sh
```

The script reuses already-running services and starts only missing services.

## URLs

- Dashboard: http://127.0.0.1:5173
- Backend: http://127.0.0.1:8000
- Health: http://127.0.0.1:8000/health
- Swagger: http://127.0.0.1:8000/docs

## Safe Scenario

Expected:

- Decision: `ALLOW`
- Execution: `EXECUTED`
- Mock send-email call: 1

Actual:

- Live browser safe demo returned `ALLOW`
- Execution status `EXECUTED`
- Live audit ledger added an approved send-email event

## Malicious Scenario

Expected:

- Decision: `BLOCK`
- Execution: `NOT_EXECUTED`

Actual:

- Policy `block-secret-to-unapproved`
- Destination `UNAPPROVED`
- Protected data label present
- Mock send-email call count remained 0

## Redaction Scenario

Expected:

- Decision: `REDACT`
- Execution: `REDACTED_AND_EXECUTED`

Actual:

- Mock tool executed once with sanitized arguments
- Raw synthetic canary absent from audit metadata

## Approval Scenario

Expected:

- Decision: `REQUIRE_APPROVAL`
- Execution: `PENDING_APPROVAL`
- No mock export execution

Actual:

- Two pending approval records demonstrated
- Export mock call count 0
- Approval API can record APPROVED or REJECTED
- Approval status does not resume execution

## Reset Demo Data

Stop the backend before resetting:

```bash
rm -f data/agentshield.db data/agentshield.db-shm data/agentshield.db-wal
```

Then restart with the startup script.

Do not remove source files or policy configuration.

## Troubleshooting

- Port 8000 occupied: keep or stop the existing backend.
- Port 5173 occupied: keep or stop the existing frontend.
- Dashboard shows offline: verify `/health` and Vite proxy.
- No demo event appears: verify the backend database is reachable.
- Approval cannot be reviewed: verify the approval remains PENDING.
