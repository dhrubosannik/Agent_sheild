# AgentShield Hackathon Demo Script

Target duration: 5–7 minutes.

## 1. Introduction — 45 seconds

Say:

"AI agents can read untrusted documents and then call tools. Checking only the initial prompt is not enough. AgentShield evaluates the actual tool call before it executes."

Show the dashboard and explain the left scenario panel, center interceptor and ledger, and right telemetry panel.

## 2. Safe Scenario — 1 minute

- Open Demo Scenarios.
- Run Safe Scenario.
- Explain that the approved destination and clean payload pass policy.

Show:

- `ALLOW`
- `EXECUTED`
- Corresponding audit event

## 3. Malicious Scenario — 90 seconds

- Open `examples/sample_vendor_document.txt`.
- Identify the embedded instruction as untrusted content.
- Run Malicious Scenario.

Show:

- Unapproved destination
- Protected data detection
- `block-secret-to-unapproved`
- `BLOCK`
- `NOT_EXECUTED`

Never reveal a raw canary value in the dashboard or presentation.

## 4. Redaction — 60 seconds

- Run Redaction Scenario.
- Explain that the applicable policy replaces protected data before the mock tool executes.

Show:

- `REDACT`
- `REDACTED_AND_EXECUTED`
- Sanitized tool argument
- Redacted audit metadata

## 5. Human Approval — 75 seconds

- Run Approval Scenario.
- Open Approvals.
- Approve or reject one record.

Explain:

"This MVP records the approval decision. It does not automatically resume or execute the original tool."

Show:

- `REQUIRE_APPROVAL`
- `PENDING_APPROVAL`
- Updated approval status
- Export mock remains unexecuted

## 6. Architecture — 60 seconds

Explain:

- Python SDK wrapper
- FastAPI backend
- Pydantic validation
- Shared policy engine
- Destination and sensitive-data checks
- SQLite audit storage
- React dashboard

## Backup

If the dashboard is unavailable:

```bash
.venv/bin/python examples/demo_agent.py --scenario all
```
