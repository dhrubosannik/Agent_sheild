# AgentShield Live Demo Narration

## Before Starting

Start:

```bash
./scripts/start_agentshield.sh
```

Open:

- Dashboard: http://127.0.0.1:5173
- Health: http://127.0.0.1:8000/health

Reset:

```bash
rm -f data/agentshield.db data/agentshield.db-shm data/agentshield.db-wal
```

Restart both services after resetting.

## Scenario 1 — Safe

**Say:** “This call sends a benign vendor summary to an approved destination.”

**Action:** Click Run Safe Scenario.

**Expected:** `ALLOW`, `EXECUTED`, mock send-email count 1.

**Observe:** The dashboard shows an allowed event and updated ledger.

**Concept:** Approved destinations and clean payloads permit execution.

## Scenario 2 — Malicious

**Say:** “The vendor document contains a malicious instruction to exfiltrate a synthetic secret.”

**Action:** Click Run Malicious Scenario.

**Expected:** `BLOCK`, `NOT_EXECUTED`, mock send-email count 0.

**Observe:** The event includes `PROTECTED_DATA`, `UNAPPROVED_DESTINATION`, and policy `block-secret-to-unapproved`.

**Concept:** Deterministic data and destination checks prevent side effects.

## Scenario 3 — Redaction

**Say:** “This payload is sensitive, but an explicit redaction rule permits a sanitized copy.”

**Action:** Click Run Redaction Scenario.

**Expected:** `REDACT`, `REDACTED_AND_EXECUTED`.

**Observe:** The mock tool receives `[REDACTED]` instead of the original canary.

**Concept:** Sanitized arguments reach the tool, not raw protected values.

## Scenario 4 — Approval

**Say:** “This external export is not executed automatically. It creates an approval record.”

**Action:** Click Run Approval Scenario, then open Approvals.

**Expected:** `REQUIRE_APPROVAL`, `PENDING_APPROVAL`, mock export count 0.

**Observe:** Approve or reject the record.

**Concept:** Approval is a separate record-management workflow. The MVP does not resume execution after approval.

## Backup CLI Procedure

```bash
.venv/bin/python examples/demo_agent.py --scenario safe
.venv/bin/python examples/demo_agent.py --scenario malicious
.venv/bin/python examples/demo_agent.py --scenario redaction
.venv/bin/python examples/demo_agent.py --scenario approval
```

Use if dashboard controls are unavailable.
