# AgentShield — Hackathon Presentation

Format: 16:9 slide specification

---

## Slide 1 — AgentShield

**A Security Gateway for AI Agent Tool Execution**

Environment: HAXTHON / PROD-SANDBOX

---

## Slide 2 — The Problem

- AI agents call tools.
- Agents consume untrusted documents and retrieved content.
- Malicious instructions can alter proposed tool calls.
- Sensitive data can reach unauthorized destinations.
- Prompt-only filtering is not an execution boundary.

---

## Slide 3 — Realistic Attack Scenario

1. A research agent reads a vendor document.
2. The document instructs it to reveal `DEMO_SECRET`.
3. It proposes sending an external email.
4. Without enforcement, the underlying tool could execute.

No real secret or external service is used in the demo.

---

## Slide 4 — Our Solution

AgentShield evaluates a proposed tool call before the original tool executes.

- ALLOW
- BLOCK
- REDACT
- REQUIRE_APPROVAL

---

## Slide 5 — Architecture

```text
Agent / Application
        |
AgentShield Python SDK
        |
Argument Normalization
        |
Destination + Sensitive-Data Inspection
        |
Deterministic Policy Engine
        |
Execution Decision
        |
Permitted Tool / No Execution / Pending Approval
        |
Privacy-Safe Audit Logging
        |
FastAPI + React Dashboard
```

---

## Slide 6 — Execution Flow

1. SDK intercepts arguments.
2. Pydantic validates the tool call.
3. Destination and sensitive data are inspected.
4. Policy precedence determines a decision.
5. The SDK executes, redacts, pauses, or blocks.
6. A metadata-only audit event is stored.

---

## Slide 7 — Four Security Decisions

- **ALLOW:** execute original arguments
- **BLOCK:** never invoke original tool
- **REDACT:** invoke original tool with sanitized arguments
- **REQUIRE_APPROVAL:** create pending record and do not execute

---

## Slide 8 — Technology Stack

- Python
- FastAPI
- Pydantic
- PyYAML
- SQLite
- Python SDK
- pytest
- React
- Vite

---

## Slide 9 — Live Demonstration

1. Safe approved email
2. Secret exfiltration attempt
3. Sensitive-data redaction
4. External export approval

---

## Slide 10 — Security and Audit Dashboard

Show the reference console:

- Live events
- Security decisions
- Tool and destination fields
- Policy metadata
- Payload fingerprint
- Pending approvals
- Demo scenario controls

All metrics and events come from backend data.

---

## Slide 11 — Testing and Performance

- 142 pytest tests passed
- Frontend production build passed
- All four CLI demo scenarios passed
- Live health and events API checks passed
- Local synthetic policy p50/p95 and SDK overhead measured
- No claim of production throughput

---

## Slide 12 — Limitations

- API authentication and authorization not implemented
- SQLite audit records not cryptographically tamper-evident
- Prompt-injection detection is heuristic
- SDK applies only to wrapped tools
- Approval records do not resume execution
- Framework adapters are future work

---

## Slide 13 — Future Roadmap

- Authentication and reviewer authorization
- Signed or hash-chained audit logs
- Better sensitive-data classification
- Secure approval resume workflow
- LangChain adapter
- CrewAI adapter
- AutoGen adapter
- Production deployment hardening

---

## Slide 14 — Why It Matters

AgentShield protects the point where an agent can create a real side effect.

- Explainable decisions
- Deterministic enforcement
- Safe payload redaction
- Privacy-safe audit visibility
- Backend-controlled demo behavior

---

## Slide 15 — Closing

**AgentShield: Security Before Execution**

Q&A
