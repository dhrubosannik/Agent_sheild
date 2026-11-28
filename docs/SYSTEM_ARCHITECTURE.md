# System Architecture

## High-level flow

```text
Agent / Application
       |
       v
AgentShield Python SDK (wrapper/decorator)
       |
       v
Normalize proposed tool call
       |
       v
Policy Engine <---- YAML/JSON policy configuration
       |
       +--> Sensitive-data inspection
       +--> Destination classification
       +--> Tool/action policy checks
       +--> Risk signals (heuristics)
       |
       v
Decision: ALLOW / REDACT / REQUIRE_APPROVAL / BLOCK
       |
       +--> ALLOW/REDACT: execute wrapped tool (redacted payload for REDACT)
       +--> REQUIRE_APPROVAL: do not execute; create pending approval
       +--> BLOCK: do not execute
       |
       v
Audit Logger (redacted event)
       |
       v
FastAPI + Dashboard for inspection and approval workflow
```

## Components
1. **SDK layer:** Python decorator or wrapper intercepts tool calls before the original function runs.
2. **Normalization layer:** Converts inputs into a consistent internal representation.
3. **Policy engine:** Evaluates deterministic rules and produces a decision plus reasons.
4. **Inspection layer:** Detects configured sensitive values/labels and classifies destinations.
5. **Risk signal layer:** Adds heuristic signals for suspicious instructions; these signals are not the sole security boundary.
6. **Execution layer:** Runs the original tool only when the decision permits it.
7. **Audit layer:** Stores decision metadata without storing raw secrets.
8. **API/dashboard:** Displays decisions, policies, event details, and pending approvals.

## Trust boundaries
- Agent-generated tool arguments are untrusted.
- Retrieved documents and web content are untrusted data, not instructions to AgentShield.
- Policy configuration is trusted only when loaded from the configured local policy source and validated.
- The original tool must never run before the gateway decision.
- Audit records must not contain raw secret values or full sensitive payloads.

## Failure behavior
Default to **fail closed** for protected actions if policy evaluation fails, policy configuration is invalid, or the audit requirement cannot be satisfied. Make this behavior explicit and configurable only through a deliberate, documented setting. Never silently execute on an internal error.
