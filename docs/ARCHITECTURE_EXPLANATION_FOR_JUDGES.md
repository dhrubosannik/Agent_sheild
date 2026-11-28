# AgentShield Architecture Explanation for Judges

## Simple Explanation

AgentShield stands between an AI agent and a tool. Before a tool runs, AgentShield asks: “Is this action safe?” It can allow it, hide sensitive values, pause it for approval, or stop it.

## Intermediate Explanation

The Python SDK receives the proposed function call. It normalizes arguments and asks the policy engine about the destination, protected data, tool name, and configured rules. The SDK then executes or prevents the original function accordingly. FastAPI provides health, evaluation, event, policy, and approval APIs. SQLite stores audit metadata and approval records. React displays real backend results.

## Detailed Explanation

### Component Responsibilities

- SDK: intercept tool calls and apply execution decisions
- Policy engine: normalize, inspect, match, and decide
- Destination classifier: recognize approved, internal, unapproved, unknown targets
- Sensitive-data detector: identify configured values and common credential patterns
- Redaction service: produce sanitized argument copies
- Audit service: persist metadata-only events
- Approval repository: manage explicit approval status transitions
- FastAPI: expose controlled local APIs
- React: show backend-derived security state

### Tool-Call Lifecycle

```text
Agent tool proposal
  -> SDK argument extraction
  -> Pydantic ToolCall validation
  -> normalization
  -> destination classification
  -> sensitive-data detection
  -> heuristic risk signals
  -> deterministic policy evaluation
  -> ALLOW / REDACT / REQUIRE_APPROVAL / BLOCK
  -> conditional tool execution
  -> privacy-safe audit event
```

### Integration Boundaries

The policy engine is shared between the SDK and API. The SDK is the execution boundary for custom Python tools. The dashboard does not evaluate security decisions itself.

### Current Limitations

- No API authentication or authorization
- No cryptographic audit integrity
- Heuristic prompt-injection detection
- Wrapped-tool-only enforcement
- Approval-record management without automatic execution resume
- No production framework adapters
