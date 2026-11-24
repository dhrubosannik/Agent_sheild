# AgentShield Technical Architecture

## Components

### Python SDK

The SDK provides `protect_tool` and direct `wrap` APIs. It extracts function arguments, creates a `ToolCall`, evaluates it through the shared policy engine, and controls execution of the original function.

### Policy Engine

The engine normalizes arguments, classifies destinations, detects configured protected values and credential patterns, matches policy rules, and applies deterministic precedence.

### FastAPI

FastAPI exposes health, evaluation, event, approval, policy, and demo routes. Route handlers remain thin and business logic stays in services.

### SQLite

SQLite stores audit events and approval records. Audit events contain metadata and payload fingerprints, not raw payloads or protected values.

### React Dashboard

The dashboard reads backend events, approvals, policy data, and demo results. It does not implement security decisions in the browser.

## Tool Interception Flow

```text
Agent proposes tool call
  -> SDK extracts arguments
  -> shared policy engine evaluates
  -> destination classified
  -> sensitive data detected
  -> deterministic decision returned
  -> SDK executes, redacts, pauses, or blocks
  -> privacy-safe audit event recorded
```

## Trust Boundaries

- Agent arguments are untrusted
- Retrieved documents are untrusted data
- Policy configuration is trusted local configuration
- Raw payloads are not stored in audit records
- Only explicitly wrapped tools are protected
