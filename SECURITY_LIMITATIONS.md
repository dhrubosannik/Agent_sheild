# AgentShield Security Limitations

## Missing Authentication

The local MVP FastAPI API has no authentication or role-based authorization. It is not safe to expose publicly.

## Audit Integrity

SQLite audit records are not cryptographically chained or signed. They are privacy-safe but not tamper-evident.

## Prompt-Injection Detection

The heuristic detector is supplementary and imperfect. Deterministic destination and protected-data checks remain the primary enforcement mechanism.

## SDK Boundary

Only explicitly wrapped tools are protected. Calling an original unwrapped function directly bypasses AgentShield.

## Approval Workflow

Approval records do not resume or execute tools. Rejected and pending actions remain unexecuted.

## Production Requirements

Production deployment requires authentication, authorization, HTTPS, secure logging, audit integrity, policy update controls, secret management, and operational monitoring.
