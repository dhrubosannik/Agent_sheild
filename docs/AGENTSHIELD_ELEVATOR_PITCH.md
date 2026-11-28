# AgentShield Elevator Pitch

## 15 Seconds

AgentShield is a security gateway that evaluates AI-agent tool calls and blocks, redacts, or requires approval before sensitive actions execute.

## 30 Seconds

AgentShield protects AI-agent tool execution. It inspects tool arguments, destination, and sensitive data, applies deterministic policies, and prevents unsafe side effects. It also provides privacy-safe audit events and a live React dashboard.

## 60 Seconds

AI agents can read untrusted documents and propose tool calls that expose secrets or contact unsafe destinations. AgentShield places a Python SDK boundary before custom tools and evaluates each proposed action through a shared policy engine. It returns ALLOW, REDACT, REQUIRE_APPROVAL, or BLOCK. Safe tools execute, redacted tools receive sanitized arguments, approval actions pause, and blocked actions never execute. FastAPI and SQLite provide audit and approval APIs, while React displays real backend events.

## 2-Minute Technical Pitch

AgentShield is a lightweight execution-boundary MVP for AI-agent tool security. An SDK decorator or wrapper intercepts custom Python tool arguments and converts them into a Pydantic `ToolCall`. A shared policy engine normalizes the payload, classifies destinations, detects configured protected values and common credential patterns, and evaluates deterministic rules.

The project supports four outcomes: ALLOW executes original arguments; REDACT replaces sensitive values and executes the sanitized copy; REQUIRE_APPROVAL creates a pending approval record and performs no tool execution; and BLOCK prevents execution.

FastAPI exposes evaluation, audit, approval, policy, and demo APIs. SQLite stores metadata-only audit events and approval transitions. React provides a reference-console dashboard with live event and approval views. All demo actions use mock tools and synthetic data.

The project currently provides 142 passing pytest tests, a passing frontend build, and verified safe, malicious, redaction, and approval demo flows. It is demo-ready as a controlled local MVP. It is not production-ready because it lacks API authentication, cryptographic audit integrity, framework adapters, and approval execution/resumption.
