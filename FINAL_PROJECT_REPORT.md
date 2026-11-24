# AgentShield Final Project Report

## Project Introduction

AgentShield is a lightweight security gateway that evaluates AI-agent tool calls before sensitive tools execute.

## Problem Statement

Untrusted documents can manipulate agents into transmitting protected data or calling tools against inappropriate destinations. Prompt-only filtering is insufficient because enforcement must cover the actual tool call.

## Proposed Solution

AgentShield combines a Python SDK wrapper, deterministic policy engine, destination classification, protected-data detection, optional heuristic risk signals, privacy-safe audit storage, approval records, FastAPI APIs, and a React dashboard.

## Core Features

- Custom Python tool protection
- Deterministic policy precedence
- Exact and subdomain approved-destination matching
- Configured protected-value detection
- API-key and bearer-token pattern blocking
- Redaction before tool execution
- Pending approval records
- SQLite audit events
- Offline demo scenarios
- Live-data security dashboard

## System Architecture

```text
Agent/Application
  -> AgentShield SDK wrapper
  -> argument normalization
  -> destination and sensitive-data inspection
  -> deterministic policy evaluation
  -> execution decision
  -> mock/tool execution only when permitted
  -> privacy-safe SQLite audit event
  -> FastAPI APIs
  -> React dashboard
```

## Technologies

- Python
- FastAPI
- Pydantic
- PyYAML
- SQLite
- pytest
- React
- Vite
- IBM Plex Mono and Inter

## Demonstration Scenarios

- Safe approved email: `ALLOW`
- Secret exfiltration to an unapproved destination: `BLOCK`
- Protected approved audit message: `REDACT`
- External export: `REQUIRE_APPROVAL`

## Testing and Performance

- Full pytest suite: 140 passed
- Frontend production build: passed
- All four demo scenarios: passed
- Raw local audit database `DEMO_SECRET` hits: 0
- Policy evaluation average: 0.021 ms
- Protected SDK call average: 0.035 ms
- Audit write average: 0.494 ms
- FastAPI evaluation average: 3.003 ms

## Known Limitations

- No authentication or authorization
- SQLite audit storage is not cryptographically tamper-evident
- Prompt-injection detection is heuristic
- Approval records do not resume tool execution
- SDK protection applies only to explicitly wrapped tools
- Framework adapters beyond custom Python tools are not implemented

## Conclusion

AgentShield is demo-ready as a synthetic local MVP and is not production-ready.

## Final Readiness Assessment

- Overall demo readiness: **DEMO READY**
- Backend readiness: **DEMO READY**
- Frontend readiness: **DEMO READY**
- SDK readiness: **DEMO READY**
- Security readiness: **PARTIALLY DEMO READY**
- Testing readiness: **DEMO READY**
- Documentation readiness: **DEMO READY**
- Deployment readiness: **NOT PRODUCTION READY**

The project is ready for controlled local hackathon demonstration. It must not be exposed as a public unauthenticated service.
