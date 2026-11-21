# Project Overview

## Product
**AgentShield** is a lightweight security gateway that protects AI-agent workflows at the moment an agent attempts to use a tool.

## Problem
Untrusted web pages, documents, and retrieved content can contain indirect prompt-injection instructions. A manipulated agent may then use an otherwise legitimate tool to send secrets, customer data, or unsafe commands to an inappropriate destination.

## Proposed solution
Place a policy gateway in front of sensitive custom tools. Before the underlying tool executes, AgentShield inspects:
- Tool name and action type
- Destination and destination classification
- Payload content and sensitivity labels
- Policy configuration
- Risk signals, including suspicious instruction patterns

## Decisions
- `ALLOW`: execute the original tool call.
- `REDACT`: remove or mask configured sensitive values, then execute only the redacted payload.
- `REQUIRE_APPROVAL`: pause execution and create a pending approval record.
- `BLOCK`: do not execute the underlying tool.

## Primary users
Developers building support, research, HR, finance, and operations agents; security teams that need explainable records of proposed actions.

## MVP scope
- Python custom-tool wrapper/decorator
- FastAPI service
- Pydantic request/response models
- YAML/JSON policy rules
- Deterministic data and destination checks
- Basic heuristic prompt-injection risk signals
- Redacted JSONL or SQLite audit trail
- Small dashboard
- Synthetic scenario pack and automated tests

## Out of scope for MVP
- Full autonomous-agent platform
- Claiming perfect prompt-injection detection
- Production-grade identity management or enterprise approval integrations
- Framework adapters unless the custom-tool MVP is complete and tested

## Success criteria
A benign action is allowed; an unsafe exfiltration action is blocked; a configured redaction case is safely transformed; a high-impact action can require approval; and each decision creates a useful, privacy-conscious audit event.
