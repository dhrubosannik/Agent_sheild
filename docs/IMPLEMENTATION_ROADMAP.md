# Implementation Roadmap

Complete each phase and run its tests before starting the next.

## Phase 0 — Repository inspection and plan
Read all specification files, inspect the current workspace, identify conflicts, and produce a plan. Do not code until the user approves the plan.

## Phase 1 — Project scaffold
Create backend, SDK, tests, policies, examples, scenarios, and frontend directories. Add dependency files, configuration, `.gitignore`, and setup instructions.

## Phase 2 — Data models and policy loading
Create Pydantic models, policy schema, YAML loading, validation, and safe error behavior.

## Phase 3 — Security and policy engine
Implement normalization, destination classification, sensitive-data detection, heuristic signals, rule evaluation, decision precedence, and redaction.

## Phase 4 — SDK wrapper
Implement the decorator/wrapper and prove execution semantics for all four decisions.

## Phase 5 — Audit logging and API
Implement privacy-safe audit storage and FastAPI endpoints. Add API tests.

## Phase 6 — Demo agent and scenarios
Create the simulated vendor document and demo agent. Demonstrate benign ALLOW and malicious exfiltration BLOCK.

## Phase 7 — Dashboard
Build the overview, event detail, pending approvals, and demo controls. Connect only to real API data.

## Phase 8 — Integration and security regression
Run all tests, inspect logs for secret leakage, test domain spoofing, verify fail-closed behavior, and fix defects.

## Phase 9 — Demo readiness
Write a short runbook, reset procedure, expected screenshots, architecture explanation, limitations, and measured results.

## Definition of done
The demo works from a clean setup; the tests pass; unsafe tools are not executed; logs do not expose raw secrets; and the dashboard reflects actual backend decisions.
