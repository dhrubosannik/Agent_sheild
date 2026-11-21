# Sequential VS Code AI Coding Prompts

Use these prompts one at a time. Do not paste all prompts together. The agent must have read `AI_AGENT_INSTRUCTIONS.md` and all specification files first.

---

## Prompt 0 — Read and plan (no coding)

Read `AI_AGENT_INSTRUCTIONS.md` and every other project `.md` file in this workspace. Inspect the existing repository. Do not write or modify code yet. Summarize the product, architecture, trust boundaries, MVP scope, proposed folder structure, key interfaces, risks, and phase plan. Identify contradictions or missing decisions. Wait for my approval.

## Prompt 1 — Scaffold

Implement only Phase 1 from `IMPLEMENTATION_ROADMAP.md`. Create the agreed project structure, Python environment/dependency files, `.gitignore`, and concise setup instructions. Do not implement policy logic yet. Run basic import/startup checks and report changed files and results. Stop.

## Prompt 2 — Models and policy loading

Implement only the data models and policy-loading portion of Phase 2. Define typed Pydantic models for proposed tool calls, decisions, evaluation results, policy rules, audit events, and approval records. Load and validate the YAML/JSON policy configuration. Add tests for valid and invalid policy files. Do not implement the complete evaluator yet. Stop after tests and report.

## Prompt 3 — Security and policy engine

Implement Phase 3. Build reusable services for argument normalization, safe destination classification, protected-data detection, optional prompt-injection risk signals, deterministic policy matching, documented decision precedence, and safe redaction. Ensure an explicit deny cannot be overridden by a broad allow. Fail closed on evaluation errors. Add focused unit tests, including a spoofed-domain case. Do not build the UI. Stop after tests and report.

## Prompt 4 — Python SDK wrapper

Implement Phase 4. Create a clean Python decorator or wrapper around custom tool functions. The wrapper must evaluate arguments before invoking the original function. ALLOW invokes with original arguments; REDACT invokes only with sanitized arguments; REQUIRE_APPROVAL and BLOCK never invoke the original function. Add tests using a call counter or mock to prove these behaviors. Provide a small usage example. Stop after tests and report.

## Prompt 5 — Audit logging and FastAPI

Implement Phase 5. Add privacy-safe JSONL or SQLite audit storage and the FastAPI endpoints in `API_DOCUMENTATION.md`. Keep route handlers thin and reuse the shared policy engine. Ensure raw `DEMO_SECRET` and raw sensitive payloads never appear in audit records or API event responses. Add API and audit privacy tests. Stop after tests and report.

## Prompt 6 — Demo scenario

Implement Phase 6. Create a synthetic vendor document containing an indirect prompt-injection attempt and a simulated agent that proposes sending `DEMO_SECRET` to an unapproved external address. Also create a benign approved-destination scenario. Demonstrate that the benign action is ALLOW and the exfiltration attempt is BLOCKED before the mock tool runs. Record the decisions in the audit store. Use synthetic data only. Stop after running the demo and tests.

## Prompt 7 — Dashboard

Implement Phase 7. Build the minimal professional dashboard described in `FRONTEND_SPECIFICATION.md`. Show decision counts, recent events, event details, pending approvals, and controls to run the two demo scenarios. Connect to the real backend. Do not fabricate metrics or display raw payloads/secrets. Include loading, empty, and error states. Run available frontend checks and stop.

## Prompt 8 — Integration

Integrate SDK, backend, audit storage, demo agent, and dashboard. Verify the complete workflow from a clean start. Fix interface mismatches without duplicating policy logic. Document exact commands to start each component. Stop and report.

## Prompt 9 — Security regression and performance

Run the complete test suite and the security scenarios in `TESTING_STRATEGY.md`. Specifically verify fail-closed behavior, destination spoofing resistance, tool non-execution on BLOCK/REQUIRE_APPROVAL, redaction correctness, and audit privacy. Measure p50/p95 evaluation overhead if practical. Fix issues and rerun tests. Do not exaggerate results. Stop and report.

## Prompt 10 — Hackathon demo readiness

Prepare a concise demo runbook: prerequisites, setup, startup commands, demo sequence, expected decisions, where to view audit events, reset instructions, architecture explanation, limitations, and likely judge questions with factual answers. Verify every command on the current project. Do not claim unsupported integrations or production readiness. Stop after delivering the runbook.

---

## Prompt discipline
After each phase, review the agent's completion report. If tests fail, ask it to fix the failures before moving forward. Commit or back up working milestones before large changes. Keep the scope focused on a reliable custom-tool MVP.
