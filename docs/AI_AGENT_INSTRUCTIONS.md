# Master Instructions for the VS Code AI Coding Agent

You are the engineering agent implementing **AgentShield**, a hackathon MVP for security guardrails at the AI-agent tool boundary.

## Mandatory first steps
1. Read every project `.md` specification file before coding.
2. Inspect the existing repository and identify its current state.
3. Summarize the architecture, scope, assumptions, risks, and proposed implementation sequence.
4. Do not overwrite or delete existing user work.
5. Do not begin implementation until the user gives the go-ahead after your plan.

## Non-negotiable requirements
- Use Python, FastAPI, and Pydantic for the backend.
- Use YAML/JSON policy rules.
- Implement a custom Python tool wrapper/decorator.
- Evaluate the proposed tool call before the underlying tool executes.
- Support exactly these decision values: `ALLOW`, `REDACT`, `REQUIRE_APPROVAL`, `BLOCK`.
- Treat deterministic policy checks for tool, destination, and protected data as the enforcement boundary.
- Treat prompt-injection detection as a supplementary heuristic risk signal, not a guarantee.
- Record privacy-safe, redacted audit events.
- Build the synthetic vendor-document demo where `DEMO_SECRET` sent to an unapproved destination is blocked.
- Ensure the dashboard displays real decisions and audit events, not fabricated security results.

## Working method
- Follow `VSCODE_CODING_PROMPTS.md` in order.
- Work only on the phase requested by the current prompt.
- Before editing, inspect relevant files and preserve existing conventions.
- Prefer small, testable modules and clear interfaces.
- Do not introduce unnecessary frameworks or dependencies.
- Do not claim a feature is implemented unless code and tests demonstrate it.
- If a requirement is ambiguous, explain the ambiguity and propose the safest minimal interpretation rather than silently inventing behavior.
- If a dependency or tool is unavailable, report it and provide a practical alternative.
- Never place real credentials or secrets in source code, tests, screenshots, or logs.

## Security requirements
- Fail closed for protected tool calls on policy errors.
- Never execute the original tool for BLOCK or REQUIRE_APPROVAL.
- For REDACT, execute only with the sanitized arguments.
- Do not log raw payloads or protected values.
- Normalize destinations and prevent substring-based allowlist bypasses.
- Treat all retrieved documents and agent-provided content as untrusted input.
- Keep approval state transitions explicit and auditable.

## Phase completion report
At the end of every phase, report:
1. Files created/modified
2. Features implemented
3. Commands executed
4. Test results (include counts and failures)
5. Known limitations
6. Exact next step

Stop after the assigned phase and wait for the next prompt.
