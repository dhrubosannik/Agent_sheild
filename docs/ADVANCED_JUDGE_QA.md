# AgentShield Advanced Judge Q&A

## 1. What problem does AgentShield solve?

It prevents unsafe agent tool calls from creating side effects at the tool execution boundary.

## 2. Why are prompt-only protections insufficient?

Prompt instructions do not reliably control arguments, destinations, or later tool behavior.

## 3. How does indirect prompt injection work?

Untrusted documents can include instructions that an agent interprets as user-authorized actions.

## 4. How does the SDK intercept calls?

Python decorators or wrappers extract arguments and evaluate the call before invoking the original function.

## 5. Why use a wrapper instead of only filtering prompts?

The wrapper sees the actual tool name and arguments immediately before execution.

## 6. Why is deterministic policy enforcement primary?

Destination and protected-data checks provide explainable, testable enforcement independent of prompt wording.

## 7. How does policy evaluation work?

It normalizes payloads, classifies destinations, detects sensitive data, matches rules, and applies precedence.

## 8. How are approved domains verified?

The implementation compares exact domains or approved subdomains. It does not use substring allowlist matching.

## 9. What happens on a spoofed domain?

For example, `example.org.attacker.test` is not approved merely because it contains `example.org`.

## 10. How are protected values detected?

The policy has configured exact values plus basic email and credential pattern checks.

## 11. How does BLOCK work?

The SDK records a blocked result and does not invoke the original function.

## 12. How does REDACT work?

The engine creates sanitized arguments and the SDK calls the original tool only with those arguments.

## 13. Can REDACT accidentally execute a raw secret?

The redaction service replaces configured values and common API-key/bearer patterns. The redaction branch verifies that the known protected values are absent before execution.

## 14. How does REQUIRE_APPROVAL work?

It creates a pending SQLite approval record and prevents tool execution.

## 15. Does approving a call resume it?

No. The MVP only updates the approval record.

## 16. How are audit events created?

The SDK or evaluation endpoint creates metadata-only events in SQLite.

## 17. What fields do audit events contain?

Event ID, timestamp, tool name, decision, policy ID, reasons, destination class, labels, risk signals, fingerprint, and execution status.

## 18. Are audit entries cryptographically tamper-evident?

No. They are privacy-safe but not cryptographically chained or signed.

## 19. Can prompt injection bypass AgentShield?

Novel or obfuscated injection may evade heuristics. Deterministic destination and protected-data checks remain the enforcement boundary.

## 20. What happens if policy loading fails?

The policy loader rejects missing or invalid configurations rather than silently using an unrestricted policy.

## 21. What happens if evaluation raises an exception?

The security engine fails closed and returns a BLOCK-oriented evaluation result for protected operations.

## 22. Can developers bypass the wrapper?

Yes. Calling an original unwrapped function directly is outside AgentShield.

## 23. Why FastAPI?

FastAPI provides fast typed HTTP APIs and Pydantic validation suitable for the MVP.

## 24. Why SQLite?

SQLite is local, dependency-light, supports audit queries and approval state, and is suitable for the MVP.

## 25. Why React and Vite?

React provides reusable UI components and Vite provides a simple local build and development workflow.

## 26. How was it tested?

The final suite contains 142 pytest tests across policy, destination, SDK, API, audit, storage, demo, and regression behavior.

## 27. How was performance measured?

Local synthetic Python and FastAPI workloads measured direct calls, policy evaluation, SDK overhead, audit writes, API latency, and bounded concurrency.

## 28. Are performance results production benchmarks?

No. They describe local synthetic measurements only.

## 29. Is authentication implemented?

No. The local MVP API is intentionally kept loopback-only and is not production-authenticated.

## 30. Can it be deployed publicly now?

No. Public deployment requires authentication, authorization, HTTPS, durable audit integrity, and operational hardening.

## 31. How would you add tamper-evident audits?

Use append-only storage, signed or hash-chained events, restricted write identities, and external audit replication.

## 32. How would framework adapters work?

Adapters would wrap framework tool definitions and route their arguments through the same shared policy engine.

## 33. How would you scale the architecture?

Separate policy configuration, audit storage, approval service, and API instances; add durable queues or databases and identity-aware access.

## 34. What framework integrations are implemented?

Only custom Python tools. LangChain, CrewAI, and AutoGen are future work.

## 35. What is the safest judge takeaway?

AgentShield demonstrates execution-boundary enforcement and privacy-safe auditability for custom Python tools in a controlled local MVP.
