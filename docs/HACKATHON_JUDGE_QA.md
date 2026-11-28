# AgentShield Judge Q&A

## 1. What is AgentShield?

AgentShield is a gateway that evaluates AI-agent tool calls before execution.

## 2. What problem does it solve?

Untrusted content can manipulate agents into exfiltrating protected data or invoking tools unsafely.

## 3. Why is it different from prompt filtering?

It protects the tool execution boundary, not only prompt text.

## 4. How does indirect prompt injection work?

An untrusted document contains instructions that may cause an agent to propose an unsafe tool call.

## 5. How does the SDK intercept calls?

The SDK wraps custom Python functions, extracts arguments, and evaluates them before invoking the original function.

## 6. How does policy evaluation work?

It normalizes arguments, classifies destinations, detects sensitive data, matches rules, and applies deterministic precedence.

## 7. How are destinations classified?

Approved domains match exactly or as subdomains; malformed and spoofed destinations do not match silently.

## 8. How is sensitive data detected?

The MVP supports configured exact values and basic API-key, bearer-token, and email-like patterns.

## 9. What decisions are supported?

ALLOW, REDACT, REQUIRE_APPROVAL, and BLOCK.

## 10. How does redaction work?

The SDK executes the original tool only with a sanitized copy of the arguments.

## 11. How does approval work?

The engine creates a pending approval record and does not execute the tool.

## 12. Does approval resume execution?

No. The MVP only changes approval status.

## 13. How are audit events created?

The SDK or evaluation API persists metadata-only events in SQLite.

## 14. What happens on evaluation failure?

Evaluation errors fail closed with a safe block-oriented result.

## 15. Can AgentShield detect every prompt injection?

No. Prompt-injection detection is heuristic; deterministic checks are the enforcement boundary.

## 16. Can developers bypass it?

Yes. Calling an original unwrapped function directly bypasses AgentShield.

## 17. What are the current limitations?

No API authentication, no cryptographically tamper-evident audit, no approval resume mechanism, and no framework adapters.

## 18. How was performance measured?

Local synthetic direct calls, SDK calls, policy evaluation, audit writes, API requests, and bounded concurrency.

## 19. What framework integrations exist?

Custom Python tools only. LangChain, CrewAI, and AutoGen are future work.

## 20. How can the system scale?

Use durable audit storage, authentication, policy administration, identity integration, and separate operational services.

## 21. What happens to blocked tools?

The original function is never invoked.

## 22. Are secrets stored in audit logs?

No raw payloads or protected canary values are intentionally stored.

## 23. Is this production-ready?

No. It is a local hackathon MVP.

## 24. What is the next milestone?

Authentication and authorization, followed by stronger audit integrity and framework adapters.
