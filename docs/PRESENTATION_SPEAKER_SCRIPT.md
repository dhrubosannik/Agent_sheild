# AgentShield Presentation Speaker Script

Target duration: 8–10 minutes.

## Slide 1 — Title

**Say:** “AgentShield is a security gateway for AI-agent tool execution. It makes agent actions explainable, controlled, and auditable before sensitive tools run.”

**Technical follow-up:** AgentShield is a custom-Python SDK and FastAPI MVP, not a framework claim or production security platform.

**Transition:** “The reason this boundary matters is that agents increasingly act through tools.”

**Time:** 35 seconds.

## Slide 2 — The Problem

**Say:** “An agent can read an external document, web page, or retrieved record. That content may contain indirect instructions that appear relevant but are not authorized by the user.”

**Simple explanation:** Prompt filtering alone is not enough because the final risk exists in the tool call and destination.

**Technical follow-up:** Retrieved content is untrusted data, while the tool call is the execution boundary.

**Transition:** “Here is what that looks like in practice.”

**Time:** 45 seconds.

## Slide 3 — Attack Scenario

**Say:** “A simulated research agent reads a vendor document. The document tries to instruct the agent to retrieve DEMO_SECRET and send it to an unapproved external address.”

**Technical follow-up:** The demo uses only synthetic content and a mock email tool.

**Transition:** “AgentShield prevents that proposed action before the tool executes.”

**Time:** 45 seconds.

## Slide 4 — Solution

**Say:** “AgentShield evaluates the proposed tool call and returns one of four decisions: ALLOW, BLOCK, REDACT, or REQUIRE_APPROVAL.”

**Four-decision explanation:**

- ALLOW executes permitted arguments.
- BLOCK prevents execution.
- REDACT executes sanitized arguments.
- REQUIRE_APPROVAL pauses execution and creates a review record.

**Transition:** “The system is organized around a small set of cooperating components.”

**Time:** 45 seconds.

## Slide 5 — Architecture

**Say:** “The agent proposes a tool call through the SDK wrapper. AgentShield normalizes arguments, inspects destination and sensitive data, applies deterministic policy, creates an execution decision, and records audit metadata.”

**Technical follow-up:** FastAPI exposes evaluation and inspection APIs. SQLite stores audit and approval records. React reads backend data.

**Transition:** “The execution flow is intentionally simple.”

**Time:** 60 seconds.

## Slide 6 — How It Works

**Say:** “First, the SDK intercepts arguments. Second, AgentShield normalizes and inspects them. Third, the policy engine decides. Fourth, the SDK applies the decision.”

**Technical follow-up:** Blocked and approval-required calls never invoke the original function. Redacted calls invoke it with sanitized arguments only.

**Transition:** “This gives judges a clear explanation for every outcome.”

**Time:** 50 seconds.

## Slide 7 — Four Security Decisions

**Say:** “ALLOW is the clean approved path. BLOCK is protected data or a denied destination. REDACT removes configured or patterned sensitive values. REQUIRE_APPROVAL creates a pending review and does not execute.”

**Technical follow-up:** Precedence is documented and tested. Prompt-injection signals are supplementary, not the sole control.

**Transition:** “The implementation stack is intentionally lightweight.”

**Time:** 45 seconds.

## Slide 8 — Technology Stack

**Say:** “The backend uses Python, FastAPI, Pydantic, and PyYAML. SQLite provides local audit storage. The SDK is custom Python. pytest verifies behavior. React and Vite provide the dashboard.”

**Technical follow-up:** The project does not claim implemented LangChain, CrewAI, or AutoGen adapters.

**Transition:** “We can now demonstrate the system.”

**Time:** 45 seconds.

## Slide 9 — Live Demonstration

**Say:** “There are four scenarios: safe email, malicious secret exfiltration, redaction, and external export approval.”

**Action:** Open the dashboard Demo Scenarios section.

**Technical follow-up:** Each button calls the existing backend demo endpoint, which uses the real SDK and policy engine.

**Transition:** “First, the safe path.”

**Time:** 40 seconds.

## Slide 10 — Security and Audit Dashboard

**Say:** “The dashboard shows live event decisions, policy metadata, approval records, and demo controls. It does not fabricate security metrics.”

**Technical follow-up:** Counts and event details come from FastAPI audit and approval APIs. The UI never displays raw payloads.

**Transition:** “This is backed by verification.”

**Time:** 45 seconds.

## Slide 11 — Testing and Performance

**Say:** “The latest verified suite contains 142 pytest tests. The frontend production build passes. All four CLI demos pass. The live health and event APIs pass.”

**Technical follow-up:** Synthetic local measurements showed low policy and SDK overhead, but they are not production throughput claims.

**Transition:** “We are explicit about the remaining limitations.”

**Time:** 45 seconds.

## Slide 12 — Limitations

**Say:** “This MVP is not production-ready. It lacks authentication and authorization, cryptographically tamper-evident audit storage, complete framework adapters, and an approval-to-execution resume mechanism.”

**Technical follow-up:** The API is intended to remain loopback-local. Prompt-injection detection is heuristic.

**Transition:** “The roadmap addresses these limits.”

**Time:** 50 seconds.

## Slide 13 — Future Roadmap

**Say:** “The next milestones are authentication and reviewer authorization, tamper-evident audit logging, stronger data classification, approval execution controls, framework adapters, and secure deployment.”

**Technical follow-up:** These are planned capabilities, not implemented claims.

**Transition:** “The core value is at the execution boundary.”

**Time:** 40 seconds.

## Slide 14 — Why It Matters

**Say:** “AgentShield makes AI-agent tool calls deterministic, explainable, and preventable. It records what happened without storing raw payloads.”

**Closing point:** “It adds a control at the point where an agent could create a real side effect.”

**Transition:** “One sentence closes it.”

**Time:** 35 seconds.

## Slide 15 — Closing

**Say:** “AgentShield: security before execution.”

**Final line:** “Thank you. I will take questions.”

**Time:** 20 seconds.
