# AgentShield — AI Agent Tool-Call Security Gateway

This folder contains the project specification and implementation instructions for the AgentShield hackathon MVP.

## How to use
1. Copy this folder into your VS Code project workspace, or extract the ZIP into a new folder.
2. Open the folder in VS Code.
3. Give your coding agent the instructions in `AI_AGENT_INSTRUCTIONS.md`.
4. Then run the prompts in `VSCODE_CODING_PROMPTS.md` in order. Do not skip phases.
5. Require the agent to run tests and report results at the end of every phase.

## Source concept
The uploaded DevNexus HAXTHON proposal describes a lightweight policy gateway placed before agent tools such as `send_email`, `http_post`, or `export_file`. It evaluates the proposed action, destination, payload labels, and risk signals before the real tool runs. Outcomes are `ALLOW`, `REDACT`, `REQUIRE_APPROVAL`, or `BLOCK`, with an audit event.

## MVP demo
A simulated research agent reads a vendor document containing malicious instructions. It proposes sending `DEMO_SECRET` to an unapproved external address. AgentShield evaluates the action and blocks it. The dashboard shows the decision, policy ID, destination class, and a redacted payload fingerprint.

## Important
This is a prototype security control, not a guarantee that all prompt injections can be detected. Deterministic policy checks are the enforcement boundary. Prompt-injection wording detection is a supplementary risk signal and must never be presented as perfect.
