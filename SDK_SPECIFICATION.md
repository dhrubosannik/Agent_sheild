# Python SDK Specification

## Goal
Offer a lightweight integration for developers using their own Python tools.

## Required interface
Provide either:
- `@protect_tool(...)` decorator, or
- `shield.wrap(tool_function, tool_name=...)`

The wrapper must intercept arguments before the original function executes.

## Required behavior
- Normalize function name and arguments.
- Evaluate policy using the same shared policy engine used by the API.
- `ALLOW`: call the original function with original arguments.
- `REDACT`: call the original function with the redacted arguments only.
- `REQUIRE_APPROVAL`: do not call the original function; return a structured pending-approval result.
- `BLOCK`: do not call the original function; return a structured blocked result or raise a documented exception.

## Developer experience
Provide a small example showing a protected `send_email` mock tool and a safe call. Include type hints and clear documentation.

## Critical test
Use a counter or mock to prove that the original function is never called for BLOCK and REQUIRE_APPROVAL, and receives only sanitized arguments for REDACT.

## Scope
Custom Python tools only for MVP. Future adapters for LangChain, CrewAI, and AutoGen must be separate, version-pinned, and tested.
