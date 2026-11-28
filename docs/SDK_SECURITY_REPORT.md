# SDK Security Report

Status: PASS for local wrapper behavior; PARTIAL for Firebase identity.

Verified:

- Sync and async wrappers pass.
- BLOCK and REQUIRE_APPROVAL prevent original-tool invocation.
- REDACT passes sanitized arguments.
- Direct unwrapped functions remain outside SDK enforcement.
- Fail-close and strict test fixtures are covered.

Firebase credentials are never placed in SDK or frontend credential files; frontend receives public Firebase web configuration only.
