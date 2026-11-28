# Policy Engine Specification

## Policy format
Use YAML or JSON with a version field and named policies. Validate configuration at startup and fail safely if it is invalid.

Example YAML:

```yaml
version: 1
defaults:
  unknown_destination: REQUIRE_APPROVAL
  evaluation_error: BLOCK
approved_domains:
  - example.org
protected_values:
  - name: demo_secret
    value: DEMO_SECRET
    action: BLOCK
rules:
  - id: block-secret-to-unapproved
    description: Block protected data sent to an unapproved destination
    tools: [send_email, http_post]
    data_labels: [PROTECTED]
    destination_classes: [UNAPPROVED, UNKNOWN]
    decision: BLOCK
  - id: approve-external-export
    description: Require approval for external file exports
    tools: [export_file]
    destination_classes: [UNAPPROVED, UNKNOWN]
    decision: REQUIRE_APPROVAL
```

## Evaluation precedence
Use and document a deterministic precedence. Recommended:
1. Invalid input/configuration or internal evaluation error: BLOCK.
2. Explicit deny rule: BLOCK.
3. Protected data to unapproved/unknown destination: BLOCK.
4. Explicit redaction rule: REDACT.
5. Approval-required rule: REQUIRE_APPROVAL.
6. Explicit allow rule: ALLOW.
7. Safe default: REQUIRE_APPROVAL for unknown/high-impact cases; otherwise BLOCK or a narrowly scoped allow policy.

Do not allow a broad allow rule to override a more specific deny rule.

## REDACT behavior
- Apply redaction before the wrapped tool executes.
- Preserve the original payload only in memory if needed for evaluation; never write it to the audit log.
- Include a list of redacted labels/fields, not the secret values.
- If safe redaction cannot be guaranteed, BLOCK.

## Policy explanation
Every decision should include `policy_id` (or a stable default identifier), `reason_codes`, and a human-readable explanation.
