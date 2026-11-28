# Frontend Specification

## Goal
Build a professional, minimal security dashboard. It should look like a developer/security product, not a generic AI-themed landing page.

## Main views
1. **Overview:** counts of ALLOW, REDACT, REQUIRE_APPROVAL, BLOCK; recent event stream.
2. **Event details:** tool name, decision, policy ID, destination class, reason codes, data labels, timestamp, payload fingerprint. Never show raw secrets.
3. **Pending approvals:** list pending actions and allow a demo reviewer to approve/reject the record.
4. **Demo controls:** run the benign and malicious synthetic scenarios.

## UX requirements
- Clear status labels for the four decisions.
- Strong visual distinction for BLOCK and REQUIRE_APPROVAL without excessive decoration.
- Empty, loading, and error states.
- Responsive layout.
- Do not fabricate events or metrics. All displayed data must come from the backend or be clearly marked as demo seed data.
- No raw payload display; show redacted summaries and fingerprints only.
