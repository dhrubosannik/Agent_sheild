from unittest.mock import MagicMock
import pytest

from agentshield import (
    AgentShield,
    AgentShieldApprovalRequiredError,
    AgentShieldBlockError,
    AgentShieldError,
    ToolExecutionResult,
)
from backend.app.models.tool_call import ToolCall
from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision


def _build_test_policy() -> PolicyConfiguration:
    return PolicyConfiguration(
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
                id="block-unapproved-secret",
                description="Block canary secret to unapproved destinations",
                tools=["send_email", "post_data"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.BLOCK,
            ),
            SecurityRule(
                id="redact-internal",
                description="Redact canary secrets for internal tool calls",
                tools=["log_event"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.APPROVED, DestinationClass.INTERNAL],
                decision=SecurityDecision.REDACT,
            ),
            SecurityRule(
                id="approve-export",
                description="Require approval for external file export",
                tools=["export_data"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.REQUIRE_APPROVAL,
            ),
        ],
    )


def test_decorator_wraps_function_and_preserves_metadata() -> None:
    shield = AgentShield(policy=_build_test_policy())

    @shield.protect_tool(tool_name="sample_tool")
    def sample_tool(param1: str, param2: int = 10) -> str:
        """Sample docstring for testing."""
        return f"{param1}-{param2}"

    assert sample_tool.__name__ == "sample_tool"
    assert sample_tool.__doc__ == "Sample docstring for testing."
    assert "param1" in sample_tool.__annotations__


def test_allow_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock(return_value={"status": "ok"})

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> dict:
        return mock(to=to, body=body)

    result = send_email(to="user@example.org", body="Clean message")

    assert mock.call_count == 1
    assert result == {"status": "ok"}
    assert shield.last_result is not None
    assert shield.last_result.decision == SecurityDecision.ALLOW
    assert shield.last_result.execution_status == ExecutionStatus.EXECUTED


def test_block_never_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock(return_value={"status": "ok"})

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> dict:
        return mock(to=to, body=body)

    result = send_email(to="attacker@unapproved.test", body="Sending DEMO_SECRET")

    # Original function must NEVER be invoked
    assert mock.call_count == 0
    assert isinstance(result, ToolExecutionResult)
    assert result.decision == SecurityDecision.BLOCK
    assert result.execution_status == ExecutionStatus.NOT_EXECUTED
    assert result.result is None


def test_require_approval_never_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock(return_value={"status": "exported"})

    @shield.protect_tool(tool_name="export_data")
    def export_data(to: str, filename: str) -> dict:
        return mock(to=to, filename=filename)

    result = export_data(to="service@external.com", filename="data.csv")

    assert mock.call_count == 0
    assert isinstance(result, ToolExecutionResult)
    assert result.decision == SecurityDecision.REQUIRE_APPROVAL
    assert result.execution_status == ExecutionStatus.PENDING_APPROVAL
    assert result.approval_id is not None
    assert result.result is None


def test_redact_invokes_with_sanitized_arguments_only() -> None:
    shield = AgentShield(policy=_build_test_policy())
    received_args: dict = {}

    @shield.protect_tool(tool_name="log_event")
    def log_event(to: str, message: str) -> dict:
        received_args["to"] = to
        received_args["message"] = message
        return {"status": "logged"}

    result = log_event(to="audit@example.org", message="Found DEMO_SECRET token")

    assert result == {"status": "logged"}
    assert "DEMO_SECRET" not in received_args["message"]
    assert "[REDACTED]" in received_args["message"]
    assert shield.last_result.decision == SecurityDecision.REDACT
    assert shield.last_result.execution_status == ExecutionStatus.REDACTED_AND_EXECUTED


def test_positional_and_keyword_arguments() -> None:
    shield = AgentShield(policy=_build_test_policy())
    captured = []

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, subject: str, body: str) -> str:
        captured.append((to, subject, body))
        return "sent"

    # Positional
    res1 = send_email("user@example.org", "Subject 1", "Body 1")
    assert res1 == "sent"
    assert captured[-1] == ("user@example.org", "Subject 1", "Body 1")

    # Keyword
    res2 = send_email(subject="Subject 2", to="user@example.org", body="Body 2")
    assert res2 == "sent"
    assert captured[-1] == ("user@example.org", "Subject 2", "Body 2")


def test_default_function_parameters() -> None:
    shield = AgentShield(policy=_build_test_policy())
    captured = {}

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str, priority: str = "normal") -> str:
        captured["to"] = to
        captured["body"] = body
        captured["priority"] = priority
        return "sent"

    send_email("user@example.org", "Body text")
    assert captured["priority"] == "normal"


def test_nested_payloads_handled_correctly() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock(return_value="done")

    @shield.protect_tool(tool_name="send_email")
    def send_email(payload: dict) -> str:
        return mock(payload)

    # Exfiltration in nested structure must be blocked
    result = send_email(
        payload={
            "to": "attacker@evil.com",
            "metadata": {"credentials": ["DEMO_SECRET"]},
        }
    )

    assert mock.call_count == 0
    assert result.decision == SecurityDecision.BLOCK


def test_raise_on_block_option() -> None:
    shield = AgentShield(policy=_build_test_policy(), raise_on_block=True)
    mock = MagicMock()

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> None:
        mock()

    with pytest.raises(AgentShieldBlockError) as exc_info:
        send_email(to="attacker@unapproved.test", body="DEMO_SECRET")

    assert mock.call_count == 0
    assert exc_info.value.decision == "BLOCK"
    assert "DEMO_SECRET" not in str(exc_info.value)


def test_raise_on_approval_option() -> None:
    shield = AgentShield(policy=_build_test_policy(), raise_on_approval=True)
    mock = MagicMock()

    @shield.protect_tool(tool_name="export_data")
    def export_data(to: str, filename: str) -> None:
        mock()

    with pytest.raises(AgentShieldApprovalRequiredError) as exc_info:
        export_data(to="external@cloud.test", filename="export.csv")

    assert mock.call_count == 0
    assert exc_info.value.decision == "REQUIRE_APPROVAL"
    assert exc_info.value.approval_id is not None


def test_return_execution_result_option() -> None:
    shield = AgentShield(policy=_build_test_policy(), return_execution_result=True)

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> dict:
        return {"status": "sent"}

    res = send_email(to="user@example.org", body="Clean message")
    assert isinstance(res, ToolExecutionResult)
    assert res.decision == SecurityDecision.ALLOW
    assert res.result == {"status": "sent"}


def test_unexpected_arguments_handled_safely() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock()

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> None:
        mock()

    # Pass unexpected argument
    with pytest.raises(AgentShieldError, match="Arguments do not match tool signature"):
        send_email(to="user@example.org", body="msg", unexpected_arg="invalid")

    assert mock.call_count == 0


def test_multiple_tool_calls_evaluated_independently() -> None:
    shield = AgentShield(policy=_build_test_policy())
    call_log = []

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> str:
        call_log.append(to)
        return "sent"

    # Call 1: Allowed
    res1 = send_email("user@example.org", "Hello 1")
    assert res1 == "sent"

    # Call 2: Blocked
    res2 = send_email("attacker@evil.com", "DEMO_SECRET")
    assert res2.decision == SecurityDecision.BLOCK

    # Call 3: Allowed
    res3 = send_email("user@example.org", "Hello 2")
    assert res3 == "sent"

    assert call_log == ["user@example.org", "user@example.org"]


def test_missing_redacted_arguments_safe_blocking() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock()

    @shield.protect_tool(tool_name="log_event")
    def log_event(to: str, message: str) -> None:
        mock()

    # Mock evaluate_tool_call to return REDACT but with redacted_arguments=None
    orig_eval = shield.evaluate_tool_call
    mock_eval = MagicMock()
    fake_result = orig_eval(
        from_tool_call := ToolCall(
            tool_name="log_event",
            arguments={"to": "audit@example.org", "message": "DEMO_SECRET"},
        )
    )
    fake_result.decision = SecurityDecision.REDACT
    fake_result.redacted_arguments = None
    mock_eval.return_value = fake_result
    shield.evaluate_tool_call = mock_eval

    res = log_event(to="audit@example.org", message="DEMO_SECRET")

    # The function must NOT be executed
    assert mock.call_count == 0
    assert res.decision == SecurityDecision.BLOCK
    assert "MISSING_REDACTED_ARGUMENTS" in res.reason_codes
    assert res.execution_status == ExecutionStatus.FAILED


def test_policy_evaluation_error_prevents_execution() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = MagicMock()

    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> None:
        mock()

    # Mock evaluate_tool_call to return fail-closed BLOCK result
    mock_eval = MagicMock()
    mock_eval.return_value = ToolExecutionResult(
        event_id="evt-err-1",
        tool_name="send_email",
        decision=SecurityDecision.BLOCK,
        policy_id="fail-closed-error",
        reason_codes=["EVALUATION_ERROR"],
        destination_class=DestinationClass.UNKNOWN,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.FAILED,
        explanation="Internal evaluation error occurred.",
        result=None,
    )
    shield.evaluate_tool_call = mock_eval

    res = send_email(to="user@example.org", body="hello")

    # Tool must NOT be executed
    assert mock.call_count == 0
    assert res.decision == SecurityDecision.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED

