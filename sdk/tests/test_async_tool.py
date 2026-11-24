from unittest.mock import AsyncMock
import pytest

from agentshield import AgentShield, AgentShieldBlockError, ToolExecutionResult
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
                tools=["async_send"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.BLOCK,
            ),
            SecurityRule(
                id="redact-async",
                description="Redact canary secrets for async tool",
                tools=["async_log"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.APPROVED, DestinationClass.INTERNAL],
                decision=SecurityDecision.REDACT,
            ),
            SecurityRule(
                id="approve-async",
                description="Require approval for async export",
                tools=["async_export"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.REQUIRE_APPROVAL,
            ),
        ],
    )


@pytest.mark.anyio
async def test_async_allow_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = AsyncMock(return_value={"status": "async_sent"})

    @shield.protect_tool(tool_name="async_send")
    async def async_send(to: str, body: str) -> dict:
        return await mock(to=to, body=body)

    res = await async_send(to="user@example.org", body="Clean async message")

    assert mock.await_count == 1
    assert res == {"status": "async_sent"}
    assert shield.last_result.decision == SecurityDecision.ALLOW
    assert shield.last_result.execution_status == ExecutionStatus.EXECUTED


@pytest.mark.anyio
async def test_async_block_never_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = AsyncMock(return_value={"status": "async_sent"})

    @shield.protect_tool(tool_name="async_send")
    async def async_send(to: str, body: str) -> dict:
        return await mock(to=to, body=body)

    res = await async_send(to="attacker@unapproved.test", body="Leaking DEMO_SECRET")

    assert mock.await_count == 0
    assert isinstance(res, ToolExecutionResult)
    assert res.decision == SecurityDecision.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED


@pytest.mark.anyio
async def test_async_require_approval_never_invokes_original_function() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = AsyncMock(return_value={"status": "exported"})

    @shield.protect_tool(tool_name="async_export")
    async def async_export(to: str, filename: str) -> dict:
        return await mock(to=to, filename=filename)

    res = await async_export(to="backup@external.com", filename="archive.zip")

    assert mock.await_count == 0
    assert isinstance(res, ToolExecutionResult)
    assert res.decision == SecurityDecision.REQUIRE_APPROVAL
    assert res.execution_status == ExecutionStatus.PENDING_APPROVAL


@pytest.mark.anyio
async def test_async_redact_invokes_with_sanitized_arguments() -> None:
    shield = AgentShield(policy=_build_test_policy())
    received = {}

    @shield.protect_tool(tool_name="async_log")
    async def async_log(to: str, message: str) -> dict:
        received["to"] = to
        received["message"] = message
        return {"status": "logged"}

    res = await async_log(to="audit@example.org", message="Found DEMO_SECRET")

    assert res == {"status": "logged"}
    assert "DEMO_SECRET" not in received["message"]
    assert "[REDACTED]" in received["message"]
    assert shield.last_result.decision == SecurityDecision.REDACT
    assert shield.last_result.execution_status == ExecutionStatus.REDACTED_AND_EXECUTED


@pytest.mark.anyio
async def test_async_evaluation_error_prevents_execution() -> None:
    shield = AgentShield(policy=_build_test_policy())
    mock = AsyncMock()

    @shield.protect_tool(tool_name="async_send")
    async def async_send(to: str, body: str) -> None:
        await mock()

    # Evaluation returns fail-closed BLOCK
    from unittest.mock import MagicMock
    mock_eval = MagicMock()
    mock_eval.return_value = ToolExecutionResult(
        event_id="evt-async-err",
        tool_name="async_send",
        decision=SecurityDecision.BLOCK,
        policy_id="fail-closed-error",
        reason_codes=["EVALUATION_ERROR"],
        destination_class=DestinationClass.UNKNOWN,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=None,
        execution_status=ExecutionStatus.FAILED,
        explanation="Evaluation error in async pipeline.",
        result=None,
    )
    shield.evaluate_tool_call = mock_eval

    res = await async_send(to="user@example.org", body="msg")

    assert mock.await_count == 0
    assert res.decision == SecurityDecision.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED

