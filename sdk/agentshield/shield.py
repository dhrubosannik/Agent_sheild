"""Central AgentShield client for protecting AI-agent tools."""

from collections.abc import Callable
import os
from pathlib import Path
from typing import Any

from backend.app.core.policy_loader import PolicyConfigurationError, load_policy
from backend.app.core.policy_models import PolicyConfiguration
from backend.app.models.audit_event import AuditEvent
from backend.app.models.evaluation import EvaluationResult
from backend.app.models.tool_call import ToolCall
from backend.app.services.security_engine import evaluate_tool_call
from .config import ShieldConfig
from .decorator import wrap_tool
from .exceptions import AgentShieldConfigurationError
from .results import ToolExecutionResult


class AgentShield:
    """AgentShield client providing policy evaluation and tool execution protection."""

    def __init__(
        self,
        policy_path: str | os.PathLike[str] | None = None,
        policy: PolicyConfiguration | None = None,
        raise_on_block: bool = False,
        raise_on_approval: bool = False,
        return_execution_result: bool = False,
        audit_callback: Callable[[AuditEvent], None] | None = None,
    ) -> None:
        self.config = ShieldConfig(
            policy_path=policy_path,
            raise_on_block=raise_on_block,
            raise_on_approval=raise_on_approval,
            return_execution_result=return_execution_result,
            audit_callback=audit_callback,
        )

        if policy is not None:
            self.policy = policy
        else:
            try:
                self.policy = load_policy(policy_path)
            except PolicyConfigurationError as exc:
                raise AgentShieldConfigurationError(
                    f"Failed to load AgentShield policy configuration: {str(exc)}"
                ) from exc

        self.audit_events: list[AuditEvent] = []
        self.last_result: ToolExecutionResult | None = None

    def evaluate_tool_call(self, tool_call: ToolCall) -> EvaluationResult:
        """Evaluates a tool call using the centralized security engine."""
        return evaluate_tool_call(tool_call, policy=self.policy)

    def record_audit_event(self, event: AuditEvent) -> None:
        """Records a completed audit event and triggers callbacks."""
        self.audit_events.append(event)
        if self.config.audit_callback is not None:
            try:
                self.config.audit_callback(event)
            except Exception:
                # Do not allow callback errors to disrupt execution
                pass

    def protect_tool(
        self,
        tool_name: str | None = None,
        raise_on_block: bool | None = None,
        raise_on_approval: bool | None = None,
        return_execution_result: bool | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that protects a tool function with AgentShield evaluation."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return wrap_tool(
                func=func,
                shield_client=self,
                tool_name=tool_name,
                raise_on_block=raise_on_block,
                raise_on_approval=raise_on_approval,
                return_execution_result=return_execution_result,
            )

        return decorator

    def wrap(
        self,
        tool_function: Callable[..., Any],
        tool_name: str | None = None,
        raise_on_block: bool | None = None,
        raise_on_approval: bool | None = None,
        return_execution_result: bool | None = None,
    ) -> Callable[..., Any]:
        """Directly wraps a tool function with AgentShield evaluation."""
        return wrap_tool(
            func=tool_function,
            shield_client=self,
            tool_name=tool_name,
            raise_on_block=raise_on_block,
            raise_on_approval=raise_on_approval,
            return_execution_result=return_execution_result,
        )
