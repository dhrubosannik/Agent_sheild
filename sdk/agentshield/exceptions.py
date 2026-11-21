"""Exceptions for the AgentShield SDK."""

from typing import Any


class AgentShieldError(Exception):
    """Base exception for all AgentShield SDK errors."""


class AgentShieldBlockError(AgentShieldError):
    """Raised when a tool call is BLOCKED by AgentShield policy."""

    def __init__(
        self,
        explanation: str,
        event_id: str,
        policy_id: str,
        decision: str = "BLOCK",
        reason_codes: list[str] | None = None,
        execution_result: Any | None = None,
    ) -> None:
        super().__init__(explanation)
        self.explanation = explanation
        self.event_id = event_id
        self.policy_id = policy_id
        self.decision = decision
        self.reason_codes = reason_codes or []
        self.execution_result = execution_result


class AgentShieldApprovalRequiredError(AgentShieldError):
    """Raised when a tool call requires human approval before execution."""

    def __init__(
        self,
        explanation: str,
        event_id: str,
        policy_id: str,
        decision: str = "REQUIRE_APPROVAL",
        approval_id: str | None = None,
        reason_codes: list[str] | None = None,
        execution_result: Any | None = None,
    ) -> None:
        super().__init__(explanation)
        self.explanation = explanation
        self.event_id = event_id
        self.policy_id = policy_id
        self.decision = decision
        self.approval_id = approval_id
        self.reason_codes = reason_codes or []
        self.execution_result = execution_result


class AgentShieldEvaluationError(AgentShieldError):
    """Raised when policy evaluation fails or encounters an error."""


class AgentShieldConfigurationError(AgentShieldError):
    """Raised when AgentShield SDK configuration is invalid."""
