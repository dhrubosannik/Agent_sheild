"""Result models for the AgentShield SDK."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.models.risk_signal import RiskSignal


class ToolExecutionResult(BaseModel):
    """Structured result returned by AgentShield protected tool calls."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    decision: SecurityDecision
    policy_id: str = Field(min_length=1)
    reason_codes: list[str] = Field(default_factory=list)
    destination_class: DestinationClass
    data_labels: list[str] = Field(default_factory=list)
    risk_signals: list[str | RiskSignal] = Field(default_factory=list)
    payload_fingerprint: str | None = None
    execution_status: ExecutionStatus
    explanation: str = Field(min_length=1)
    result: Any = None
    approval_id: str | None = None

    @property
    def is_allowed(self) -> bool:
        return self.decision == SecurityDecision.ALLOW

    @property
    def is_redacted(self) -> bool:
        return self.decision == SecurityDecision.REDACT

    @property
    def is_blocked(self) -> bool:
        return self.decision == SecurityDecision.BLOCK

    @property
    def is_pending_approval(self) -> bool:
        return self.decision == SecurityDecision.REQUIRE_APPROVAL

    @property
    def is_executed(self) -> bool:
        return self.execution_status in (
            ExecutionStatus.EXECUTED,
            ExecutionStatus.REDACTED_AND_EXECUTED,
        )
