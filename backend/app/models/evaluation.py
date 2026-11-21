from pydantic import BaseModel, ConfigDict, Field

from .enums import DestinationClass, ExecutionStatus, SecurityDecision
from .risk_signal import RiskSignal


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    decision: SecurityDecision
    policy_id: str = Field(min_length=1)
    reason_codes: list[str] = Field(default_factory=list)
    destination_class: DestinationClass
    data_labels: list[str] = Field(default_factory=list)
    risk_signals: list[str | RiskSignal] = Field(default_factory=list)
    payload_fingerprint: str | None = None
    redacted_arguments: dict[str, object] | None = None
    execution_status: ExecutionStatus
    explanation: str = Field(min_length=1)
