from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .enums import DestinationClass, ExecutionStatus, SecurityDecision
from .risk_signal import RiskSignal

AuditEventType = Literal["DECISION", "EXECUTION_STATUS", "APPROVAL_DECISION"]


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    tool_name: str = Field(min_length=1)
    decision: SecurityDecision
    policy_id: str = Field(min_length=1)
    reason_codes: list[str] = Field(default_factory=list)
    destination_class: DestinationClass
    data_labels: list[str] = Field(default_factory=list)
    risk_signals: list[str | RiskSignal] = Field(default_factory=list)
    payload_fingerprint: str | None = None
    # Status recorded when this (immutable) record was appended.
    execution_status: ExecutionStatus
    sequence: int | None = None
    previous_event_hash: str | None = None
    current_event_hash: str | None = None
    actor_uid: str | None = None
    # Chain v2 fields. Legacy (v1) records have chain_version None.
    chain_version: int | None = None
    event_type: AuditEventType | None = None
    related_event_id: str | None = None
    # Derived, never hashed: latest status from appended EXECUTION_STATUS records.
    effective_execution_status: ExecutionStatus | None = None
