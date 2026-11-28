from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import ApprovalStatus, DestinationClass, RiskLevel


def _normalize_ts(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    user_id: str = Field(default="system", min_length=1, max_length=128)
    agent_id: str = Field(default="default-agent", min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=200)
    requested_action: str = Field(min_length=1, max_length=1000)
    destination_class: DestinationClass = DestinationClass.UNKNOWN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime | None = None
    created_at: datetime | None = None
    reviewed_by: str | None = None
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    decision_reason: str | None = Field(default=None, max_length=1000)
    correlation_id: str = Field(default="unknown", min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _sync_fields(self) -> "Approval":
        req_ts = _normalize_ts(self.requested_at)
        crt_ts = _normalize_ts(self.created_at)
        if req_ts is None and crt_ts is None:
            raise ValueError("requested_at or created_at timestamp is required.")
        self.requested_at = req_ts or crt_ts
        self.created_at = crt_ts or req_ts
        self.reviewed_at = _normalize_ts(self.reviewed_at)

        rev = self.reviewed_by if self.reviewed_by is not None else self.reviewer
        if isinstance(rev, str):
            rev = rev.strip() or None
        self.reviewed_by = rev
        self.reviewer = rev

        if self.decision_reason is not None:
            cleaned_reason = self.decision_reason.strip()
            self.decision_reason = cleaned_reason or None
        return self
