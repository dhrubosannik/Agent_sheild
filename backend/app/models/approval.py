from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .enums import ApprovalStatus, DestinationClass


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    requested_action: str = Field(min_length=1)
    destination_class: DestinationClass
    status: ApprovalStatus
    created_at: datetime
    reviewer: str | None = None
    reviewed_at: datetime | None = None
