"""Configuration options for the AgentShield SDK."""

from collections.abc import Callable
from pathlib import Path

from backend.app.models.audit_event import AuditEvent


class ShieldConfig:
    """Settings for AgentShield client and decorators."""

    def __init__(
        self,
        policy_path: str | Path | None = None,
        raise_on_block: bool = False,
        raise_on_approval: bool = False,
        return_execution_result: bool = False,
        audit_callback: Callable[[AuditEvent], None] | None = None,
    ) -> None:
        self.policy_path = policy_path
        self.raise_on_block = raise_on_block
        self.raise_on_approval = raise_on_approval
        self.return_execution_result = return_execution_result
        self.audit_callback = audit_callback
