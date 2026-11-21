"""AgentShield Python SDK."""

from .config import ShieldConfig
from .decorator import wrap_tool
from .exceptions import (
    AgentShieldApprovalRequiredError,
    AgentShieldBlockError,
    AgentShieldConfigurationError,
    AgentShieldError,
    AgentShieldEvaluationError,
)
from .results import ToolExecutionResult
from .shield import AgentShield

__all__ = [
    "AgentShield",
    "AgentShieldApprovalRequiredError",
    "AgentShieldBlockError",
    "AgentShieldConfigurationError",
    "AgentShieldError",
    "AgentShieldEvaluationError",
    "ShieldConfig",
    "ToolExecutionResult",
    "wrap_tool",
]
