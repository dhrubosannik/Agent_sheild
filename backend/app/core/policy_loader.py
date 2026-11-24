import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .config import resolve_policy_path
from .policy_models import PolicyConfiguration


class PolicyConfigurationError(Exception):
    """Base exception for policy configuration failures."""


class PolicyFileNotFoundError(PolicyConfigurationError):
    pass


class PolicyParseError(PolicyConfigurationError):
    pass


class PolicyValidationError(PolicyConfigurationError):
    pass


def load_policy(path: str | os.PathLike[str] | None = None) -> PolicyConfiguration:
    policy_path = resolve_policy_path(str(path)) if path is not None else resolve_policy_path()
    if not policy_path.is_file():
        raise PolicyFileNotFoundError(f"Policy file not found: {policy_path}")

    try:
        raw = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyParseError(f"Policy file could not be read: {policy_path}") from exc

    try:
        data: Any = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"Policy file contains invalid YAML: {policy_path}") from exc

    if not isinstance(data, dict):
        raise PolicyValidationError("Policy configuration must be a YAML mapping")

    try:
        policy = PolicyConfiguration.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError("Policy configuration contains invalid fields") from exc

    rule_ids = [rule.id for rule in policy.rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise PolicyValidationError("Policy configuration contains duplicate rule IDs")

    return policy
