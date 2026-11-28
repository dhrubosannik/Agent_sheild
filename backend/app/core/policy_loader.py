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


def load_active_policy(policy_repo: Any | None = None) -> PolicyConfiguration:
    """Loads the base YAML policy and merges enabled Firestore policies when active."""
    base_policy = load_policy()
    if policy_repo is None:
        from .config import get_settings

        settings = get_settings()
        if settings.database_mode.lower() != "firestore":
            return base_policy
        from ..storage.firestore_policy_repository import FirestorePolicyRepository

        policy_repo = FirestorePolicyRepository()

    from ..models.policy import merge_policies_into_configuration

    stored = policy_repo.list_enabled_policies()
    return merge_policies_into_configuration(base_policy, stored)
