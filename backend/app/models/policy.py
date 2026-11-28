"""Pydantic models and engine-compatible validation for Firestore ``policies``."""

from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from ..core.policy_models import (
    ApprovedDomain,
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from ..models.enums import DestinationClass, SecurityDecision

POLICY_FIELDS = frozenset(
    {
        "policy_id",
        "name",
        "description",
        "enabled",
        "priority",
        "action",
        "rules",
        "created_by",
        "created_at",
        "updated_at",
        "version",
    }
)

_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACTOR_RE = re.compile(r"^[^\s/]+$")


def validate_policy_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("policy_id must be a string.")
    cleaned = value.strip()
    if not cleaned or ".." in cleaned or not _POLICY_ID_RE.match(cleaned):
        raise ValueError(
            "policy_id must be 1-128 characters starting with an alphanumeric character "
            "(allowed: letters, digits, '.', '_', '-')."
        )
    return cleaned


def validate_non_empty_str(value: Any, *, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length:
        raise ValueError(f"{field_name} must be a non-empty string up to {max_length} characters.")
    return cleaned


def validate_created_by(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("created_by must be a string.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 128 or ".." in cleaned or not _ACTOR_RE.match(cleaned):
        raise ValueError("created_by must be a valid actor identifier.")
    return cleaned


def validate_strict_bool(value: Any, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean.")
    return value


def validate_strict_int(value: Any, *, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer.")
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}.")
    return value


def validate_action(value: Any) -> SecurityDecision:
    if isinstance(value, SecurityDecision):
        return value
    if not isinstance(value, str):
        raise ValueError("action must be a string.")
    try:
        return SecurityDecision(value)
    except ValueError as exc:
        allowed = ", ".join(d.value for d in SecurityDecision)
        raise ValueError(f"action must be one of: {allowed}.") from exc


def validate_timestamp(value: Any, *, field_name: str) -> datetime:
    if value is None or isinstance(value, bool) or not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a timestamp.")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class PolicyRuleSpec(BaseModel):
    """Engine-compatible ``rules`` map stored inside ``policies/{policy_id}``.

    Only fields recognized by ``SecurityRule`` and ``PolicyConfiguration`` in
    ``backend/app/core/policy_models.py`` are permitted; unknown keys are
    rejected so stored policies can never silently diverge from the policy engine.
    """

    model_config = ConfigDict(extra="forbid")

    tools: list[StrictStr] = Field(default_factory=list)
    data_labels: list[StrictStr] = Field(default_factory=list)
    destination_classes: list[DestinationClass] = Field(default_factory=list)
    approved_domains: list[StrictStr] = Field(default_factory=list)
    allowed_internal_destinations: list[StrictStr] = Field(default_factory=list)
    protected_values: list[ProtectedValue] = Field(default_factory=list)
    defaults: DefaultPolicyBehavior | None = None

    @field_validator("tools", "data_labels")
    @classmethod
    def _validate_non_empty_list_items(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in values:
            stripped = item.strip()
            if not stripped:
                raise ValueError("rule lists cannot contain empty strings.")
            cleaned.append(stripped)
        return cleaned

    @field_validator("approved_domains")
    @classmethod
    def _validate_approved_domains(cls, values: list[str]) -> list[str]:
        return [ApprovedDomain(domain=item).domain for item in values]

    @field_validator("allowed_internal_destinations")
    @classmethod
    def _validate_internal_destinations(cls, values: list[str]) -> list[str]:
        return PolicyConfiguration.validate_internal_allowlist(values)

    @model_validator(mode="after")
    def _require_non_empty_spec(self) -> "PolicyRuleSpec":
        has_any = any(
            [
                self.tools,
                self.data_labels,
                self.destination_classes,
                self.approved_domains,
                self.allowed_internal_destinations,
                self.protected_values,
                self.defaults is not None,
            ]
        )
        if not has_any:
            raise ValueError(
                "rules map must specify at least one engine-compatible field "
                "(tools, data_labels, destination_classes, approved_domains, "
                "allowed_internal_destinations, protected_values, or defaults)."
            )
        return self

    def to_firestore_map(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.tools:
            out["tools"] = list(self.tools)
        if self.data_labels:
            out["data_labels"] = list(self.data_labels)
        if self.destination_classes:
            out["destination_classes"] = [dc.value for dc in self.destination_classes]
        if self.approved_domains:
            out["approved_domains"] = list(self.approved_domains)
        if self.allowed_internal_destinations:
            out["allowed_internal_destinations"] = list(self.allowed_internal_destinations)
        if self.protected_values:
            out["protected_values"] = [
                {"name": pv.name, "value": pv.value, "action": pv.action.value}
                for pv in self.protected_values
            ]
        if self.defaults is not None:
            out["defaults"] = {
                "unknown_destination": self.defaults.unknown_destination.value,
                "evaluation_error": self.defaults.evaluation_error.value,
                "internal_destination": self.defaults.internal_destination.value,
            }
        return out

    def has_rule_criteria(self) -> bool:
        return bool(self.tools or self.data_labels or self.destination_classes)


class StoredPolicy(BaseModel):
    """Canonical representation of a document in Firestore ``policies/{policy_id}``."""

    model_config = ConfigDict(extra="forbid")

    policy_id: StrictStr
    name: StrictStr
    description: StrictStr
    enabled: StrictBool
    priority: StrictInt
    action: SecurityDecision
    rules: PolicyRuleSpec
    created_by: StrictStr
    created_at: datetime
    updated_at: datetime
    version: StrictInt

    @field_validator("policy_id", mode="before")
    @classmethod
    def _check_policy_id(cls, value: Any) -> str:
        return validate_policy_id(value)

    @field_validator("name", mode="before")
    @classmethod
    def _check_name(cls, value: Any) -> str:
        return validate_non_empty_str(value, field_name="name", max_length=200)

    @field_validator("description", mode="before")
    @classmethod
    def _check_description(cls, value: Any) -> str:
        return validate_non_empty_str(value, field_name="description", max_length=1000)

    @field_validator("enabled", mode="before")
    @classmethod
    def _check_enabled(cls, value: Any) -> bool:
        return validate_strict_bool(value, field_name="enabled")

    @field_validator("priority", mode="before")
    @classmethod
    def _check_priority(cls, value: Any) -> int:
        return validate_strict_int(value, field_name="priority", minimum=1, maximum=10000)

    @field_validator("action", mode="before")
    @classmethod
    def _check_action(cls, value: Any) -> SecurityDecision:
        return validate_action(value)

    @field_validator("rules", mode="before")
    @classmethod
    def _check_rules(cls, value: Any) -> PolicyRuleSpec:
        if isinstance(value, PolicyRuleSpec):
            return value
        if not isinstance(value, dict):
            raise ValueError("rules must be a map/object.")
        return PolicyRuleSpec.model_validate(value)

    @field_validator("created_by", mode="before")
    @classmethod
    def _check_created_by(cls, value: Any) -> str:
        return validate_created_by(value)

    @field_validator("created_at", mode="before")
    @classmethod
    def _check_created_at(cls, value: Any) -> datetime:
        return validate_timestamp(value, field_name="created_at")

    @field_validator("updated_at", mode="before")
    @classmethod
    def _check_updated_at(cls, value: Any) -> datetime:
        return validate_timestamp(value, field_name="updated_at")

    @field_validator("version", mode="before")
    @classmethod
    def _check_version(cls, value: Any) -> int:
        return validate_strict_int(value, field_name="version", minimum=1, maximum=1_000_000)


class PolicyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: StrictStr
    name: StrictStr
    description: StrictStr
    enabled: StrictBool = True
    priority: StrictInt = 100
    action: SecurityDecision
    rules: dict[str, Any]

    @field_validator("policy_id", mode="before")
    @classmethod
    def _check_policy_id(cls, value: Any) -> str:
        return validate_policy_id(value)

    @field_validator("name", mode="before")
    @classmethod
    def _check_name(cls, value: Any) -> str:
        return validate_non_empty_str(value, field_name="name", max_length=200)

    @field_validator("description", mode="before")
    @classmethod
    def _check_description(cls, value: Any) -> str:
        return validate_non_empty_str(value, field_name="description", max_length=1000)

    @field_validator("enabled", mode="before")
    @classmethod
    def _check_enabled(cls, value: Any) -> bool:
        return validate_strict_bool(value, field_name="enabled")

    @field_validator("priority", mode="before")
    @classmethod
    def _check_priority(cls, value: Any) -> int:
        return validate_strict_int(value, field_name="priority", minimum=1, maximum=10000)

    @field_validator("action", mode="before")
    @classmethod
    def _check_action(cls, value: Any) -> SecurityDecision:
        return validate_action(value)

    @field_validator("rules", mode="before")
    @classmethod
    def _check_rules(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("rules must be a map/object.")
        return PolicyRuleSpec.model_validate(value).to_firestore_map()


class PolicyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: StrictStr | None = None
    description: StrictStr | None = None
    enabled: StrictBool | None = None
    priority: StrictInt | None = None
    action: SecurityDecision | None = None
    rules: dict[str, Any] | None = None

    @field_validator("name", mode="before")
    @classmethod
    def _check_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        return validate_non_empty_str(value, field_name="name", max_length=200)

    @field_validator("description", mode="before")
    @classmethod
    def _check_description(cls, value: Any) -> str | None:
        if value is None:
            return None
        return validate_non_empty_str(value, field_name="description", max_length=1000)

    @field_validator("enabled", mode="before")
    @classmethod
    def _check_enabled(cls, value: Any) -> bool | None:
        if value is None:
            return None
        return validate_strict_bool(value, field_name="enabled")

    @field_validator("priority", mode="before")
    @classmethod
    def _check_priority(cls, value: Any) -> int | None:
        if value is None:
            return None
        return validate_strict_int(value, field_name="priority", minimum=1, maximum=10000)

    @field_validator("action", mode="before")
    @classmethod
    def _check_action(cls, value: Any) -> SecurityDecision | None:
        if value is None:
            return None
        return validate_action(value)

    @field_validator("rules", mode="before")
    @classmethod
    def _check_rules(cls, value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("rules must be a map/object.")
        return PolicyRuleSpec.model_validate(value).to_firestore_map()

    @model_validator(mode="after")
    def _require_any_field(self) -> "PolicyUpdateRequest":
        if all(
            v is None
            for v in (self.name, self.description, self.enabled, self.priority, self.action, self.rules)
        ):
            raise ValueError("At least one policy field must be provided for update.")
        return self


class PolicyHistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: StrictStr
    version: StrictInt
    change_type: StrictStr
    changed_by: StrictStr
    changed_at: datetime
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any]


class PolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[StoredPolicy]
    total: int
    limit: int
    next_cursor: str | None = None


def merge_policies_into_configuration(
    base_policy: PolicyConfiguration,
    stored_policies: list[StoredPolicy],
) -> PolicyConfiguration:
    """Combines enabled stored Firestore policies (ordered by priority ASC)
    with the base YAML ``PolicyConfiguration`` for ``evaluate_policy``.
    """
    active = sorted(
        (p for p in stored_policies if p.enabled),
        key=lambda p: (p.priority, p.policy_id),
    )
    if not active:
        return base_policy

    merged_domains = list(base_policy.approved_domains)
    seen_domains = set(merged_domains)
    merged_internal = list(base_policy.allowed_internal_destinations)
    seen_internal = set(merged_internal)
    protected_by_name = {pv.name: pv for pv in base_policy.protected_values}
    merged_defaults = base_policy.defaults

    stored_rules: list[SecurityRule] = []
    override_ids: set[str] = set()
    defaults_applied = False

    for policy in active:
        spec = policy.rules
        for domain in spec.approved_domains:
            if domain not in seen_domains:
                merged_domains.append(domain)
                seen_domains.add(domain)
        for dest in spec.allowed_internal_destinations:
            if dest not in seen_internal:
                merged_internal.append(dest)
                seen_internal.add(dest)
        for pv in spec.protected_values:
            protected_by_name[pv.name] = pv
        if spec.defaults is not None and not defaults_applied:
            merged_defaults = spec.defaults
            defaults_applied = True
        if spec.has_rule_criteria():
            override_ids.add(policy.policy_id)
            stored_rules.append(
                SecurityRule(
                    id=policy.policy_id,
                    description=policy.description,
                    tools=list(spec.tools),
                    data_labels=list(spec.data_labels),
                    destination_classes=list(spec.destination_classes),
                    decision=policy.action,
                )
            )

    base_rules = [rule for rule in base_policy.rules if rule.id not in override_ids]
    return PolicyConfiguration(
        version=base_policy.version,
        defaults=merged_defaults,
        approved_domains=merged_domains,
        protected_values=list(protected_by_name.values()),
        rules=[*stored_rules, *base_rules],
        allowed_internal_destinations=merged_internal,
    )
