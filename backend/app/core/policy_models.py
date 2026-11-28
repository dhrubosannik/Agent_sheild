import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models.enums import DestinationClass, SecurityDecision

# Decisions an operator may choose for internal/sensitive destinations.
# ALLOW and REDACT are deliberately excluded: permitting an internal target
# must be done per-destination through ``allowed_internal_destinations``.
_INTERNAL_DESTINATION_DECISIONS = {SecurityDecision.BLOCK, SecurityDecision.REQUIRE_APPROVAL}


class DefaultPolicyBehavior(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unknown_destination: SecurityDecision
    evaluation_error: SecurityDecision
    internal_destination: SecurityDecision = SecurityDecision.BLOCK

    @field_validator("internal_destination")
    @classmethod
    def restrict_internal_default(cls, value: SecurityDecision) -> SecurityDecision:
        if value not in _INTERNAL_DESTINATION_DECISIONS:
            raise ValueError(
                "internal_destination default must be BLOCK or REQUIRE_APPROVAL; "
                "permit specific internal targets with allowed_internal_destinations"
            )
        return value


class ApprovedDomain(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        normalized = value.strip().lower().rstrip(".")
        if not normalized or "/" in normalized or "@" in normalized:
            raise ValueError("approved domain must be a domain name")
        return normalized


class ProtectedValue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    action: SecurityDecision


class SecurityRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    tools: list[str] = Field(default_factory=list)
    data_labels: list[str] = Field(default_factory=list)
    destination_classes: list[DestinationClass] = Field(default_factory=list)
    decision: SecurityDecision

    @field_validator("tools", "data_labels")
    @classmethod
    def reject_empty_strings(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("policy lists cannot contain empty strings")
        return values


class PolicyConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    defaults: DefaultPolicyBehavior
    approved_domains: list[str]
    protected_values: list[ProtectedValue]
    rules: list[SecurityRule]
    # Explicit allowlist for internal/sensitive destinations (exact hostnames,
    # IP addresses or CIDR networks). Matching destinations are classified
    # APPROVED; every other internal destination is INTERNAL and blocked by
    # ``defaults.internal_destination``.
    allowed_internal_destinations: list[str] = Field(default_factory=list)

    @field_validator("allowed_internal_destinations")
    @classmethod
    def validate_internal_allowlist(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            item = raw.strip().lower().rstrip(".")
            if not item or any(ch in item for ch in "/@ ") and not _is_network(item):
                raise ValueError(f"invalid allowed_internal_destinations entry: {raw!r}")
            if "*" in item:
                raise ValueError("wildcards are not permitted in allowed_internal_destinations")
            normalized.append(item)
        return normalized


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
