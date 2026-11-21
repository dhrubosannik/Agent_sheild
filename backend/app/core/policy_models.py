from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models.enums import DestinationClass, SecurityDecision


class DefaultPolicyBehavior(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unknown_destination: SecurityDecision
    evaluation_error: SecurityDecision


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
