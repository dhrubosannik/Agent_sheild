"""Read-only policy configuration API."""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from ..core.policy_loader import load_policy
from ..models.enums import SecurityDecision
from ..core.auth import AuthenticatedUser, UserRole, require_roles
from fastapi import Depends

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])


class ProtectedRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    action: SecurityDecision


class PolicyRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    tools: list[str]
    data_labels: list[str]
    destination_classes: list[str]
    decision: SecurityDecision


class PolicyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    approved_domains: list[str]
    protected_values: list[ProtectedRuleView]
    rules: list[PolicyRuleView]


@router.get("/current", response_model=PolicyView)
def get_current_policy(
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> PolicyView:
    policy = load_policy()
    return PolicyView(
        version=policy.version,
        approved_domains=policy.approved_domains,
        protected_values=[
            ProtectedRuleView(name=item.name, action=item.action)
            for item in policy.protected_values
        ],
        rules=[
            PolicyRuleView(
                id=rule.id,
                description=rule.description,
                tools=rule.tools,
                data_labels=rule.data_labels,
                destination_classes=[item.value for item in rule.destination_classes],
                decision=rule.decision,
            )
            for rule in policy.rules
        ],
    )
