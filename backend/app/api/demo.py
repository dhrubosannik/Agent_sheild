"""HTTP entry points for the existing offline AgentShield demo."""

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from examples.demo_agent import DemoAgent
from sdk.agentshield import AgentShield
from sdk.agentshield.results import ToolExecutionResult
from ..services.audit_logger import AuditLogger, get_audit_service

router = APIRouter(prefix="/api/v1/demo", tags=["Demo"])


class DemoRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    results: list[ToolExecutionResult]
    tool_call_counts: dict[str, int]


@router.post("/run/{scenario}", response_model=DemoRunResponse)
def run_demo_scenario(
    scenario: Literal["safe", "malicious", "redaction", "approval", "all"],
    audit_logger: AuditLogger = Depends(get_audit_service),
) -> DemoRunResponse:
    shield = AgentShield(
        raise_on_block=False,
        raise_on_approval=False,
        return_execution_result=True,
        audit_logger=audit_logger,
    )
    agent = DemoAgent(shield)
    results: list[ToolExecutionResult] = []

    if scenario in ("safe", "all"):
        results.append(agent.run_safe())
    if scenario in ("malicious", "all"):
        results.append(agent.run_malicious())
    if scenario in ("redaction", "all"):
        results.append(agent.run_redaction())
    if scenario in ("approval", "all"):
        approved, rejected = agent.run_approval(auto_review=False)
        results.extend([approved, rejected])

    return DemoRunResponse(
        scenario=scenario,
        results=results,
        tool_call_counts=dict(agent.tools.call_counts),
    )
