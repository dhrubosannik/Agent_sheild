"""API route for evaluating proposed AI tool calls."""

from fastapi import APIRouter, Depends, Request

from ..models.evaluation import EvaluationResult
from ..models.security_event import build_security_event_input
from ..models.tool_call import ToolCall
from ..services.audit_logger import AuditLogger, get_audit_service
from ..services.security_engine import evaluate_tool_call
from ..storage.firestore_security_event_repository import FirestoreSecurityEventRepository
from ..core.auth import AuthenticatedUser, UserRole, require_roles
from .security_events import get_optional_security_event_repository

router = APIRouter(prefix="/api/v1", tags=["Evaluation"])


@router.post("/evaluate", response_model=EvaluationResult)
def evaluate_tool_call_endpoint(
    tool_call: ToolCall,
    request: Request,
    audit_logger: AuditLogger = Depends(get_audit_service),
    security_event_repo: FirestoreSecurityEventRepository | None = Depends(
        get_optional_security_event_repository
    ),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> EvaluationResult:
    """Evaluates a proposed tool call using the deterministic security policy engine.

    CRITICAL: This endpoint strictly evaluates proposed arguments against security policies.
    It DOES NOT execute the underlying tool. Tool execution is handled by the SDK wrapper.
    """
    result = evaluate_tool_call(tool_call)

    # Persist the evaluation result to the audit log
    context = tool_call.context or {}
    raw_agent_id = context.get("agent_id")
    agent_id = raw_agent_id.strip() if isinstance(raw_agent_id, str) and raw_agent_id.strip() else "default-agent"
    correlation_id = request.headers.get("x-correlation-id") or str(tool_call.request_id)

    audit_logger.log_event(
        evaluation_result=result,
        tool_name=tool_call.tool_name,
        requested_action=f"Evaluate tool call '{tool_call.tool_name}'",
        actor_uid=user.uid,
        agent_id=agent_id,
        correlation_id=correlation_id,
    )

    if security_event_repo is not None:
        event_input = build_security_event_input(
            tool_call=tool_call,
            result=result,
            user_id=user.uid,
            correlation_id=correlation_id,
        )
        security_event_repo.create_event(**event_input, idempotent=True)

    return result
