"""API route for evaluating proposed AI tool calls."""

from fastapi import APIRouter, Depends

from ..models.evaluation import EvaluationResult
from ..models.tool_call import ToolCall
from ..services.audit_logger import AuditLogger, get_audit_service
from ..services.security_engine import evaluate_tool_call
from ..core.auth import AuthenticatedUser, UserRole, require_roles

router = APIRouter(prefix="/api/v1", tags=["Evaluation"])


@router.post("/evaluate", response_model=EvaluationResult)
def evaluate_tool_call_endpoint(
    tool_call: ToolCall,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> EvaluationResult:
    """Evaluates a proposed tool call using the deterministic security policy engine.

    CRITICAL: This endpoint strictly evaluates proposed arguments against security policies.
    It DOES NOT execute the underlying tool. Tool execution is handled by the SDK wrapper.
    """
    result = evaluate_tool_call(tool_call)

    # Persist the evaluation result to the audit log
    audit_logger.log_event(
        evaluation_result=result,
        tool_name=tool_call.tool_name,
        requested_action=f"Evaluate tool call '{tool_call.tool_name}'",
        actor_uid=user.uid,
    )

    return result
