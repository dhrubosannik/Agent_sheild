"""Central Security Engine for AgentShield.

Coordinates normalization, destination classification, sensitive-data detection,
prompt-injection heuristics, deterministic policy evaluation, and redaction.
"""

from typing import Any
import uuid

from ..core.policy_loader import load_policy
from ..core.policy_models import PolicyConfiguration
from ..models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from ..models.evaluation import EvaluationResult
from ..models.risk_signal import RiskSignal
from ..models.tool_call import ToolCall
from .destination_classifier import classify_destination
from .injection_detector import detect_prompt_injection
from .payload_normalizer import (
    NormalizationError,
    compute_payload_fingerprint,
    normalize_arguments,
)
from .policy_evaluator import evaluate_policy
from .redaction_service import redact_arguments
from .sensitive_data_detector import detect_sensitive_data


def evaluate_tool_call(
    tool_call: ToolCall,
    policy: PolicyConfiguration | None = None,
) -> EvaluationResult:
    """Evaluates a proposed tool call against security policies before execution.

    Coordinates all security services:
    1. Validates and normalizes arguments.
    2. Classifies destination.
    3. Detects configured secrets and sensitive data.
    4. Evaluates prompt-injection heuristics.
    5. Applies deterministic policy precedence.
    6. Sanitizes arguments if REDACT is chosen.
    7. Generates payload fingerprint.
    8. Fails closed on any unexpected error.
    """
    event_id = f"evt-{uuid.uuid4().hex[:12]}"

    try:
        # Load default policy if not provided
        active_policy = policy if policy is not None else load_policy()

        # Step 1 & 2: Normalize arguments
        try:
            normalized_args = normalize_arguments(tool_call.arguments)
        except NormalizationError as norm_err:
            return EvaluationResult(
                event_id=event_id,
                decision=SecurityDecision.BLOCK,
                policy_id="invalid-payload-normalization",
                reason_codes=["INVALID_PAYLOAD", "NORMALIZATION_ERROR"],
                destination_class=DestinationClass.UNKNOWN,
                data_labels=[],
                risk_signals=[],
                payload_fingerprint=None,
                redacted_arguments=None,
                execution_status=ExecutionStatus.FAILED,
                explanation=f"Tool call arguments failed normalization: {str(norm_err)}",
            )

        # Step 3 & 4: Destination classification
        destination_class = classify_destination(normalized_args, active_policy)

        # Step 5: Sensitive data detection
        detection_result = detect_sensitive_data(normalized_args, active_policy)
        data_labels = detection_result.data_labels

        # Step 6: Prompt-injection heuristic risk signals
        risk_signals: list[str | RiskSignal] = []
        injection_signals = detect_prompt_injection(normalized_args, tool_call.context)
        risk_signals.extend(injection_signals)

        # Step 7 & 8: Policy evaluation and decision precedence
        eval_decision = evaluate_policy(
            tool_name=tool_call.tool_name,
            normalized_arguments=normalized_args,
            destination_class=destination_class,
            data_labels=data_labels,
            risk_signals=injection_signals,
            policy=active_policy,
        )

        decision = eval_decision.decision
        policy_id = eval_decision.policy_id
        reason_codes = list(eval_decision.reason_codes)
        explanation = eval_decision.explanation
        redacted_args: dict[str, object] | None = None

        # Step 9: Redaction handling if REDACT is selected
        if decision == SecurityDecision.REDACT:
            success, sanitized = redact_arguments(normalized_args, active_policy)
            if success and sanitized is not None:
                redacted_args = sanitized
            else:
                # If safe redaction cannot be guaranteed, fail closed to BLOCK
                decision = SecurityDecision.BLOCK
                reason_codes.append("REDACTION_FAILED")
                explanation = "Redaction could not be safely guaranteed; action blocked (failed closed)."

        # Step 10: Payload fingerprint
        fingerprint = compute_payload_fingerprint(normalized_args)

        # Execution status before SDK execution
        if decision == SecurityDecision.REQUIRE_APPROVAL:
            execution_status = ExecutionStatus.PENDING_APPROVAL
        else:
            execution_status = ExecutionStatus.NOT_EXECUTED

        return EvaluationResult(
            event_id=event_id,
            decision=decision,
            policy_id=policy_id,
            reason_codes=reason_codes,
            destination_class=destination_class,
            data_labels=data_labels,
            risk_signals=risk_signals,
            payload_fingerprint=fingerprint,
            redacted_arguments=redacted_args,
            execution_status=execution_status,
            explanation=explanation,
        )

    except Exception as exc:
        # Strict security requirement: fail closed on evaluation errors
        return EvaluationResult(
            event_id=event_id,
            decision=SecurityDecision.BLOCK,
            policy_id="fail-closed-error",
            reason_codes=["EVALUATION_ERROR"],
            destination_class=DestinationClass.UNKNOWN,
            data_labels=[],
            risk_signals=[],
            payload_fingerprint=None,
            redacted_arguments=None,
            execution_status=ExecutionStatus.FAILED,
            explanation="Internal evaluation failure; failed closed for security.",
        )
