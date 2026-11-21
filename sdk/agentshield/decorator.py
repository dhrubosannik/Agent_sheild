"""Decorator and wrapper implementation for AgentShield protected tools."""

from collections.abc import Callable
from datetime import UTC, datetime
import functools
import inspect
from typing import Any

from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import ExecutionStatus, SecurityDecision
from backend.app.models.tool_call import ToolCall
from .exceptions import (
    AgentShieldApprovalRequiredError,
    AgentShieldBlockError,
    AgentShieldError,
)
from .results import ToolExecutionResult


def _extract_argument_dict(sig: inspect.Signature, *args: Any, **kwargs: Any) -> tuple[dict[str, Any], inspect.BoundArguments]:
    """Binds arguments to function signature and prepares a dictionary for ToolCall."""
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()

    extracted: dict[str, Any] = {}
    for param_name, param in sig.parameters.items():
        val = bound.arguments.get(param_name)
        if param.kind == inspect.Parameter.VAR_POSITIONAL:
            # Tuple of positional varargs
            if val:
                extracted[param_name] = list(val)
        elif param.kind == inspect.Parameter.VAR_KEYWORD:
            # Dictionary of keyword varargs
            if isinstance(val, dict):
                for k, v in val.items():
                    extracted[k] = v
        else:
            extracted[param_name] = val

    return extracted, bound


def _apply_redactions_to_bound(
    bound: inspect.BoundArguments,
    sig: inspect.Signature,
    redacted_args: dict[str, Any],
) -> None:
    """Updates bound arguments with sanitized values for safe function invocation."""
    for key, sanitized_val in redacted_args.items():
        if key in bound.arguments:
            bound.arguments[key] = sanitized_val
        else:
            # Check if key belongs to VAR_KEYWORD dict
            for param_name, param in sig.parameters.items():
                if param.kind == inspect.Parameter.VAR_KEYWORD:
                    if param_name in bound.arguments and isinstance(bound.arguments[param_name], dict):
                        bound.arguments[param_name][key] = sanitized_val


def wrap_tool(
    func: Callable[..., Any],
    shield_client: Any,
    tool_name: str | None = None,
    raise_on_block: bool | None = None,
    raise_on_approval: bool | None = None,
    return_execution_result: bool | None = None,
) -> Callable[..., Any]:
    """Wraps a callable tool with AgentShield security evaluation."""
    effective_name = tool_name or func.__name__
    effective_raise_block = (
        raise_on_block if raise_on_block is not None else shield_client.config.raise_on_block
    )
    effective_raise_approval = (
        raise_on_approval
        if raise_on_approval is not None
        else shield_client.config.raise_on_approval
    )
    effective_return_result = (
        return_execution_result
        if return_execution_result is not None
        else shield_client.config.return_execution_result
    )

    sig = inspect.signature(func)
    is_async = inspect.iscoroutinefunction(func)

    def _record_audit(result_obj: ToolExecutionResult) -> None:
        event = AuditEvent(
            event_id=result_obj.event_id,
            timestamp=datetime.now(UTC),
            tool_name=effective_name,
            decision=result_obj.decision,
            policy_id=result_obj.policy_id,
            reason_codes=result_obj.reason_codes,
            destination_class=result_obj.destination_class,
            data_labels=result_obj.data_labels,
            risk_signals=result_obj.risk_signals,
            payload_fingerprint=result_obj.payload_fingerprint,
            execution_status=result_obj.execution_status,
        )
        shield_client.record_audit_event(event)

    def _process_decision(
        eval_result: Any,
        extracted_args: dict[str, Any],
        bound: inspect.BoundArguments,
        execute_fn: Callable[[], Any],
    ) -> Any:
        decision = eval_result.decision
        event_id = eval_result.event_id
        policy_id = eval_result.policy_id
        reason_codes = list(eval_result.reason_codes)
        destination_class = eval_result.destination_class
        data_labels = list(eval_result.data_labels)
        risk_signals = list(eval_result.risk_signals)
        payload_fingerprint = eval_result.payload_fingerprint
        explanation = eval_result.explanation

        # 1. ALLOW
        if decision == SecurityDecision.ALLOW:
            try:
                fn_result = execute_fn()
                status = ExecutionStatus.EXECUTED
            except Exception as exc:
                failed_res = ToolExecutionResult(
                    event_id=event_id,
                    tool_name=effective_name,
                    decision=decision,
                    policy_id=policy_id,
                    reason_codes=reason_codes + ["EXECUTION_FAILED"],
                    destination_class=destination_class,
                    data_labels=data_labels,
                    risk_signals=risk_signals,
                    payload_fingerprint=payload_fingerprint,
                    execution_status=ExecutionStatus.FAILED,
                    explanation=f"Function execution failed: {str(exc)}",
                    result=None,
                )
                shield_client.last_result = failed_res
                _record_audit(failed_res)
                raise exc

            result_obj = ToolExecutionResult(
                event_id=event_id,
                tool_name=effective_name,
                decision=decision,
                policy_id=policy_id,
                reason_codes=reason_codes,
                destination_class=destination_class,
                data_labels=data_labels,
                risk_signals=risk_signals,
                payload_fingerprint=payload_fingerprint,
                execution_status=status,
                explanation=explanation,
                result=fn_result,
            )
            shield_client.last_result = result_obj
            _record_audit(result_obj)
            return result_obj if effective_return_result else fn_result

        # 2. REDACT
        if decision == SecurityDecision.REDACT:
            redacted_arguments = eval_result.redacted_arguments
            if not isinstance(redacted_arguments, dict):
                # Safe fail-closed: do NOT execute function
                status = ExecutionStatus.FAILED
                result_obj = ToolExecutionResult(
                    event_id=event_id,
                    tool_name=effective_name,
                    decision=SecurityDecision.BLOCK,
                    policy_id=policy_id,
                    reason_codes=reason_codes + ["MISSING_REDACTED_ARGUMENTS"],
                    destination_class=destination_class,
                    data_labels=data_labels,
                    risk_signals=risk_signals,
                    payload_fingerprint=payload_fingerprint,
                    execution_status=status,
                    explanation="Redacted arguments missing or invalid; execution blocked for safety.",
                    result=None,
                )
                shield_client.last_result = result_obj
                _record_audit(result_obj)
                if effective_raise_block:
                    raise AgentShieldBlockError(
                        explanation=result_obj.explanation,
                        event_id=event_id,
                        policy_id=policy_id,
                        reason_codes=result_obj.reason_codes,
                        execution_result=result_obj,
                    )
                return result_obj

            _apply_redactions_to_bound(bound, sig, redacted_arguments)
            try:
                fn_result = execute_fn()
                status = ExecutionStatus.REDACTED_AND_EXECUTED
            except Exception as exc:
                failed_res = ToolExecutionResult(
                    event_id=event_id,
                    tool_name=effective_name,
                    decision=decision,
                    policy_id=policy_id,
                    reason_codes=reason_codes + ["EXECUTION_FAILED"],
                    destination_class=destination_class,
                    data_labels=data_labels,
                    risk_signals=risk_signals,
                    payload_fingerprint=payload_fingerprint,
                    execution_status=ExecutionStatus.FAILED,
                    explanation=f"Function execution failed: {str(exc)}",
                    result=None,
                )
                shield_client.last_result = failed_res
                _record_audit(failed_res)
                raise exc

            result_obj = ToolExecutionResult(
                event_id=event_id,
                tool_name=effective_name,
                decision=decision,
                policy_id=policy_id,
                reason_codes=reason_codes,
                destination_class=destination_class,
                data_labels=data_labels,
                risk_signals=risk_signals,
                payload_fingerprint=payload_fingerprint,
                execution_status=status,
                explanation=explanation,
                result=fn_result,
            )
            shield_client.last_result = result_obj
            _record_audit(result_obj)
            return result_obj if effective_return_result else fn_result

        # 3. REQUIRE_APPROVAL
        if decision == SecurityDecision.REQUIRE_APPROVAL:
            status = ExecutionStatus.PENDING_APPROVAL
            approval_id = f"apr-{event_id}"
            result_obj = ToolExecutionResult(
                event_id=event_id,
                tool_name=effective_name,
                decision=decision,
                policy_id=policy_id,
                reason_codes=reason_codes,
                destination_class=destination_class,
                data_labels=data_labels,
                risk_signals=risk_signals,
                payload_fingerprint=payload_fingerprint,
                execution_status=status,
                explanation=explanation,
                result=None,
                approval_id=approval_id,
            )
            shield_client.last_result = result_obj
            _record_audit(result_obj)
            if effective_raise_approval:
                raise AgentShieldApprovalRequiredError(
                    explanation=explanation,
                    event_id=event_id,
                    policy_id=policy_id,
                    approval_id=approval_id,
                    reason_codes=reason_codes,
                    execution_result=result_obj,
                )
            return result_obj

        # 4. BLOCK (and fallback)
        status = ExecutionStatus.NOT_EXECUTED
        result_obj = ToolExecutionResult(
            event_id=event_id,
            tool_name=effective_name,
            decision=SecurityDecision.BLOCK,
            policy_id=policy_id,
            reason_codes=reason_codes,
            destination_class=destination_class,
            data_labels=data_labels,
            risk_signals=risk_signals,
            payload_fingerprint=payload_fingerprint,
            execution_status=status,
            explanation=explanation,
            result=None,
        )
        shield_client.last_result = result_obj
        _record_audit(result_obj)
        if effective_raise_block:
            raise AgentShieldBlockError(
                explanation=explanation,
                event_id=event_id,
                policy_id=policy_id,
                reason_codes=reason_codes,
                execution_result=result_obj,
            )
        return result_obj

    if is_async:

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                extracted_args, bound = _extract_argument_dict(sig, *args, **kwargs)
            except TypeError as exc:
                raise AgentShieldError(
                    f"Arguments do not match tool signature for '{effective_name}': {str(exc)}"
                ) from exc

            tool_call = ToolCall(tool_name=effective_name, arguments=extracted_args)
            eval_result = shield_client.evaluate_tool_call(tool_call)

            # Define execution closure for async function
            async def _async_exec() -> Any:
                return await func(*bound.args, **bound.kwargs)

            # We adapt execution handling for async
            decision = eval_result.decision
            if decision == SecurityDecision.ALLOW:
                try:
                    fn_res = await _async_exec()
                    status = ExecutionStatus.EXECUTED
                except Exception as exc:
                    failed_res = ToolExecutionResult(
                        event_id=eval_result.event_id,
                        tool_name=effective_name,
                        decision=decision,
                        policy_id=eval_result.policy_id,
                        reason_codes=list(eval_result.reason_codes) + ["EXECUTION_FAILED"],
                        destination_class=eval_result.destination_class,
                        data_labels=list(eval_result.data_labels),
                        risk_signals=list(eval_result.risk_signals),
                        payload_fingerprint=eval_result.payload_fingerprint,
                        execution_status=ExecutionStatus.FAILED,
                        explanation=f"Function execution failed: {str(exc)}",
                        result=None,
                    )
                    shield_client.last_result = failed_res
                    _record_audit(failed_res)
                    raise exc

                res_obj = ToolExecutionResult(
                    event_id=eval_result.event_id,
                    tool_name=effective_name,
                    decision=decision,
                    policy_id=eval_result.policy_id,
                    reason_codes=list(eval_result.reason_codes),
                    destination_class=eval_result.destination_class,
                    data_labels=list(eval_result.data_labels),
                    risk_signals=list(eval_result.risk_signals),
                    payload_fingerprint=eval_result.payload_fingerprint,
                    execution_status=status,
                    explanation=eval_result.explanation,
                    result=fn_res,
                )
                shield_client.last_result = res_obj
                _record_audit(res_obj)
                async_wrapper.last_result = res_obj
                return res_obj if effective_return_result else fn_res

            if decision == SecurityDecision.REDACT:
                redacted_arguments = eval_result.redacted_arguments
                if not isinstance(redacted_arguments, dict):
                    status = ExecutionStatus.FAILED
                    res_obj = ToolExecutionResult(
                        event_id=eval_result.event_id,
                        tool_name=effective_name,
                        decision=SecurityDecision.BLOCK,
                        policy_id=eval_result.policy_id,
                        reason_codes=list(eval_result.reason_codes) + ["MISSING_REDACTED_ARGUMENTS"],
                        destination_class=eval_result.destination_class,
                        data_labels=list(eval_result.data_labels),
                        risk_signals=list(eval_result.risk_signals),
                        payload_fingerprint=eval_result.payload_fingerprint,
                        execution_status=status,
                        explanation="Redacted arguments missing or invalid; execution blocked for safety.",
                        result=None,
                    )
                    shield_client.last_result = res_obj
                    _record_audit(res_obj)
                    async_wrapper.last_result = res_obj
                    if effective_raise_block:
                        raise AgentShieldBlockError(
                            explanation=res_obj.explanation,
                            event_id=eval_result.event_id,
                            policy_id=eval_result.policy_id,
                            reason_codes=res_obj.reason_codes,
                            execution_result=res_obj,
                        )
                    return res_obj

                _apply_redactions_to_bound(bound, sig, redacted_arguments)
                try:
                    fn_res = await _async_exec()
                    status = ExecutionStatus.REDACTED_AND_EXECUTED
                except Exception as exc:
                    failed_res = ToolExecutionResult(
                        event_id=eval_result.event_id,
                        tool_name=effective_name,
                        decision=decision,
                        policy_id=eval_result.policy_id,
                        reason_codes=list(eval_result.reason_codes) + ["EXECUTION_FAILED"],
                        destination_class=eval_result.destination_class,
                        data_labels=list(eval_result.data_labels),
                        risk_signals=list(eval_result.risk_signals),
                        payload_fingerprint=eval_result.payload_fingerprint,
                        execution_status=ExecutionStatus.FAILED,
                        explanation=f"Function execution failed: {str(exc)}",
                        result=None,
                    )
                    shield_client.last_result = failed_res
                    _record_audit(failed_res)
                    raise exc

                res_obj = ToolExecutionResult(
                    event_id=eval_result.event_id,
                    tool_name=effective_name,
                    decision=decision,
                    policy_id=eval_result.policy_id,
                    reason_codes=list(eval_result.reason_codes),
                    destination_class=eval_result.destination_class,
                    data_labels=list(eval_result.data_labels),
                    risk_signals=list(eval_result.risk_signals),
                    payload_fingerprint=eval_result.payload_fingerprint,
                    execution_status=status,
                    explanation=eval_result.explanation,
                    result=fn_res,
                )
                shield_client.last_result = res_obj
                _record_audit(res_obj)
                async_wrapper.last_result = res_obj
                return res_obj if effective_return_result else fn_res

            # REQUIRE_APPROVAL or BLOCK
            res = _process_decision(
                eval_result,
                extracted_args,
                bound,
                lambda: None,
            )
            async_wrapper.last_result = shield_client.last_result
            return res

        async_wrapper.tool_name = effective_name
        async_wrapper.shield = shield_client
        async_wrapper.last_result = None
        return async_wrapper

    else:

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                extracted_args, bound = _extract_argument_dict(sig, *args, **kwargs)
            except TypeError as exc:
                raise AgentShieldError(
                    f"Arguments do not match tool signature for '{effective_name}': {str(exc)}"
                ) from exc

            tool_call = ToolCall(tool_name=effective_name, arguments=extracted_args)
            eval_result = shield_client.evaluate_tool_call(tool_call)

            res = _process_decision(
                eval_result,
                extracted_args,
                bound,
                lambda: func(*bound.args, **bound.kwargs),
            )
            sync_wrapper.last_result = shield_client.last_result
            return res

        sync_wrapper.tool_name = effective_name
        sync_wrapper.shield = shield_client
        sync_wrapper.last_result = None
        return sync_wrapper
