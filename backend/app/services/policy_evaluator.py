"""Deterministic policy evaluation engine for AgentShield."""

from typing import Any

from ..core.policy_models import PolicyConfiguration, SecurityRule
from ..models.enums import DestinationClass, SecurityDecision
from ..models.risk_signal import RiskSignal


class EvaluationDecision:
    def __init__(
        self,
        decision: SecurityDecision,
        policy_id: str,
        reason_codes: list[str],
        explanation: str,
    ) -> None:
        self.decision = decision
        self.policy_id = policy_id
        self.reason_codes = reason_codes
        self.explanation = explanation


def _matches_rule(
    rule: SecurityRule,
    tool_name: str,
    data_labels: list[str],
    destination_class: DestinationClass,
) -> bool:
    """Evaluates whether a tool call matches all non-empty criteria of a security rule."""
    # 1. Tool check
    if rule.tools and tool_name not in rule.tools:
        return False

    # 2. Data labels check (if rule specifies data_labels, at least one must match)
    if rule.data_labels:
        if not any(label in rule.data_labels for label in data_labels):
            return False

    # 3. Destination class check
    if rule.destination_classes:
        if destination_class not in rule.destination_classes:
            return False

    return True


def evaluate_policy(
    tool_name: str,
    normalized_arguments: dict[str, Any],
    destination_class: DestinationClass,
    data_labels: list[str],
    risk_signals: list[RiskSignal],
    policy: PolicyConfiguration,
) -> EvaluationDecision:
    """Evaluates proposed tool call parameters against policy rules using deterministic precedence.

    Precedence:
    1. Invalid input or internal evaluation failure -> BLOCK
    2. Explicit deny / block rules -> BLOCK
    3. Protected data sent to an unapproved or unknown destination -> BLOCK
    4. Applicable redaction rules -> REDACT
    5. Approval-required rules -> REQUIRE_APPROVAL
    6. Explicit allow rules -> ALLOW
    7. Unknown or unmatched high-risk actions -> safe default (from policy.defaults)
    """
    # Precedence Step 2: Explicit deny rules
    block_rules = [r for r in policy.rules if r.decision == SecurityDecision.BLOCK]
    for rule in block_rules:
        if _matches_rule(rule, tool_name, data_labels, destination_class):
            reasons = ["POLICY_BLOCK_RULE"]
            if "PROTECTED" in data_labels:
                reasons.append("PROTECTED_DATA")
            if destination_class == DestinationClass.UNAPPROVED:
                reasons.append("UNAPPROVED_DESTINATION")
            elif destination_class == DestinationClass.UNKNOWN:
                reasons.append("UNKNOWN_DESTINATION")
            return EvaluationDecision(
                decision=SecurityDecision.BLOCK,
                policy_id=rule.id,
                reason_codes=reasons,
                explanation=f"Action blocked by policy rule '{rule.id}': {rule.description}",
            )

    # Precedence Step 3: Protected data sent to an unapproved or unknown destination -> BLOCK
    if "PROTECTED" in data_labels and destination_class in (DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN):
        dest_code = (
            "UNAPPROVED_DESTINATION"
            if destination_class == DestinationClass.UNAPPROVED
            else "UNKNOWN_DESTINATION"
        )
        return EvaluationDecision(
            decision=SecurityDecision.BLOCK,
            policy_id="protected-data-destination-boundary",
            reason_codes=["PROTECTED_DATA", dest_code],
            explanation="Protected data cannot be sent to an unapproved or unknown destination.",
        )

    # Precedence Step 4: Applicable redaction rules
    redact_rules = [r for r in policy.rules if r.decision == SecurityDecision.REDACT]
    for rule in redact_rules:
        if _matches_rule(rule, tool_name, data_labels, destination_class):
            return EvaluationDecision(
                decision=SecurityDecision.REDACT,
                policy_id=rule.id,
                reason_codes=["POLICY_REDACT_RULE"],
                explanation=f"Action requires argument redaction according to policy rule '{rule.id}': {rule.description}",
            )

    # Precedence Step 5: Approval-required rules
    approval_rules = [r for r in policy.rules if r.decision == SecurityDecision.REQUIRE_APPROVAL]
    for rule in approval_rules:
        if _matches_rule(rule, tool_name, data_labels, destination_class):
            reasons = ["POLICY_APPROVAL_RULE"]
            if destination_class == DestinationClass.UNAPPROVED:
                reasons.append("UNAPPROVED_DESTINATION")
            elif destination_class == DestinationClass.UNKNOWN:
                reasons.append("UNKNOWN_DESTINATION")
            return EvaluationDecision(
                decision=SecurityDecision.REQUIRE_APPROVAL,
                policy_id=rule.id,
                reason_codes=reasons,
                explanation=f"Action requires human approval according to policy rule '{rule.id}': {rule.description}",
            )

    # Precedence Step 6: Explicit allow rules
    allow_rules = [r for r in policy.rules if r.decision == SecurityDecision.ALLOW]
    for rule in allow_rules:
        if _matches_rule(rule, tool_name, data_labels, destination_class):
            return EvaluationDecision(
                decision=SecurityDecision.ALLOW,
                policy_id=rule.id,
                reason_codes=["POLICY_ALLOW_RULE"],
                explanation=f"Action permitted by policy rule '{rule.id}': {rule.description}",
            )

    # Precedence Step 7: Unknown or unmatched actions -> safe defaults
    # If destination is unknown, apply configured default
    if destination_class == DestinationClass.UNKNOWN:
        default_decision = policy.defaults.unknown_destination
        return EvaluationDecision(
            decision=default_decision,
            policy_id="default-unknown-destination",
            reason_codes=["UNKNOWN_DESTINATION", "DEFAULT_POLICY"],
            explanation=f"Destination could not be verified; applying safe default policy: {default_decision.value}",
        )

    # If destination is unapproved (and not already blocked by a rule)
    if destination_class == DestinationClass.UNAPPROVED:
        return EvaluationDecision(
            decision=SecurityDecision.BLOCK,
            policy_id="default-unapproved-destination",
            reason_codes=["UNAPPROVED_DESTINATION", "DEFAULT_POLICY"],
            explanation="Action directed to an unapproved destination without an explicit allow rule.",
        )

    # If destination is approved or internal, and no protected data or blocks
    if destination_class in (DestinationClass.APPROVED, DestinationClass.INTERNAL):
        return EvaluationDecision(
            decision=SecurityDecision.ALLOW,
            policy_id="default-allow-safe",
            reason_codes=["SAFE_ACTION"],
            explanation=f"Action permitted to verified {destination_class.value.lower()} destination without protected data.",
        )

    # Fallback to configured evaluation_error safe default
    fallback = policy.defaults.evaluation_error
    return EvaluationDecision(
        decision=fallback,
        policy_id="default-fallback",
        reason_codes=["UNMATCHED_ACTION", "DEFAULT_POLICY"],
        explanation=f"Action did not match specific rules; applying fallback policy: {fallback.value}",
    )
