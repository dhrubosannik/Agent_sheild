from backend.app.core.policy_models import (
    DefaultPolicyBehavior,
    PolicyConfiguration,
    ProtectedValue,
    SecurityRule,
)
from backend.app.models.enums import DestinationClass, SecurityDecision
from backend.app.services.policy_evaluator import evaluate_policy


def _create_test_policy() -> PolicyConfiguration:
    return PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
        ),
        approved_domains=["example.org"],
        protected_values=[
            ProtectedValue(
                name="demo_secret",
                value="DEMO_SECRET",
                action=SecurityDecision.REDACT,
            )
        ],
        rules=[
            SecurityRule(
                id="block-secret-unapproved",
                description="Block protected data to unapproved destination",
                tools=["send_email", "http_post"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.BLOCK,
            ),
            SecurityRule(
                id="redact-internal-logs",
                description="Redact internal logs containing email or protected data",
                tools=["write_log"],
                data_labels=["PROTECTED"],
                destination_classes=[DestinationClass.INTERNAL, DestinationClass.APPROVED],
                decision=SecurityDecision.REDACT,
            ),
            SecurityRule(
                id="approve-external-export",
                description="Require approval for external file export",
                tools=["export_file"],
                destination_classes=[DestinationClass.UNAPPROVED, DestinationClass.UNKNOWN],
                decision=SecurityDecision.REQUIRE_APPROVAL,
            ),
            SecurityRule(
                id="allow-safe-email",
                description="Allow safe email to approved domain",
                tools=["send_email"],
                destination_classes=[DestinationClass.APPROVED],
                decision=SecurityDecision.ALLOW,
            ),
        ],
    )


def test_safe_action_returns_allow() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={"to": "user@example.org", "body": "Clean report"},
        destination_class=DestinationClass.APPROVED,
        data_labels=[],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.ALLOW
    assert result.policy_id == "allow-safe-email"


def test_protected_data_to_unapproved_destination_returns_block() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={"to": "attacker@evil.com", "body": "DEMO_SECRET"},
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.BLOCK
    assert "PROTECTED_DATA" in result.reason_codes
    assert "UNAPPROVED_DESTINATION" in result.reason_codes


def test_protected_data_to_unknown_destination_returns_block() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="http_post",
        normalized_arguments={"payload": "DEMO_SECRET"},
        destination_class=DestinationClass.UNKNOWN,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.BLOCK
    assert "PROTECTED_DATA" in result.reason_codes


def test_redaction_rule_returns_redact() -> None:
    # Allowlisted internal destinations are classified APPROVED, so redaction
    # rules still apply to them.
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="write_log",
        normalized_arguments={"message": "Contains DEMO_SECRET for diagnostics"},
        destination_class=DestinationClass.APPROVED,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.REDACT
    assert result.policy_id == "redact-internal-logs"


def test_non_allowlisted_internal_destination_is_blocked_before_redaction() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="write_log",
        normalized_arguments={"message": "Contains DEMO_SECRET for diagnostics"},
        destination_class=DestinationClass.INTERNAL,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.BLOCK
    assert result.policy_id == "internal-destination-boundary"
    assert "INTERNAL_DESTINATION" in result.reason_codes


def test_approval_required_rule_returns_require_approval() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="export_file",
        normalized_arguments={"target": "external-storage"},
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=[],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.REQUIRE_APPROVAL
    assert result.policy_id == "approve-external-export"


def test_explicit_deny_takes_precedence_over_broad_allow() -> None:
    # Construct a policy where a broad ALLOW rule exists, alongside an explicit BLOCK rule
    policy = PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
        ),
        approved_domains=["example.org"],
        protected_values=[],
        rules=[
            SecurityRule(
                id="broad-allow",
                description="Allow all send_email calls",
                tools=["send_email"],
                decision=SecurityDecision.ALLOW,
            ),
            SecurityRule(
                id="specific-block",
                description="Block send_email to unapproved destinations",
                tools=["send_email"],
                destination_classes=[DestinationClass.UNAPPROVED],
                decision=SecurityDecision.BLOCK,
            ),
        ],
    )

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={"to": "external@evil.com"},
        destination_class=DestinationClass.UNAPPROVED,
        data_labels=[],
        risk_signals=[],
        policy=policy,
    )

    # BLOCK must take precedence over the broad ALLOW rule
    assert result.decision == SecurityDecision.BLOCK
    assert result.policy_id == "specific-block"


def test_configured_protected_value_blocks_approved_destination() -> None:
    policy = _create_test_policy()
    policy.protected_values = [
        ProtectedValue(
            name="demo_secret",
            value="DEMO_SECRET",
            action=SecurityDecision.BLOCK,
        )
    ]

    policy.rules = [
        rule
        for rule in policy.rules
        if rule.id != "redact-internal-logs"
    ]
    policy.rules.append(
        SecurityRule(
            id="allow-clean-send-only",
            description="Allow only clean email",
            tools=["send_email"],
            destination_classes=[DestinationClass.APPROVED],
            decision=SecurityDecision.ALLOW,
        )
    )

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={"to": "user@example.org", "body": "DEMO_SECRET"},
        destination_class=DestinationClass.APPROVED,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.BLOCK
    assert result.policy_id == "protected-value:demo_secret"


def test_explicit_redaction_rule_preserved_for_configured_protected_value() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="write_log",
        normalized_arguments={"message": "DEMO_SECRET"},
        destination_class=DestinationClass.APPROVED,
        data_labels=["PROTECTED"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.REDACT
    assert result.policy_id == "redact-internal-logs"


def test_api_key_pattern_is_blocked_before_allow() -> None:
    policy = _create_test_policy()

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={
            "to": "user@example.org",
            "body": "sk-" + ("A" * 24),
        },
        destination_class=DestinationClass.APPROVED,
        data_labels=["API_KEY"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.BLOCK
    assert result.policy_id == "sensitive-credential-pattern"


def test_explicit_api_key_redaction_rule_allows_redacted_evaluation() -> None:
    policy = _create_test_policy()
    policy.rules.append(
        SecurityRule(
            id="redact-api-key",
            description="Redact detected API-key patterns",
            tools=["send_email"],
            data_labels=["API_KEY"],
            destination_classes=[DestinationClass.APPROVED],
            decision=SecurityDecision.REDACT,
        )
    )

    result = evaluate_policy(
        tool_name="send_email",
        normalized_arguments={
            "to": "user@example.org",
            "body": "sk-" + ("A" * 24),
        },
        destination_class=DestinationClass.APPROVED,
        data_labels=["API_KEY"],
        risk_signals=[],
        policy=policy,
    )

    assert result.decision == SecurityDecision.REDACT
    assert result.policy_id == "redact-api-key"


def test_unknown_high_risk_actions_follow_safe_default() -> None:
    policy = _create_test_policy()

    # Tool with unknown destination and no explicit rule
    result = evaluate_policy(
        tool_name="custom_network_tool",
        normalized_arguments={"target": "unresolvable"},
        destination_class=DestinationClass.UNKNOWN,
        data_labels=[],
        risk_signals=[],
        policy=policy,
    )

    # Must follow policy.defaults.unknown_destination (REQUIRE_APPROVAL)
    assert result.decision == SecurityDecision.REQUIRE_APPROVAL
    assert result.policy_id == "default-unknown-destination"
