from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.core.config import resolve_policy_path
from backend.app.core.policy_loader import (
    PolicyFileNotFoundError,
    PolicyParseError,
    PolicyValidationError,
    load_policy,
)
from backend.app.core.policy_models import PolicyConfiguration
from backend.app.models import DestinationClass, SecurityDecision


VALID_POLICY = """
version: 1
defaults:
  unknown_destination: REQUIRE_APPROVAL
  evaluation_error: BLOCK
approved_domains:
  - example.org
protected_values:
  - name: demo_secret
    value: DEMO_SECRET
    action: BLOCK
rules:
  - id: block-secret
    description: Block protected data externally
    tools: [send_email, http_post]
    data_labels: [PROTECTED]
    destination_classes: [UNAPPROVED, UNKNOWN]
    decision: BLOCK
  - id: approve-export
    description: Require export approval
    tools: [export_file]
    destination_classes: [UNAPPROVED]
    decision: REQUIRE_APPROVAL
"""


def write_policy(tmp_path: Path, content: str) -> Path:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


def test_default_policy_loads_successfully() -> None:
    policy = load_policy(resolve_policy_path())

    assert policy.version == 1
    assert policy.approved_domains == ["example.org"]


def test_valid_yaml_policy_loads_successfully(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, VALID_POLICY))

    assert policy.defaults.unknown_destination == SecurityDecision.REQUIRE_APPROVAL
    assert policy.defaults.evaluation_error == SecurityDecision.BLOCK


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    policy_path = write_policy(tmp_path, "version: [unclosed")

    with pytest.raises(PolicyParseError):
        load_policy(policy_path)


def test_missing_policy_file_handled_safely(tmp_path: Path) -> None:
    with pytest.raises(PolicyFileNotFoundError):
        load_policy(tmp_path / "missing.yaml")


def test_missing_required_policy_fields_rejected(tmp_path: Path) -> None:
    policy_path = write_policy(tmp_path, "version: 1\n")

    with pytest.raises(PolicyValidationError):
        load_policy(policy_path)


def test_invalid_decision_value_rejected(tmp_path: Path) -> None:
    invalid = VALID_POLICY.replace(
        "decision: REQUIRE_APPROVAL",
        "decision: DENY",
        1,
    )
    policy_path = write_policy(tmp_path, invalid)

    with pytest.raises(PolicyValidationError):
        load_policy(policy_path)


def test_invalid_destination_class_rejected(tmp_path: Path) -> None:
    invalid = VALID_POLICY.replace(
        "destination_classes: [UNAPPROVED, UNKNOWN]",
        "destination_classes: [OUTSIDE]",
    )
    policy_path = write_policy(tmp_path, invalid)

    with pytest.raises(PolicyValidationError):
        load_policy(policy_path)


def test_invalid_policy_version_rejected(tmp_path: Path) -> None:
    invalid = VALID_POLICY.replace("version: 1", "version: 2", 1)
    policy_path = write_policy(tmp_path, invalid)

    with pytest.raises(PolicyValidationError):
        load_policy(policy_path)


def test_protected_values_are_parsed_correctly(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, VALID_POLICY))

    assert len(policy.protected_values) == 1
    assert policy.protected_values[0].name == "demo_secret"
    assert policy.protected_values[0].value == "DEMO_SECRET"
    assert policy.protected_values[0].action == SecurityDecision.BLOCK


def test_multiple_policy_rules_are_loaded_correctly(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, VALID_POLICY))

    assert len(policy.rules) == 2
    assert policy.rules[0].decision == SecurityDecision.BLOCK
    assert policy.rules[1].decision == SecurityDecision.REQUIRE_APPROVAL
    assert DestinationClass.UNAPPROVED in policy.rules[0].destination_classes


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    invalid = VALID_POLICY.replace(
        "id: approve-export",
        "id: block-secret",
        1,
    )
    policy_path = write_policy(tmp_path, invalid)

    with pytest.raises(PolicyValidationError):
        load_policy(policy_path)
