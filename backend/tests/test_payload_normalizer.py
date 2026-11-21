import pytest

from backend.app.services.payload_normalizer import (
    NormalizationError,
    compute_payload_fingerprint,
    normalize_arguments,
    normalize_value,
)


def test_normalize_valid_payload() -> None:
    raw = {
        "b": 2,
        "a": "hello",
        "c": [3, 1, 2],
        "d": {"y": True, "x": None},
    }
    normalized = normalize_arguments(raw)

    # Keys in dictionaries should be preserved and sorted
    assert list(normalized.keys()) == ["a", "b", "c", "d"]
    assert list(normalized["d"].keys()) == ["x", "y"]
    assert normalized["c"] == [3, 1, 2]


def test_key_whitespace_stripping() -> None:
    raw = {"  key1  ": "value1", "key2": "value2"}
    normalized = normalize_arguments(raw)

    assert "key1" in normalized
    assert normalized["key1"] == "value1"


def test_rejection_of_empty_dict_keys() -> None:
    with pytest.raises(NormalizationError, match="cannot be empty"):
        normalize_arguments({"   ": "value"})


def test_rejection_of_non_string_keys() -> None:
    with pytest.raises(NormalizationError, match="must be strings"):
        normalize_value({123: "value"})  # type: ignore[dict-item]


def test_rejection_of_nan_and_inf() -> None:
    with pytest.raises(NormalizationError, match="NaN"):
        normalize_arguments({"num": float("nan")})

    with pytest.raises(NormalizationError, match="infinite"):
        normalize_arguments({"num": float("inf")})

    with pytest.raises(NormalizationError, match="infinite"):
        normalize_arguments({"num": float("-inf")})


def test_nesting_depth_limit() -> None:
    current: dict[str, object] = {"leaf": 1}
    for _ in range(25):
        current = {"nested": current}

    with pytest.raises(NormalizationError, match="maximum nesting depth"):
        normalize_arguments(current)


def test_fingerprint_deterministic_consistency() -> None:
    payload1 = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    payload2 = {"a": 1, "c": {"x": 10, "y": 20}, "b": 2}

    fp1 = compute_payload_fingerprint(payload1)
    fp2 = compute_payload_fingerprint(payload2)

    assert fp1.startswith("sha256:")
    assert fp1 == fp2


def test_different_payloads_produce_different_fingerprints() -> None:
    payload1 = {"action": "read", "target": "document1"}
    payload2 = {"action": "write", "target": "document1"}

    fp1 = compute_payload_fingerprint(payload1)
    fp2 = compute_payload_fingerprint(payload2)

    assert fp1 != fp2
