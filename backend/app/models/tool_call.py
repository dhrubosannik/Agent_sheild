import json
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_ARGUMENT_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 20


def _json_compatible(value: Any, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError("arguments exceed the maximum nesting depth")
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and value != value:
            raise ValueError("arguments cannot contain NaN values")
        if isinstance(value, float) and value in (float("inf"), float("-inf")):
            raise ValueError("arguments cannot contain infinite values")
        return
    if isinstance(value, list):
        for item in value:
            _json_compatible(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("argument object keys must be strings")
            _json_compatible(item, depth + 1)
        return
    raise ValueError("arguments must contain only JSON-compatible values")


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any]
    context: dict[str, Any] | None = None
    request_id: UUID = Field(default_factory=uuid4)

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("tool_name cannot be empty")
        return normalized

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        _json_compatible(value)
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments must be valid JSON") from exc
        if len(encoded.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError("arguments exceed the maximum allowed size")
        return value

    @field_validator("context")
    @classmethod
    def validate_context(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return value
        _json_compatible(value)
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("context must be valid JSON") from exc
        if len(encoded.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError("context exceeds the maximum allowed size")
        return value
