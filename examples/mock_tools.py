"""In-memory mock tools protected by AgentShield."""

from typing import Any

from sdk.agentshield import AgentShield
from sdk.agentshield.results import ToolExecutionResult


class MockTools:
    def __init__(self, shield: AgentShield) -> None:
        self.shield = shield
        self.last_arguments: dict[str, Any] = {}
        self.call_counts = {
            "send_email": 0,
            "generate_report": 0,
            "export_file": 0,
        }

        @shield.protect_tool(tool_name="send_email", return_execution_result=True)
        def send_email(
            to: str,
            subject: str,
            body: str,
            context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            self.call_counts["send_email"] += 1
            self.last_arguments = {
                "to": to,
                "subject": subject,
                "body": body,
                "context": context,
            }
            return {
                "status": "sent",
                "recipient": to,
                "subject": subject,
                "mode": "mock",
            }

        @shield.protect_tool(tool_name="generate_report", return_execution_result=True)
        def generate_report(
            destination: str,
            title: str,
            summary: str,
        ) -> dict[str, Any]:
            self.call_counts["generate_report"] += 1
            return {
                "status": "generated",
                "destination": destination,
                "title": title,
                "mode": "mock",
            }

        @shield.protect_tool(tool_name="export_file", return_execution_result=True)
        def export_file(
            to: str,
            filename: str,
            context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            self.call_counts["export_file"] += 1
            return {
                "status": "exported",
                "destination": to,
                "filename": filename,
                "mode": "mock",
            }

        self.send_email = send_email
        self.generate_report = generate_report
        self.export_file = export_file

    def reset_call_counts(self) -> None:
        for tool_name in self.call_counts:
            self.call_counts[tool_name] = 0
