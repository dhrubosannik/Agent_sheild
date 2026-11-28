"""Firebase environment selection and validation.

The backend talks to exactly one Firebase target, chosen explicitly with
``FIREBASE_TARGET``:

* ``none`` (default): no Firebase. SQLite storage and explicit development
  identities only. Refused in production.
* ``emulator``: the local Firebase Emulator Suite. Both emulator hosts must be
  set, so no request can fall through to the cloud. A ``demo-*`` project ID is
  strongly recommended (the emulator never contacts Google for demo projects)
  and required during automated tests.
* ``cloud``: the shared Firebase project. Must be chosen explicitly, must not
  be mixed with emulator hosts, is refused during automated tests, and outside
  production also requires ``FIREBASE_CLOUD_PROJECT_CONFIRM`` to repeat the
  project ID (protection against connecting to shared data by accident).

Nothing here creates or modifies a Firebase project. Messages never include
credential contents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re

from .config import Settings

TARGETS = ("none", "emulator", "cloud")
PROJECT_ROOT = Path(__file__).resolve().parents[3]
_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_PLACEHOLDER_RE = re.compile(r"(<|>|your[-_]|placeholder|changeme|example-project|xxx)", re.IGNORECASE)


class FirebaseConfigurationError(RuntimeError):
    pass


@dataclass
class FirebaseConfigReport:
    target: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def render(self) -> str:
        lines = [f"Firebase target: {self.target}"]
        lines += [f"  {key}: {value}" for key, value in self.summary.items()]
        lines += [f"ERROR: {message}" for message in self.errors]
        lines += [f"WARNING: {message}" for message in self.warnings]
        return "\n".join(lines)


def is_test_mode() -> bool:
    return os.environ.get("AGENTSHIELD_TEST_MODE") == "1"


def firebase_target(settings: Settings) -> str:
    return (settings.firebase_target or "none").strip().lower()


def emulator_hosts(settings: Settings) -> tuple[str | None, str | None]:
    auth_host = settings.firebase_auth_emulator_host or os.environ.get("FIREBASE_AUTH_EMULATOR_HOST")
    firestore_host = settings.firestore_emulator_host or os.environ.get("FIRESTORE_EMULATOR_HOST")
    return (auth_host or None), (firestore_host or None)


def _needs_firestore(settings: Settings) -> bool:
    return settings.database_mode.lower() == "firestore" or settings.rate_limit_backend.lower() == "firestore"


def _check_project_id(project_id: str | None, report: FirebaseConfigReport) -> None:
    if not project_id:
        report.errors.append("FIREBASE_PROJECT_ID is required for this FIREBASE_TARGET.")
        return
    if _PLACEHOLDER_RE.search(project_id):
        report.errors.append(
            "FIREBASE_PROJECT_ID still contains a placeholder; set the real shared project ID "
            "supplied by the Firebase project owner."
        )
    elif not _PROJECT_ID_RE.match(project_id):
        report.errors.append(f"FIREBASE_PROJECT_ID {project_id!r} is not a valid Firebase/GCP project ID.")


def validate_firebase_configuration(settings: Settings, test_mode: bool | None = None) -> FirebaseConfigReport:
    test_mode = is_test_mode() if test_mode is None else test_mode
    target = firebase_target(settings)
    report = FirebaseConfigReport(target=target)
    production = settings.environment.lower() == "production"
    auth_host, firestore_host = emulator_hosts(settings)
    credentials_path = settings.google_application_credentials

    report.summary = {
        "environment": settings.environment,
        "database_mode": settings.database_mode,
        "firebase_auth_required": settings.firebase_auth_required,
        "project_id": settings.firebase_project_id or "(not set)",
        "firestore_database_id": settings.firestore_database_id,
        "auth_emulator": auth_host or "(not set)",
        "firestore_emulator": firestore_host or "(not set)",
        "admin_credentials": (
            "service-account file configured" if credentials_path
            else "Application Default Credentials" if target == "cloud" else "(not used)"
        ),
    }

    if target not in TARGETS:
        report.errors.append(f"FIREBASE_TARGET must be one of {', '.join(TARGETS)} (got {target!r}).")
        return report

    if target == "none":
        if production:
            report.errors.append("Production requires FIREBASE_TARGET=cloud.")
        if settings.database_mode.lower() == "firestore":
            report.errors.append("DATABASE_MODE=firestore requires FIREBASE_TARGET=emulator or FIREBASE_TARGET=cloud.")
        if settings.rate_limit_backend.lower() == "firestore":
            report.errors.append("RATE_LIMIT_BACKEND=firestore requires FIREBASE_TARGET=emulator or FIREBASE_TARGET=cloud.")
        if settings.firebase_auth_required:
            report.errors.append("FIREBASE_AUTH_REQUIRED=true requires FIREBASE_TARGET=emulator or FIREBASE_TARGET=cloud.")
        if settings.firebase_project_id:
            report.warnings.append(
                "FIREBASE_PROJECT_ID is set but ignored because FIREBASE_TARGET=none. "
                "Set FIREBASE_TARGET=emulator or FIREBASE_TARGET=cloud explicitly."
            )
        return report

    if target == "emulator":
        if production:
            report.errors.append("FIREBASE_TARGET=emulator is not allowed in production.")
        if not settings.firebase_project_id:
            report.errors.append("FIREBASE_PROJECT_ID is required (use a demo-* ID such as demo-agentshield).")
        elif not settings.firebase_project_id.startswith("demo-"):
            message = (
                f"Emulator project {settings.firebase_project_id!r} is not a demo-* project. Use demo-agentshield "
                "so no emulator request can ever be attributed to the shared cloud project."
            )
            (report.errors if test_mode else report.warnings).append(message)
        if not auth_host:
            report.errors.append("FIREBASE_AUTH_EMULATOR_HOST is required for FIREBASE_TARGET=emulator (e.g. 127.0.0.1:9099).")
        if _needs_firestore(settings) and not firestore_host:
            report.errors.append("FIRESTORE_EMULATOR_HOST is required for FIREBASE_TARGET=emulator with Firestore (e.g. 127.0.0.1:8080).")
        if credentials_path:
            report.warnings.append("GOOGLE_APPLICATION_CREDENTIALS is ignored for FIREBASE_TARGET=emulator; unset it to avoid confusion.")
        return report

    # cloud
    if test_mode:
        report.errors.append(
            "FIREBASE_TARGET=cloud is refused during automated tests. Tests must use the emulator "
            "(demo-agentshield) so shared Firestore data is never modified."
        )
    _check_project_id(settings.firebase_project_id, report)
    if auth_host or firestore_host:
        report.errors.append(
            "FIREBASE_TARGET=cloud must not be combined with FIREBASE_AUTH_EMULATOR_HOST or "
            "FIRESTORE_EMULATOR_HOST (unset them, including in your shell)."
        )
    if not production and settings.firebase_cloud_project_confirm != settings.firebase_project_id:
        report.errors.append(
            "Connecting a development machine to the shared cloud project requires "
            "FIREBASE_CLOUD_PROJECT_CONFIRM to equal FIREBASE_PROJECT_ID."
        )
    if credentials_path:
        path = Path(credentials_path).expanduser()
        if not path.is_file():
            report.errors.append("GOOGLE_APPLICATION_CREDENTIALS points to a file that does not exist.")
        else:
            try:
                path.resolve().relative_to(PROJECT_ROOT)
                inside_repo = True
            except ValueError:
                inside_repo = False
            if inside_repo:
                report.errors.append(
                    "The service-account credentials file is inside the repository. Move it outside the project "
                    "(e.g. ~/.config/agentshield/) so it can never be committed."
                )
    else:
        report.warnings.append(
            "No GOOGLE_APPLICATION_CREDENTIALS file: Firebase Admin will use Application Default Credentials "
            "(gcloud auth application-default login, or the platform's attached service account)."
        )
    return report


def enforce_firebase_configuration(settings: Settings) -> FirebaseConfigReport:
    report = validate_firebase_configuration(settings)
    if not report.ok:
        raise FirebaseConfigurationError(
            "Invalid Firebase configuration:\n- " + "\n- ".join(report.errors)
            + "\nRun: python scripts/check_firebase_config.py"
        )
    return report
