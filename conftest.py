"""Root pytest configuration (applies to backend/tests and sdk/tests).

Safety for a shared Firebase project:
* AGENTSHIELD_TEST_MODE=1 makes the backend refuse FIREBASE_TARGET=cloud and
  require demo-* emulator projects, so tests can never touch shared data.
* The developer's own .env / cloud settings are not loaded: the env file is
  pointed at a non-existent path and cloud variables are removed from the
  test process.
* The default audit database is a throwaway file (never data/agentshield.db).
* The shared rate-limit budget is raised so unrelated tests cannot trip it.
Emulator tests (backend/tests/emulator) opt in to FIREBASE_TARGET=emulator.
"""

import os
import tempfile

_TEST_DIR = tempfile.mkdtemp(prefix="agentshield-tests-")
os.environ["AGENTSHIELD_TEST_MODE"] = "1"
os.environ["AGENTSHIELD_ENV_FILE"] = os.path.join(_TEST_DIR, "no-env-file")
for _name in (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIREBASE_CLOUD_PROJECT_CONFIRM",
    "FIREBASE_TARGET",
    "FIREBASE_PROJECT_ID",
    "DATABASE_MODE",
    "FIREBASE_AUTH_REQUIRED",
    "RATE_LIMIT_BACKEND",
):
    if os.environ.get("AGENTSHIELD_EMULATOR_TESTS") != "1" or _name in ("GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_CLOUD_PROJECT_CONFIRM"):
        os.environ.pop(_name, None)
os.environ["AGENTSHIELD_DATABASE_PATH"] = os.path.join(_TEST_DIR, "agentshield-test.db")
os.environ.setdefault("RATE_LIMIT_REQUESTS", "1000000")
