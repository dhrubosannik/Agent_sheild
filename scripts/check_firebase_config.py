"""Report the active Firebase configuration and anything missing.

Never prints credential contents or paths. Exit code 1 when invalid.

    python scripts/check_firebase_config.py
    AGENTSHIELD_ENV_FILE=.env.cloud python scripts/check_firebase_config.py
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.firebase_config import validate_firebase_configuration  # noqa: E402


def main() -> None:
    env_file = os.environ.get("AGENTSHIELD_ENV_FILE", ".env")
    print(f"Env file: {env_file} ({'found' if Path(env_file).is_file() else 'not found'})")
    report = validate_firebase_configuration(get_settings())
    print(report.render())
    print("Configuration OK" if report.ok else "Configuration INVALID")
    raise SystemExit(0 if report.ok else 1)


if __name__ == "__main__":
    main()
