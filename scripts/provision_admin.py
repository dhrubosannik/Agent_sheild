"""Securely provision the first Firebase administrator."""

import argparse
import json

import firebase_admin
from firebase_admin import auth, credentials


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", required=True)
    parser.add_argument("--project-id", required=True)
    args = parser.parse_args()

    app = firebase_admin.initialize_app(
        credentials.ApplicationDefault(),
        {"projectId": args.project_id},
    )
    auth.set_custom_user_claims(args.uid, {"role": "ADMIN"}, app=app)
    print(json.dumps({"uid": args.uid, "role": "ADMIN", "status": "configured"}))


if __name__ == "__main__":
    main()
