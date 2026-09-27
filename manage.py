#!/usr/bin/env python3
"""Offline setup commands. No scanners or requests are started."""

import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
from werkzeug.security import generate_password_hash
from config import DATABASE_PATH
from database import init_db
import engagement_store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "user", "demo"])
    args = parser.parse_args()
    if args.command == "user":
        username = input("Operator username: ").strip()
        password = getpass.getpass("Password (at least 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if (
            not username
            or len(username) > 100
            or len(password) < 12
            or password != confirm
        ):
            raise SystemExit("Invalid username or passwords do not match / too short")
        folder = Path(__file__).resolve().parent / "instance"
        folder.mkdir(exist_ok=True, mode=0o700)
        settings = {
            "username": username,
            "password_hash": generate_password_hash(password),
            "session_secret": secrets.token_hex(32),
        }
        path = folder / "operator.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(settings, f)
        print(
            "Operator saved. Restart the app to enable login. Keep instance/ out of git."
        )
    else:
        init_db()
        if args.command == "init":
            print("Database initialized:", DATABASE_PATH)
        else:
            cleaned = engagement_store.validate_engagement(
                "PTBot XSS Practice",
                [("url", "http://127.0.0.1:8000/"), ("ip", "127.0.0.1")],
                [],
                {"http_request": 30, "port_scan": 10, "xss_test": 60},
            )
            from workbench_store import connect
            with connect(DATABASE_PATH) as c:
                existing = c.execute("SELECT id FROM engagements WHERE client_name='PTBot XSS Practice'").fetchone()
            if existing:
                print(f"Practice engagement #{existing[0]} already exists. No new data created.")
                return
            eid = engagement_store.create_engagement(DATABASE_PATH, cleaned)
            print(f"Draft engagement #{eid} created. Review and approve it in the UI.")


if __name__ == "__main__":
    main()
