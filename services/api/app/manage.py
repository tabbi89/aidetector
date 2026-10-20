"""Operator commands run from a shell inside the api container.

    python -m app.manage create-admin --email you@example.com --name "You"

The password is read from the terminal (or one line of stdin with
``--password-stdin``), never from argv or the environment, where it would land
in shell history and ``ps``. Re-running it for an existing email resets that
person's password and makes them the workspace admin — the recovery path.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from app.core.db import SessionLocal
from app.core.passwords import MAX_LENGTH, MIN_LENGTH
from app.scans.accounts import bootstrap_admin


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != first:
        raise SystemExit("passwords do not match")
    return first


def create_admin(args: argparse.Namespace) -> int:
    password = _read_password(args.password_stdin)
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        print(
            f"password must be {MIN_LENGTH}-{MAX_LENGTH} characters",
            file=sys.stderr,
        )
        return 2
    with SessionLocal() as db:
        membership = bootstrap_admin(
            db,
            email=args.email,
            display_name=args.name or args.email.split("@")[0],
            password=password,
            tenant=args.tenant,
        )
        db.commit()
        print(f"admin {membership.user.email} ready in workspace '{membership.tenant_slug}'")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser(
        "create-admin", help="create the workspace admin or reset their password"
    )
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="")
    admin.add_argument("--tenant", default="default")
    admin.add_argument("--password-stdin", action="store_true")
    admin.set_defaults(handler=create_admin)
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
