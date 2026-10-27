"""Local administrator command for workspace membership management."""

from __future__ import annotations

import argparse

from securescope.evidence.models import WorkspaceRole
from securescope.persistence.evidence_repository import upsert_workspace_member


def parser() -> argparse.ArgumentParser:
    """Build the non-interactive membership command parser."""

    command = argparse.ArgumentParser(description="Grant or update a SecureScope workspace role.")
    command.add_argument("--workspace", required=True)
    command.add_argument("--email", required=True)
    command.add_argument("--name", required=True)
    command.add_argument(
        "--role",
        required=True,
        choices=[role.value for role in WorkspaceRole],
    )
    command.add_argument("--granted-by", required=True)
    return command


def main() -> None:
    """Grant one role after the local administrator supplies exact identity fields."""

    args = parser().parse_args()
    membership_id = upsert_workspace_member(
        args.workspace,
        email=args.email,
        display_name=args.name,
        role=args.role,
        granted_by=args.granted_by,
    )
    print(f"Workspace membership #{membership_id} saved for {args.email.lower()}.")


if __name__ == "__main__":
    main()
