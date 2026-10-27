"""Interactive identity setup run by the administrator on the application host."""

from __future__ import annotations

import argparse
import logging
import re

from dotenv import load_dotenv, set_key

from securescope.paths import ENV_FILE
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    upsert_workspace_member,
)
from securescope.persistence.migration_service import MigrationError

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Configure the local recorder through the existing membership service.

    Returns:
        None; the administrator restarts Streamlit to load the new identity.
    Raises:
        SystemExit: On invalid input or an unavailable workspace/database.
    """
    parser = argparse.ArgumentParser(
        description="Configure the local SecureScope workspace administrator."
    )
    parser.add_argument("--workspace")
    parser.add_argument("--email")
    parser.add_argument("--name")
    args = parser.parse_args()
    workspace = args.workspace or input("Exact client workspace name: ").strip()
    email = (args.email or input("Your email: ")).strip().lower()
    name = (args.name or input("Your name: ")).strip()
    if not workspace or not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        parser.error("Supply a workspace name, your name and a valid email address.")
    load_dotenv(ENV_FILE)
    try:
        upsert_workspace_member(
            workspace,
            email=email,
            display_name=name,
            role="Administrator",
            granted_by=f"Local administrator: {name}",
        )
        set_key(str(ENV_FILE), "SECURESCOPE_CURRENT_USER_EMAIL", email)
    except (EvidenceRepositoryError, DatabaseConfigurationError, MigrationError, OSError) as exc:
        LOGGER.error("Identity setup failed: %s", exc)
        parser.exit(1, f"Identity was not fully configured: {exc}\n")
    print(
        f"Administrator configured for {workspace}. Restart SecureScope to enable evidence editing."
    )


if __name__ == "__main__":
    main()
