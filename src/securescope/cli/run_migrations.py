"""Command-line entry point for SecureScope PostgreSQL migrations."""

from __future__ import annotations

import logging
import sys

from dotenv import load_dotenv  # type: ignore[import-not-found]

from securescope.paths import ENV_FILE
from securescope.persistence.migration_service import MigrationError, run_pending_migrations


def main() -> int:
    """Load configuration and apply pending database migrations.

    Returns:
        Process exit code: zero on success, one on migration failure.

    Raises:
        RuntimeError: Not raised; migration failures are logged and converted
            to a non-zero process exit code.
    """

    load_dotenv(dotenv_path=ENV_FILE, override=False)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        applied = run_pending_migrations()
    except MigrationError as exc:
        logging.getLogger(__name__).error("Migration failed: %s", exc)
        return 1
    if applied:
        print("Applied migrations: " + ", ".join(applied))
    else:
        print("Database schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
