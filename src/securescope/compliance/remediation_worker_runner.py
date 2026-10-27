"""Standalone Windows-friendly runner for the remediation execution worker."""

from __future__ import annotations

import logging
import os
import time

from dotenv import load_dotenv

from securescope.compliance.remediation_worker_service import run_remediation_worker_cycle
from securescope.paths import ENV_FILE

LOGGER = logging.getLogger(__name__)


def main() -> int:
    """Run bounded remediation worker cycles until the process is stopped.

    Returns:
        Process status code; normal operator interruption returns zero.

    Raises:
        ValueError: Never raised for normal configuration values.
    """

    load_dotenv(dotenv_path=ENV_FILE, override=False)
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        poll_seconds = max(
            1,
            int(os.getenv("REMEDIATION_WORKER_POLL_SECONDS", "5")),
        )
    except ValueError:
        poll_seconds = 5
    LOGGER.info("SecureScope remediation worker started")
    try:
        while True:
            outcome = run_remediation_worker_cycle()
            if outcome.get("processed"):
                LOGGER.info("Remediation cycle result: %s", outcome)
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        LOGGER.info("SecureScope remediation worker stopped by operator")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
