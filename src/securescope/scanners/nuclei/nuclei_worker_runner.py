"""Command-line entry point for the standalone SecureScope Nuclei worker."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.scanners.nuclei.nuclei_worker_service import run_worker_forever

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)


def configure_logging() -> None:
    """Configure worker logging from environment variables."""

    log_directory = Path(os.getenv("NUCLEI_WORKER_LOG_DIR", str(APP_DIR / "logs")))
    log_directory.mkdir(parents=True, exist_ok=True)
    level_name = os.getenv("NUCLEI_WORKER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(
                log_directory / "nuclei_worker.log",
                encoding="utf-8",
            ),
            logging.StreamHandler(),
        ],
    )


def main() -> int:
    """Run the standalone worker until the process is stopped.

    Returns:
        Process exit code. The worker normally runs indefinitely.
    """

    configure_logging()
    run_worker_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
