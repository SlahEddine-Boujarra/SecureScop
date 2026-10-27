"""Diagnose or explicitly start one queued OpenVAS task.

Default mode is read-only. Use --start-next only when you intentionally want to
claim one eligible PostgreSQL job and execute the exact Greenbone sequence:
create_target -> create_task -> start_task.
"""

from __future__ import annotations

import argparse
import json
import sys

from securescope.scanners.openvas.openvas_worker_service import (
    diagnose_openvas_submission_path,
    trigger_openvas_queue_start_cycle,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-next",
        action="store_true",
        help="Create and start exactly one eligible queued OpenVAS task.",
    )
    args = parser.parse_args()

    diagnostic = diagnose_openvas_submission_path()
    print(json.dumps(diagnostic, indent=2, default=str))
    if not diagnostic.get("ok"):
        return 1

    if not args.start_next:
        print("Read-only diagnostic passed. No target or task was created.")
        return 0

    result = trigger_openvas_queue_start_cycle(timeout_seconds=30.0)
    print(json.dumps(result, indent=2, default=str))
    if result.get("error"):
        return 2
    if result.get("started"):
        print("One queued OpenVAS task was created and started.")
        return 0
    print("No eligible queued task was started.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
