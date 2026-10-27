"""Health probe for the standalone SecureScope Nuclei worker."""

from __future__ import annotations

import argparse
import json

from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.nuclei_persistence import get_worker_state, init_nuclei_tables

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)


def main() -> int:
    """Check the persisted worker heartbeat.

    Returns:
        Zero when the worker is healthy; a non-zero diagnostic code otherwise.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-age", type=int, default=30)
    args = parser.parse_args()

    init_nuclei_tables()
    state = get_worker_state()
    age = int(state.get("heartbeat_age_seconds") or 10**9)
    healthy = bool(state) and state.get("status") == "running" and age <= args.max_age
    payload = {
        "ok": healthy,
        "worker_name": state.get("worker_name"),
        "pid": state.get("pid"),
        "status": state.get("status") or "missing",
        "message": state.get("message") or "No heartbeat stored.",
        "heartbeat_age_seconds": age if state else None,
        "max_age_seconds": args.max_age,
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0 if healthy else 2


if __name__ == "__main__":
    raise SystemExit(main())
