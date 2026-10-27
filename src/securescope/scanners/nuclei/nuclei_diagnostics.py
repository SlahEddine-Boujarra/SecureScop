"""Read-only diagnostics for the SecureScope Nuclei integration."""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.nuclei_persistence import (
    count_active_nuclei_jobs,
    get_worker_state,
    init_nuclei_tables,
    list_nuclei_batches,
)
from securescope.scanners.nuclei.nuclei_client import NucleiClient, NucleiError, profile_options

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)
DEFAULT_CLIENT_NAME = (
    os.getenv("SECURESCOPE_DEFAULT_CLIENT", "Default Client").strip() or "Default Client"
)


def run_diagnostics() -> dict[str, Any]:
    """Collect safe local CLI, template, database and worker health data."""

    result: dict[str, Any] = {
        "ok": False,
        "provider": "ProjectDiscovery Nuclei",
        "integration": "local CLI",
        "api_key_required": False,
        "profiles": profile_options(),
        "checks": {},
    }
    try:
        client = NucleiClient()
        result["checks"]["engine"] = client.health()
    except NucleiError as exc:
        result["checks"]["engine"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    try:
        init_nuclei_tables()
        batches = list_nuclei_batches(DEFAULT_CLIENT_NAME, limit=10)
        result["checks"]["postgresql"] = {
            "ok": True,
            "active_jobs": count_active_nuclei_jobs(),
            "recent_batch_count": len(batches),
        }
        result["checks"]["worker"] = get_worker_state() or {
            "status": "missing",
            "message": "No standalone Nuclei worker heartbeat is stored.",
        }
    except Exception as exc:
        result["checks"]["postgresql"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    result["ok"] = bool(
        result["checks"].get("engine", {}).get("ok")
        and result["checks"].get("postgresql", {}).get("ok")
    )
    return result


def main() -> int:
    """Print diagnostics as JSON and return a process exit code."""

    payload = run_diagnostics()
    output = APP_DIR / "logs" / "nuclei_diagnostics.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, default=str))
    print(f"Saved: {output}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
