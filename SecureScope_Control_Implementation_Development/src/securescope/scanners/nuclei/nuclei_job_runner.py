"""Execute one prepared Nuclei command and write an atomic result marker.

The runner is intentionally database-independent. The standalone worker starts
one runner process per active job and reconciles the result JSON after browser
or worker restarts.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def utc_now() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON through a temporary file and replace the destination."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".tmp",
        prefix=f"{path.name}.",
        dir=path.parent,
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, default=str)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def load_command(path: Path) -> list[str]:
    """Load and validate a prepared subprocess argument list.

    Args:
        path: JSON file containing a string list.

    Returns:
        A validated command list.

    Raises:
        ValueError: If the file does not contain a usable command.
    """

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("The command file must contain a non-empty JSON list.")
    command = [str(item) for item in payload]
    if any(not item for item in command):
        raise ValueError("The command file contains an empty argument.")
    return command


def main() -> int:
    """Execute one Nuclei job and persist its terminal process result."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--command-file", required=True)
    parser.add_argument("--result-file", required=True)
    parser.add_argument("--stdout-file", required=True)
    parser.add_argument("--stderr-file", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()

    command_path = Path(args.command_file).resolve()
    result_path = Path(args.result_file).resolve()
    stdout_path = Path(args.stdout_file).resolve()
    stderr_path = Path(args.stderr_file).resolve()
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    started_monotonic = time.monotonic()
    result: dict[str, Any] = {
        "started_at": started_at,
        "completed_at": None,
        "duration_seconds": 0.0,
        "exit_code": None,
        "timed_out": False,
        "error": "",
        "runner_pid": os.getpid(),
    }

    try:
        command = load_command(command_path)
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            completed = subprocess.run(
                command,
                cwd=command_path.parent,
                stdout=stdout_handle,
                stderr=stderr_handle,
                timeout=max(60, int(args.timeout_seconds)),
                check=False,
                creationflags=CREATE_NO_WINDOW,
            )
        result["exit_code"] = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        result["exit_code"] = -1
        result["error"] = f"Nuclei exceeded the configured job timeout of {exc.timeout} seconds."
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result["exit_code"] = -1
        result["error"] = f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        result["exit_code"] = -2
        result["error"] = "Runner interrupted by operator."
    finally:
        result["completed_at"] = utc_now()
        result["duration_seconds"] = round(
            time.monotonic() - started_monotonic,
            3,
        )
        write_json_atomic(result_path, result)

    return int(result["exit_code"] or 0)


if __name__ == "__main__":
    raise SystemExit(main())
