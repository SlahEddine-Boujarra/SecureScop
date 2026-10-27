"""Persistent OpenVAS monitoring, recovery, report import and PDF finalization."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Optional

from dotenv import load_dotenv
from gvm import connections as gvm_connections
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

from securescope.integrations.ciso_assistant_service import (
    CisoApiError,
    CisoAssistantClient,
    format_nmap_asset_description,
    load_ciso_config,
)
from securescope.paths import ENV_FILE
from securescope.persistence.db_service import load_assets_for_client
from securescope.persistence.openvas_persistence import (
    activate_openvas_batch_dispatch,
    claim_next_queued_openvas_job,
    complete_openvas_batch_dispatch,
    complete_openvas_job_action,
    count_active_openvas_scans,
    count_pending_openvas_dispatch_jobs,
    create_openvas_batch,
    create_or_update_openvas_job,
    get_active_openvas_attempt,
    get_latest_dispatchable_openvas_batch_id,
    get_latest_prepared_openvas_batch_id,
    get_openvas_job_by_id,
    get_openvas_job_by_task,
    init_openvas_tables,
    list_queued_openvas_jobs,
    list_worker_jobs,
    load_openvas_batch_jobs,
    mark_asset_scanned_direct,
    openvas_task_exists,
    record_openvas_job_event,
    requeue_ambiguous_openvas_start_failures,
    requeue_stale_openvas_submissions,
    save_scan_record_direct,
    set_current_openvas_attempt,
    update_batch_counters,
    update_openvas_job,
    update_openvas_job_by_id,
)
from securescope.reporting.openvas_pdf_report import save_asset_report_pdf

load_dotenv(dotenv_path=ENV_FILE, override=False)

logger = logging.getLogger("securescope.openvas.worker")

# Greenbone/gvmd is accessed through one SSH-forwarded Unix socket. Previous
# releases opened several concurrent GMP sessions (starter, fast sync, priority
# sync, deep sync and one thread per task). That produced intermittent gvmd 500
# responses and left valid tasks in New/Local only. All GMP traffic is now
# serialized inside this Python process. Starting eight tasks is still fast:
# eight start_task commands are sent one after another, while OpenVAS runs the
# accepted scans concurrently according to scanner capacity.
_GMP_IO_LOCK = threading.RLock()

GVM_USERNAME = os.getenv("GVM_USERNAME", "admin")
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "")
LOCAL_TUNNEL_HOST = os.getenv("LOCAL_TUNNEL_HOST", "127.0.0.1")
LOCAL_TUNNEL_PORT = int(os.getenv("LOCAL_TUNNEL_PORT", "19390"))
GMP_TIMEOUT_SECONDS = int(os.getenv("GMP_TIMEOUT_SECONDS", "600"))
GMP_STATUS_TIMEOUT_SECONDS = max(10, int(os.getenv("GMP_STATUS_TIMEOUT_SECONDS", "30")))
REPORT_MAX_ROWS = max(1000, int(os.getenv("REPORT_MAX_ROWS", "200")))
CISO_MIN_CVSS_FOR_RISK = float(os.getenv("CISO_MIN_CVSS_FOR_RISK", "4.0"))
MAX_FINALIZATION_ATTEMPTS = max(
    1,
    int(os.getenv("OPENVAS_FINALIZATION_ATTEMPTS", "3")),
)
SCAN_CONFIG_NAME = os.getenv("SCAN_CONFIG_NAME", "Full and fast")
PORT_LIST_NAME = os.getenv("PORT_LIST_NAME", "All IANA assigned TCP")
SCANNER_NAME = os.getenv("SCANNER_NAME", "OpenVAS Default")
OPENVAS_ALIVE_TEST = os.getenv("OPENVAS_ALIVE_TEST", "Consider Alive").strip() or "Consider Alive"
OPENVAS_USE_ALIVE_TEST = os.getenv(
    "OPENVAS_USE_ALIVE_TEST",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}
OPENVAS_RECOVER_BEFORE_CREATE = os.getenv(
    "OPENVAS_RECOVER_BEFORE_CREATE",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}
REQUESTED_DIAGNOSTIC_SECONDS = max(
    15,
    int(os.getenv("OPENVAS_REQUESTED_DIAGNOSTIC_SECONDS", "45")),
)
MAX_CONCURRENT_SCANS = max(
    1,
    int(os.getenv("OPENVAS_MAX_CONCURRENT_SCANS", "8")),
)
MAX_SUBMISSION_ATTEMPTS = max(
    1,
    int(os.getenv("OPENVAS_MAX_SUBMISSION_ATTEMPTS", "3")),
)
PARALLEL_BATCH_SIZE = max(
    1,
    int(
        os.getenv(
            "OPENVAS_PARALLEL_BATCH_SIZE",
            str(MAX_CONCURRENT_SCANS),
        )
    ),
)
PARALLEL_START_WORKERS = max(
    1,
    int(
        os.getenv(
            "OPENVAS_PARALLEL_START_WORKERS",
            str(MAX_CONCURRENT_SCANS),
        )
    ),
)
GMP_START_TIMEOUT_SECONDS = max(
    15,
    int(os.getenv("GMP_START_TIMEOUT_SECONDS", "90")),
)
MISSING_TASK_GRACE_SECONDS = max(
    15,
    int(os.getenv("OPENVAS_MISSING_TASK_GRACE_SECONDS", "120")),
)
MAX_FINALIZATIONS_PER_CYCLE = max(
    1,
    int(os.getenv("OPENVAS_FINALIZATIONS_PER_CYCLE", "1")),
)
ACTIVE_SLOT_FRESH_SECONDS = max(
    60,
    int(os.getenv("OPENVAS_ACTIVE_SLOT_FRESH_SECONDS", "180")),
)
TUNNEL_PROBE_TIMEOUT_SECONDS = max(
    0.2,
    float(os.getenv("OPENVAS_TUNNEL_PROBE_TIMEOUT_SECONDS", "1.0")),
)
GMP_FAST_STATUS_TIMEOUT_SECONDS = max(
    5,
    int(os.getenv("GMP_FAST_STATUS_TIMEOUT_SECONDS", "15")),
)
FAST_STATUS_JOB_LIMIT = max(
    8,
    int(os.getenv("OPENVAS_FAST_STATUS_JOB_LIMIT", "24")),
)
FAST_STATUS_EXACT_WORKERS = max(
    1,
    int(
        os.getenv(
            "OPENVAS_FAST_STATUS_EXACT_WORKERS",
            str(min(MAX_CONCURRENT_SCANS, 8)),
        )
    ),
)
GVMD_INTERNAL_RETRY_SECONDS = max(
    5,
    int(os.getenv("OPENVAS_GVMD_INTERNAL_RETRY_SECONDS", "15")),
)


class PlainSocketConnection:
    """Plain TCP connection through the Windows SSH tunnel."""

    def __init__(
        self,
        hostname: str = LOCAL_TUNNEL_HOST,
        port: int = LOCAL_TUNNEL_PORT,
        timeout: int = GMP_TIMEOUT_SECONDS,
    ) -> None:
        self.hostname = hostname
        self.port = int(port)
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._file: Optional[BinaryIO] = None

    def connect(self) -> None:
        if self.sock is None:
            self.sock = socket.create_connection(
                (self.hostname, self.port),
                timeout=self.timeout,
            )
            self.sock.settimeout(self.timeout)

    def disconnect(self) -> None:
        self.close()

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None

        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send(self, data: bytes) -> None:
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        self.sock.sendall(data)

    write = send

    def recv(self, size: int = 4096) -> bytes:
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        return self.sock.recv(size)

    receive = recv

    def read(self, size: int = -1) -> bytes:
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        return self.sock.recv(4096 if size is None or size < 0 else size)

    def makefile(
        self,
        mode: str = "rwb",
        buffering: int = 0,
    ) -> BinaryIO:
        if self.sock is None:
            self.connect()
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        if self._file is None:
            self._file = self.sock.makefile(mode, buffering=buffering)
        return self._file

    def fileno(self) -> int:
        return self.sock.fileno() if self.sock is not None else -1

    def settimeout(self, timeout: float) -> None:
        self.timeout = int(timeout)
        if self.sock is not None:
            self.sock.settimeout(timeout)

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()

    def __enter__(self) -> "PlainSocketConnection":
        self.connect()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.disconnect()


SocketConnection = getattr(gvm_connections, "SocketConnection", None)
DebugConnection = getattr(gvm_connections, "DebugConnection", None)

if SocketConnection is None:
    SocketConnection = PlainSocketConnection


def probe_gmp_tunnel(
    *,
    timeout_seconds: float | None = None,
) -> tuple[bool, str]:
    """Check whether the local SSH tunnel is accepting TCP connections."""
    timeout = float(timeout_seconds or TUNNEL_PROBE_TIMEOUT_SECONDS)
    try:
        with socket.create_connection(
            (LOCAL_TUNNEL_HOST, LOCAL_TUNNEL_PORT),
            timeout=max(0.2, timeout),
        ):
            return True, (f"SSH tunnel online at {LOCAL_TUNNEL_HOST}:{LOCAL_TUNNEL_PORT}")
    except OSError as exc:
        return False, (
            f"SSH tunnel offline at {LOCAL_TUNNEL_HOST}:{LOCAL_TUNNEL_PORT}: "
            f"{type(exc).__name__}: {exc}"
        )


def require_gmp_tunnel() -> None:
    """Raise one concise error before opening a GMP session if tunnel is down."""
    online, message = probe_gmp_tunnel()
    if not online:
        raise ConnectionError(message)


def make_gmp_connection(
    *,
    timeout_seconds: int | None = None,
) -> Any:
    connection = SocketConnection(
        hostname=LOCAL_TUNNEL_HOST,
        port=LOCAL_TUNNEL_PORT,
        timeout=int(timeout_seconds or GMP_TIMEOUT_SECONDS),
    )
    if DebugConnection is not None and os.getenv("DEBUG_GVM") == "1":
        connection = DebugConnection(connection)
    return connection


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def first_text(values: list[Any], default: str = "") -> str:
    if not values:
        return default
    value = values[0]
    return str(value) if value is not None else default


def _task_text(response: Any, field: str, default: str = "") -> str:
    for path in (
        f"./{field}/text()",
        f"task/{field}/text()",
        f"./task/{field}/text()",
        f".//task/{field}/text()",
        f".//{field}/text()",
    ):
        try:
            value = first_text(response.xpath(path), "")
        except Exception:
            continue
        if value:
            return value
    return default


def _task_report_id(response: Any) -> str:
    for path in (
        "./current_report/report/@id",
        "task/current_report/report/@id",
        "./task/current_report/report/@id",
        ".//task/current_report/report/@id",
        ".//current_report/report/@id",
        "./last_report/report/@id",
        "task/last_report/report/@id",
        "./task/last_report/report/@id",
        ".//task/last_report/report/@id",
        ".//last_report/report/@id",
    ):
        try:
            value = first_text(response.xpath(path), "")
        except Exception:
            continue
        if value:
            return value
    return ""


def _load_live_task_nodes(
    gmp: GMP,
    task_ids: set[str],
) -> dict[str, Any]:
    """Load one consistent GMP task snapshot for all jobs in a worker cycle.

    A single get_tasks call is substantially less likely to leave later rows
    stale than one network round trip per task. Missing IDs still fall back to
    get_task so permissions, pagination, or older gvmd behavior remain safe.
    """
    requested = {str(value).strip() for value in task_ids if str(value).strip()}
    if not requested:
        return {}

    try:
        response = gmp.get_tasks(
            filter_string="rows=-1",
            details=False,
            ignore_pagination=True,
        )
    except Exception as exc:
        logger.warning(
            "Batch get_tasks snapshot failed; falling back to individual " "task reads: %s: %s",
            type(exc).__name__,
            exc,
        )
        return {}

    nodes: list[Any] = []
    for path in ("./task", "task", ".//task"):
        try:
            nodes = list(response.xpath(path))
        except Exception:
            continue
        if nodes:
            break

    result: dict[str, Any] = {}
    for node in nodes:
        try:
            task_id = str(node.get("id") or "").strip()
        except Exception:
            continue
        if task_id not in requested or task_id in result:
            continue
        # Prefer top-level task rows that contain their own status element.
        try:
            has_status = bool(node.xpath("./status"))
        except Exception:
            has_status = False
        if has_status:
            result[task_id] = node

    return result


def _report_task_id(gmp: GMP, report_id: str) -> str:
    """Best-effort owner-task lookup for one report UUID."""
    if not report_id:
        return ""

    try:
        response = gmp.get_report(
            report_id,
            details=False,
            ignore_pagination=True,
        )
    except Exception:
        return ""

    for path in (
        "report/task/@id",
        "report/report/task/@id",
        ".//report/task/@id",
        ".//task/@id",
    ):
        try:
            value = first_text(response.xpath(path), "")
        except Exception:
            continue
        if value:
            return value
    return ""


def _xpath_first_text(
    response: Any,
    paths: tuple[str, ...],
    default: str = "",
) -> str:
    """Return the first non-empty XML text from a list of GMP paths."""
    for path in paths:
        try:
            value = first_text(response.xpath(path), "").strip()
        except Exception:
            continue
        if value:
            return value
    return default


def _parse_provider_progress(value: Any) -> int:
    """Normalize Greenbone task/report progress into the 0..100 range."""
    try:
        return max(0, min(100, int(float(str(value or "0").strip()))))
    except (TypeError, ValueError):
        return 0


def _task_runtime_snapshot(response: Any) -> dict[str, Any]:
    """Extract raw runtime evidence from a get_task/get_tasks response."""
    return {
        "task_status": _task_text(response, "status", "Unknown"),
        "task_progress": _parse_provider_progress(_task_text(response, "progress", "0")),
        "report_id": _task_report_id(response),
        "report_status": _xpath_first_text(
            response,
            (
                "task/last_report/report/scan_run_status/text()",
                ".//task/last_report/report/scan_run_status/text()",
                ".//last_report/report/scan_run_status/text()",
            ),
        ),
        "scan_start": _xpath_first_text(
            response,
            (
                "task/last_report/report/scan_start/text()",
                ".//task/last_report/report/scan_start/text()",
                ".//last_report/report/scan_start/text()",
            ),
        ),
        "scan_end": _xpath_first_text(
            response,
            (
                "task/last_report/report/scan_end/text()",
                ".//task/last_report/report/scan_end/text()",
                ".//last_report/report/scan_end/text()",
            ),
        ),
    }


def _report_runtime_snapshot(gmp: GMP, report_id: str) -> dict[str, Any]:
    """Read report execution metadata without downloading vulnerability rows.

    GMP start_task returns a report UUID, while the task status can remain
    Requested during scanner hand-off. The report's scan_run_status, scan_start
    and scan_end are therefore collected as independent provider evidence.
    """
    empty = {
        "report_status": "",
        "report_progress": 0,
        "scan_start": "",
        "scan_end": "",
        "report_task_status": "",
    }
    if not report_id:
        return empty

    try:
        # GMP documents scan_run_status, scan_start, scan_end and the task
        # progress inside the detailed report payload. rows=0 suppresses the
        # vulnerability-result rows while retaining that runtime metadata.
        response = gmp.get_report(
            report_id,
            filter_string="rows=0 apply_overrides=0 min_qod=0",
            details=True,
            ignore_pagination=True,
        )
    except Exception as exc:
        logger.debug(
            "Could not read runtime metadata for report %s: %s: %s",
            report_id,
            type(exc).__name__,
            exc,
        )
        return empty

    return {
        "report_status": _xpath_first_text(
            response,
            (
                "report/scan_run_status/text()",
                "report/report/scan_run_status/text()",
                ".//scan_run_status/text()",
            ),
        ),
        "report_progress": _parse_provider_progress(
            _xpath_first_text(
                response,
                (
                    "report/task/progress/text()",
                    "report/report/task/progress/text()",
                    ".//report/task/progress/text()",
                ),
                "0",
            )
        ),
        "scan_start": _xpath_first_text(
            response,
            (
                "report/scan_start/text()",
                "report/report/scan_start/text()",
                ".//report/scan_start/text()",
                ".//scan_start/text()",
            ),
        ),
        "scan_end": _xpath_first_text(
            response,
            (
                "report/scan_end/text()",
                "report/report/scan_end/text()",
                ".//report/scan_end/text()",
                ".//scan_end/text()",
            ),
        ),
        "report_task_status": _xpath_first_text(
            response,
            (
                "report/task/status/text()",
                "report/report/task/status/text()",
                ".//report/task/status/text()",
            ),
        ),
    }


def _merge_runtime_evidence(
    task_snapshot: dict[str, Any],
    report_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Build an effective live state while retaining every raw provider state."""
    task_status = str(task_snapshot.get("task_status") or "Unknown").strip()
    embedded_report_status = str(task_snapshot.get("report_status") or "").strip()
    report_status = str(
        report_snapshot.get("report_status") or embedded_report_status or ""
    ).strip()
    task_progress = _parse_provider_progress(task_snapshot.get("task_progress"))
    report_progress = _parse_provider_progress(report_snapshot.get("report_progress"))
    progress = max(task_progress, report_progress)
    scan_start = str(
        report_snapshot.get("scan_start") or task_snapshot.get("scan_start") or ""
    ).strip()
    scan_end = str(report_snapshot.get("scan_end") or task_snapshot.get("scan_end") or "").strip()

    terminal = {"done", "stopped", "interrupted"}
    running = {"running", "processing", "processing results"}
    report_lower = report_status.lower()
    task_lower = task_status.lower()

    effective = task_status or "Unknown"
    source = "task.status"

    # Exact task state is the primary live source. A stale report from an older
    # poll must never keep a task Running after gvmd has changed the task to
    # Interrupted, Stopped, or Done. Greenbone's get_tasks response exposes the
    # current task status and progress directly, so task terminal/running states
    # win before report enrichment is considered.
    if task_lower in terminal:
        effective = task_status
        source = "task.status"
    elif report_lower in terminal:
        effective = report_status
        source = "report.scan_run_status"
    elif scan_end:
        effective = "Done"
        source = "report.scan_end"
    elif task_lower in running:
        effective = task_status
        source = "task.status"
    elif report_lower in running:
        effective = report_status
        source = "report.scan_run_status"
    elif scan_start and not scan_end:
        effective = "Running"
        source = "report.scan_start"
    elif progress > 0 and task_lower in {
        "new",
        "requested",
        "queued",
        "unknown",
        "start submitted",
    }:
        effective = "Running"
        source = (
            "provider.progress"
            if report_progress >= task_progress and report_progress > 0
            else "task.progress"
        )
    elif task_lower in {"requested", "queued", "new", "created"}:
        effective = task_status
        source = "task.status"
    elif report_lower in {"requested", "queued"}:
        effective = report_status
        source = "report.scan_run_status"

    if str(effective).lower() == "done":
        progress = 100

    return {
        "effective_status": effective,
        "task_status": task_status,
        "report_status": report_status,
        "progress": progress,
        "progress_source": source,
        "scan_start": scan_start,
        "scan_end": scan_end,
    }


def _report_run_status(gmp: GMP, report_id: str) -> str:
    """Backward-compatible helper returning the raw report run status."""
    return str(_report_runtime_snapshot(gmp, report_id).get("report_status") or "")


def _is_missing_greenbone_task(exc: Exception) -> bool:
    """Return whether gvmd confirms that a stored task UUID is missing."""
    status = str(getattr(exc, "status", "") or "")
    message = str(exc).lower()
    return (
        status == "404"
        or "failed to find task" in message
        or ("response error 404" in message and "task" in message)
        or ("task" in message and "not found" in message)
    )


def _is_transient_gvmd_internal_error(exc: Exception) -> bool:
    """Return whether gvmd failed internally without proving task absence.

    A GMP 500 response is not a missing-task confirmation and must not turn a
    task-bearing job into a terminal submission failure. It is treated as a
    temporary manager lookup failure and retried with bounded backoff.
    """
    status = str(getattr(exc, "status", "") or "").strip()
    text = f"{type(exc).__name__}: {exc}".lower()
    return (
        status == "500"
        or "server error 500" in text
        or ("internal error" in text and "gvm" in text)
    )


def _get_task_via_official_get_tasks_command(gmp: GMP, task_id: str) -> Any:
    """Read one task with the GMP command documented by Greenbone.

    Greenbone's official gvm-tools example reads an exact task with
    ``<get_tasks task_id="..."/>``. Some gvmd builds used by this project
    return Server Error 500 for ``get_task`` while the same task is visible in
    the task list. This helper follows the documented command exactly and
    returns the top-level task element.
    """
    normalized = str(task_id or "").strip()
    if not normalized:
        raise GvmError("Task UUID is empty.")

    command = f'<get_tasks task_id="{normalized}" details="0"/>'
    raw = gmp.send_command(command)
    if isinstance(raw, bytes):
        payload = raw
    else:
        payload = str(raw).encode("utf-8", errors="replace")
    root = etree.fromstring(payload)

    status = str(root.get("status") or "")
    status_text = str(root.get("status_text") or "")
    if status and status != "200":
        if status == "404":
            raise GvmError(f"Response Error 404. Failed to find task '{normalized}'")
        raise GvmError(f"GMP get_tasks failed with {status}: {status_text or 'Unknown'}")

    nodes = root.xpath("./task") or root.xpath(".//task")
    for node in nodes:
        if str(node.get("id") or "").strip() == normalized:
            return node
    raise GvmError(f"Response Error 404. Failed to find task '{normalized}'")


def _read_task_snapshot_resilient(gmp: GMP, task_id: str) -> tuple[Any, str]:
    """Read a task from the stable list endpoint before exact get_task.

    Some gvmd builds can return an internal 500 for an exact task lookup while
    the same task is present in get_tasks (the endpoint used by the Greenbone
    task list). Prefer the bulk snapshot and use get_task only as a fallback.
    """
    normalized = str(task_id or "").strip()
    if not normalized:
        raise GvmError("Task UUID is empty.")

    nodes = _load_live_task_nodes(gmp, {normalized})
    task = nodes.get(normalized)
    if task is not None:
        return task, "get_tasks snapshot"

    return (
        _get_task_via_official_get_tasks_command(gmp, normalized),
        "get_tasks task_id command",
    )


def _defer_gvmd_start_request(
    *,
    job: dict[str, Any],
    task_id: str,
    exc: Exception,
) -> dict[str, Any]:
    """Retry the same New task after a transient gvmd start_task 500.

    A manager-side 500 does not justify creating a duplicate task or marking
    the attempt terminal. The exact UUID stays queued and the exclusive batch
    dispatcher retries it after the normal provider backoff.
    """
    job_id = int(job["id"])
    asset_ip = str(job.get("asset_ip") or "")
    error_text = f"{type(exc).__name__}: {exc}"
    update_openvas_job_by_id(
        job_id,
        task_id=task_id,
        status="Queued",
        ui_status="Queued",
        provider_status="Start retry pending",
        provider_task_status=str(job.get("provider_task_status") or "New"),
        stage="gvmd start_task temporarily unavailable; retry scheduled",
        result_message=(
            "The exact Greenbone task remains New. gvmd returned a temporary "
            "internal error while starting it, so SecureScope will retry the "
            "same UUID after a short backoff. No duplicate task is created."
        ),
        error=error_text,
        completed_at=None,
    )
    record_openvas_job_event(
        job_id,
        "task_start_deferred",
        provider_status="Start retry pending",
        ui_status="Queued",
        stage="gvmd start_task temporarily unavailable; retry scheduled",
        progress=int(job.get("progress") or 0),
        message=f"Task {task_id} start deferred after gvmd internal error.",
        error=error_text,
    )
    logger.warning(
        "gvmd internal error while starting task %s for job %s asset %s; "
        "retrying the same UUID after %ss.",
        task_id,
        job_id,
        asset_ip,
        GVMD_INTERNAL_RETRY_SECONDS,
    )
    return {
        "started": False,
        "retry": True,
        "missing": False,
        "uncertain": False,
        "precreated": True,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": asset_ip,
        "target_id": str(job.get("target_id") or ""),
        "task_id": task_id,
        "report_id": str(job.get("report_id") or ""),
        "stage": "Start retry pending",
        "error": error_text,
    }


def _defer_gvmd_task_lookup(
    job: dict[str, Any],
    task_id: str,
    exc: Exception,
) -> dict[str, Any]:
    """Keep an existing task retryable after a temporary gvmd 500 response."""
    job_id = int(job["id"])
    asset_ip = str(job.get("asset_ip") or "")
    error_text = f"{type(exc).__name__}: {exc}"
    update_openvas_job_by_id(
        job_id,
        task_id=task_id,
        status="Queued",
        ui_status="Queued",
        provider_status="Provider retry",
        stage="gvmd task lookup temporarily unavailable; retry scheduled",
        result_message=(
            "The task UUID is preserved. gvmd returned an internal error while "
            "reading it, so SecureScope will retry the same task after a short "
            "backoff and will not create a duplicate."
        ),
        error=error_text,
        completed_at=None,
    )
    record_openvas_job_event(
        job_id,
        "provider_lookup_deferred",
        provider_status="Provider retry",
        ui_status="Queued",
        stage="gvmd task lookup temporarily unavailable; retry scheduled",
        progress=int(job.get("progress") or 0),
        message=f"Task {task_id} lookup deferred after gvmd internal error.",
        error=error_text,
    )
    logger.warning(
        "gvmd internal error while reading task %s for job %s asset %s; "
        "preserving identity and retrying after %ss.",
        task_id,
        job_id,
        asset_ip,
        GVMD_INTERNAL_RETRY_SECONDS,
    )
    return {
        "started": False,
        "retry": True,
        "missing": False,
        "uncertain": False,
        "precreated": True,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": asset_ip,
        "target_id": str(job.get("target_id") or ""),
        "task_id": task_id,
        "report_id": str(job.get("report_id") or ""),
        "stage": "Provider lookup retry",
        "error": error_text,
    }


def _close_missing_task_job(
    job: dict[str, Any],
    task_id: str,
    exc: Exception,
) -> dict[str, Any]:
    """Close an orphaned task once and prevent automatic retry loops."""
    job_id = int(job["id"])
    error_text = f"{type(exc).__name__}: {exc}"
    update_openvas_job_by_id(
        job_id,
        status="Failed",
        ui_status="Failed",
        provider_status="Missing",
        stage="Greenbone task no longer exists",
        result_message=(
            "The stored task UUID is absent from this gvmd instance. The "
            "attempt was closed and will not be automatically requeued. "
            "Create an explicit retry to obtain a new task UUID."
        ),
        error=error_text,
        completed_at=utc_now(),
        last_provider_sync_at=utc_now(),
    )
    record_openvas_job_event(
        job_id,
        "task_missing",
        provider_status="Missing",
        ui_status="Failed",
        stage="Greenbone task no longer exists",
        progress=int(job.get("progress") or 0),
        message="Orphaned task was closed and removed from scanner capacity.",
        error=error_text,
    )
    return {
        "started": False,
        "missing": True,
        "uncertain": False,
        "precreated": True,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": str(job.get("asset_ip") or ""),
        "target_id": str(job.get("target_id") or ""),
        "task_id": task_id,
        "report_id": str(job.get("report_id") or ""),
        "stage": "Greenbone task no longer exists",
        "error": error_text,
    }


def _submitted_wait_seconds(job: dict[str, Any]) -> int:
    submitted = job.get("submitted_at") or job.get("created_at")
    if submitted is None:
        return 0
    if isinstance(submitted, str):
        try:
            submitted = datetime.fromisoformat(submitted.replace("Z", "+00:00"))
        except ValueError:
            return 0
    if getattr(submitted, "tzinfo", None) is None:
        submitted = submitted.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - submitted).total_seconds()))


def _scanner_health(gmp: GMP, scanner_id: str) -> tuple[bool, str]:
    if not scanner_id:
        return False, "The OpenVAS scanner ID is missing."
    try:
        response = gmp.verify_scanner(scanner_id)
        status = str(response.get("status") or "")
        text = str(response.get("status_text") or "Scanner verification completed")
        return status.startswith("2") or not status, text
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _extract_result_nodes(report: Any) -> list[Any]:
    for path in (
        "report/report/results/result",
        "report/results/result",
        ".//report/results/result",
        ".//results/result",
    ):
        try:
            nodes = list(report.xpath(path))
        except Exception:
            continue
        if nodes:
            return nodes
    return []


def _fetch_report(gmp: GMP, report_id: str) -> tuple[list[Any], str]:
    last_error = ""
    successful = False
    best: list[Any] = []

    for filter_string in (
        f"rows={REPORT_MAX_ROWS} min_qod=0",
        f"rows={REPORT_MAX_ROWS}",
        "",
    ):
        try:
            report = gmp.get_report(
                report_id,
                filter_string=filter_string,
                details=True,
                ignore_pagination=False,
            )
            successful = True
            nodes = _extract_result_nodes(report)
            if len(nodes) > len(best):
                best = nodes
            if best:
                return best, f"Report imported: {len(best)} raw result(s)"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(1)

    if successful:
        return [], "Report imported successfully with 0 vulnerability results"

    raise GvmError(f"Could not fetch OpenVAS report {report_id}. {last_error}")


def _severity_value(values: list[Any]) -> float:
    try:
        return float(first_text(values, "0") or 0)
    except (TypeError, ValueError):
        return 0.0


def _severity_label(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _stable_ref(prefix: str, *parts: str) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _iso_mapping_for_finding(
    *,
    name: str,
    description: str,
    solution: str,
    port: str,
    cve: str,
    cvss: float,
) -> list[dict[str, str]]:
    text = " ".join([name, description, solution, port, cve]).lower()

    controls: list[tuple[str, str, str]] = [
        (
            "A.8.8",
            "Management of technical vulnerabilities",
            "The OpenVAS result provides vulnerability and remediation evidence.",
        ),
        (
            "A.8.15",
            "Logging",
            "The report and worker history create timestamped technical evidence.",
        ),
        (
            "A.8.16",
            "Monitoring activities",
            "The finding is monitored through repeatable scans and status tracking.",
        ),
    ]

    def add(control_id: str, control_name: str, rationale: str) -> None:
        if any(item[0] == control_id for item in controls):
            return
        controls.append((control_id, control_name, rationale))

    if any(
        word in text
        for word in (
            "http",
            "https",
            "ssh",
            "rdp",
            "smb",
            "network",
            "service",
            "port",
        )
    ):
        add(
            "A.8.20",
            "Networks security",
            "The result concerns network exposure or network access paths.",
        )
        add(
            "A.8.21",
            "Security of network services",
            "The detected service requires secure configuration and operation.",
        )

    if any(
        word in text
        for word in (
            "ssl",
            "tls",
            "certificate",
            "cipher",
            "encryption",
            "cryptograph",
        )
    ):
        add(
            "A.8.24",
            "Use of cryptography",
            "The result concerns cryptographic configuration or certificate use.",
        )

    if any(
        word in text
        for word in (
            "authentication",
            "password",
            "credential",
            "login",
            "brute force",
        )
    ):
        add(
            "A.8.5",
            "Secure authentication",
            "The result indicates an authentication weakness or exposed login path.",
        )

    if any(
        word in text
        for word in (
            "configuration",
            "misconfiguration",
            "default",
            "hardening",
        )
    ):
        add(
            "A.8.9",
            "Configuration management",
            "The result indicates a configuration or hardening gap.",
        )

    if any(
        word in text
        for word in (
            "unsupported",
            "outdated",
            "obsolete",
            "end of life",
            "patch",
            "update",
        )
    ):
        add(
            "A.8.19",
            "Installation of software on operational systems",
            "The result concerns obsolete, vulnerable or unapproved software.",
        )

    if cvss >= 7:
        add(
            "A.5.37",
            "Documented operating procedures",
            "High-severity remediation should follow an approved procedure.",
        )

    return [
        {
            "id": control_id,
            "name": control_name,
            "rationale": rationale,
        }
        for control_id, control_name, rationale in controls
    ]


def parse_openvas_results(
    results: list[Any],
    report_id: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for result in results:
        cvss = _severity_value(result.xpath("severity/text()"))
        name = first_text(
            result.xpath("name/text()"),
            "Unnamed finding",
        )
        cve = first_text(result.xpath("nvt/cve/text()"), "N/A")
        port = first_text(result.xpath("port/text()"), "N/A")
        host = first_text(result.xpath("host/text()"), "N/A")
        nvt_oid = first_text(result.xpath("nvt/@oid"), "Unknown")
        qod = first_text(result.xpath("qod/value/text()"), "Unknown")
        solution = first_text(
            result.xpath("nvt/solution/text()"),
            "No remediation provided by the scanner.",
        )
        description = first_text(
            result.xpath("description/text()"),
            "No description provided by the scanner.",
        )
        source_key = f"{host}|{port}|{nvt_oid}|{name}"
        mapping = _iso_mapping_for_finding(
            name=name,
            description=description,
            solution=solution,
            port=port,
            cve=cve,
            cvss=cvss,
        )

        findings.append(
            {
                "Severity": _severity_label(cvss),
                "CVSS": round(cvss, 1),
                "Finding": name,
                "CVE": cve,
                "Host": host,
                "Port": port,
                "NVT OID": nvt_oid,
                "QOD": qod,
                "Report ID": report_id,
                "Solution": solution,
                "Description": description,
                "finding_ref_id": _stable_ref(
                    "openvas-finding",
                    report_id,
                    source_key,
                ),
                "vulnerability_ref_id": _stable_ref(
                    "openvas-vuln",
                    source_key,
                ),
                "risk_ref_id": _stable_ref(
                    "openvas-risk",
                    source_key,
                ),
                "ISO Mapping": mapping,
                "ISO Controls": "; ".join(f"{item['id']} {item['name']}" for item in mapping),
                "ISMS Clauses": [
                    "6.1.2",
                    "6.1.3",
                    "8.2",
                    "8.3",
                    "9.1",
                    "10.2",
                ],
                "ISO Rationale": " | ".join(item["rationale"] for item in mapping[:3]),
                "Treatment Priority": (
                    "Immediate"
                    if cvss >= 9
                    else "High" if cvss >= 7 else "Planned" if cvss >= 4 else "Routine"
                ),
                "ISO Mapping Status": ("Suggested — analyst validation required"),
            }
        )

    return sorted(
        findings,
        key=lambda item: float(item.get("CVSS", 0) or 0),
        reverse=True,
    )


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    result = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    for finding in findings:
        label = str(finding.get("Severity") or "Info")
        result[label] = result.get(label, 0) + 1
    return result


def _sync_to_ciso(
    *,
    asset: dict[str, Any],
    findings: list[dict[str, Any]],
    report_id: str,
    asset_ip: str,
) -> tuple[str, dict[str, Any] | None, str | None]:
    try:
        client = CisoAssistantClient(load_ciso_config())
        folder, perimeter = client.bootstrap_scope()
        folder_id = str(folder.get("id") or "")
        perimeter_id = str(perimeter.get("id") or "")
        if not folder_id or not perimeter_id:
            raise CisoApiError("CISO scope bootstrap did not return folder/perimeter IDs.")

        asset_tag = str(asset.get("asset_tag") or f"HOST-{asset_ip}")
        hostname = str(asset.get("hostname") or "Unknown")
        ref_id = f"securescope:{asset_tag}"[:100]
        ciso_asset, _created = client.sync_asset(
            folder_id=folder_id,
            name=(f"{asset_tag} — " f"{hostname if hostname != 'Unknown' else asset_ip}")[:200],
            ref_id=ref_id,
            description=format_nmap_asset_description(asset),
            asset_type="SP",
        )
        ciso_asset_id = str(ciso_asset.get("id") or "")
        if not ciso_asset_id:
            raise CisoApiError("CISO asset synchronization did not return an ID.")

        sync_result = client.sync_openvas_findings(
            findings=findings,
            folder_id=folder_id,
            perimeter_id=perimeter_id,
            asset_id=ciso_asset_id,
            report_id=report_id,
            target_ip=asset_ip,
            risk_min_cvss=CISO_MIN_CVSS_FOR_RISK,
        )
        sync_result["ciso_asset_id"] = ciso_asset_id
        return "Completed", sync_result, ciso_asset_id
    except Exception as exc:
        return (
            f"Failed: {type(exc).__name__}",
            {"error": str(exc)},
            None,
        )


def _finalize_job(
    gmp: GMP,
    job: dict[str, Any],
    *,
    recovered: bool = False,
) -> None:
    task_id = str(job.get("task_id") or "")
    launch_report_id = str(job.get("launch_report_id") or "")
    report_id = launch_report_id or str(job.get("report_id") or "")
    client_name = str(job.get("client_name") or "Default Client")
    asset = dict(job.get("asset_payload") or {})
    asset_ip = str(job.get("asset_ip") or asset.get("ip") or "")
    final_status = str(job.get("status") or "Done")
    attempts = int(job.get("finalization_attempts") or 0) + 1

    update_openvas_job(
        task_id,
        finalization_status="processing",
        finalization_attempts=attempts,
        stage="Fetching OpenVAS report",
        status="Fetching report",
        error="",
    )

    try:
        if not report_id:
            task = _get_task_via_official_get_tasks_command(gmp, task_id)
            report_id = _task_report_id(task)
            if report_id:
                update_openvas_job(task_id, report_id=report_id)

        if not report_id:
            raise GvmError("The OpenVAS task ended without a report ID.")

        owner_task_id = _report_task_id(gmp, report_id)
        if owner_task_id and owner_task_id != task_id:
            raise GvmError(
                "Report/task identity mismatch. "
                f"Job task {task_id} cannot finalize report {report_id}, "
                f"which belongs to task {owner_task_id}."
            )

        raw_results, fetch_note = _fetch_report(gmp, report_id)
        findings = parse_openvas_results(raw_results, report_id)
        counts = _counts(findings)
        scanned_at = utc_now()

        record = {
            "client_name": client_name,
            "report_id": report_id,
            "asset_ip": asset_ip,
            "asset": asset,
            "scanned_at": scanned_at,
            "final_status": final_status,
            "findings": findings,
            "ciso_sync": None,
            "ciso_asset_id": None,
            "openvas_task_id": task_id,
        }

        pdf_path = str(job.get("pdf_path") or "")
        if not pdf_path or not Path(pdf_path).exists():
            pdf_path = str(
                save_asset_report_pdf(
                    record,
                    client_name,
                    output_root=os.getenv(
                        "OPENVAS_REPORT_OUTPUT_ROOT",
                        "reports",
                    ),
                )
            )
        record["pdf_report_path"] = pdf_path

        ciso_status = "Not requested"
        ciso_payload: dict[str, Any] | None = None
        ciso_asset_id: str | None = None

        if bool(job.get("sync_to_ciso")) and findings:
            update_openvas_job(
                task_id,
                stage="Synchronizing CISO Assistant",
                status="Finalizing",
            )
            (
                ciso_status,
                ciso_payload,
                ciso_asset_id,
            ) = _sync_to_ciso(
                asset=asset,
                findings=findings,
                report_id=report_id,
                asset_ip=asset_ip,
            )
            record["ciso_sync"] = ciso_payload
            record["ciso_asset_id"] = ciso_asset_id
        elif bool(job.get("sync_to_ciso")):
            ciso_status = "No findings to synchronize"

        save_scan_record_direct(client_name, record)
        mark_asset_scanned_direct(
            client_name,
            asset_ip,
            scanned_at,
        )

        completion_status = (
            "Recovered report" if recovered and final_status != "Done" else "Completed"
        )
        completed_row = update_openvas_job(
            task_id,
            status=completion_status,
            ui_status=completion_status,
            provider_status=final_status,
            stage="Completed — report imported",
            progress=100,
            result_message=(f"{fetch_note}; " f"{len(findings)} normalized finding(s)"),
            report_id=report_id,
            findings_count=len(findings),
            critical_count=counts["Critical"],
            high_count=counts["High"],
            medium_count=counts["Medium"],
            pdf_path=pdf_path,
            ciso_status=ciso_status,
            ciso_payload=ciso_payload,
            finalization_status="complete",
            completed_at=scanned_at,
            error="",
            last_provider_sync_at=utc_now(),
        )
        if completed_row:
            record_openvas_job_event(
                int(completed_row["id"]),
                "finalization_completed",
                provider_status=final_status,
                ui_status=completion_status,
                stage="Completed — report imported",
                progress=100,
                message=f"{len(findings)} finding(s); PDF and history saved.",
            )
    except Exception as exc:
        logger.exception("Finalization failed for task %s", task_id)
        failed_row = update_openvas_job(
            task_id,
            status=("Failed" if attempts >= MAX_FINALIZATION_ATTEMPTS else "Finalizing"),
            ui_status=("Failed" if attempts >= MAX_FINALIZATION_ATTEMPTS else "Finalizing"),
            provider_status=final_status,
            stage="Finalization failed",
            finalization_status=("failed" if attempts >= MAX_FINALIZATION_ATTEMPTS else "pending"),
            finalization_attempts=attempts,
            error=f"{type(exc).__name__}: {exc}",
            result_message=(
                "The worker will retry finalization."
                if attempts < MAX_FINALIZATION_ATTEMPTS
                else "Finalization retry limit reached."
            ),
        )
        if failed_row:
            record_openvas_job_event(
                int(failed_row["id"]),
                "finalization_failed",
                provider_status=final_status,
                ui_status=str(failed_row.get("ui_status") or failed_row.get("status") or ""),
                stage="Finalization failed",
                progress=int(failed_row.get("progress") or 0),
                message=str(failed_row.get("result_message") or ""),
                error=f"{type(exc).__name__}: {exc}",
            )


def _normalize_greenbone_status(
    provider_status: str,
    *,
    finalization_complete: bool = False,
) -> tuple[str, str]:
    """Map raw Greenbone states to stable SecureScope UI states/stages."""
    raw = str(provider_status or "Unknown").strip()
    lowered = raw.lower()

    if lowered in {"start submitted", "start response accepted"}:
        return (
            "Waiting for scanner",
            "Start submitted; awaiting Greenbone runtime state",
        )
    if lowered in {"start confirmation pending", "task lookup pending"}:
        return (
            "Waiting for scanner",
            "Verifying task submission with Greenbone",
        )
    if lowered in {"new", "created"}:
        return (
            "Queued",
            "Task created in Greenbone; waiting for SecureScope scan slot",
        )
    if lowered == "requested":
        return (
            "Waiting for scanner",
            "Start accepted; scanner has not reported execution",
        )
    if lowered == "queued":
        return "Waiting for scanner", "Waiting for Greenbone scanner capacity"
    if lowered in {"running"}:
        return "Running", "Vulnerability tests executing"
    if lowered in {"processing", "processing results"}:
        return "Processing results", "Greenbone processing results"
    if lowered == "done":
        if finalization_complete:
            return "Completed", "Completed — report imported"
        return "Finalizing", "Importing exact report and generating outputs"
    if lowered == "stopped":
        return "Stopped", "Stopped — partial report may exist"
    if lowered == "interrupted":
        return "Interrupted", "Interrupted — report may be incomplete"
    if lowered in {"delete requested", "stop requested"}:
        return "Stop requested", "Waiting for Greenbone to stop"
    if lowered in {"resume requested"}:
        return "Resume requested", "Waiting for Greenbone to resume"
    return raw or "Unknown", f"Greenbone status: {raw or 'Unknown'}"


def _resource_id_with_aliases(
    response: Any,
    element: str,
    requested_name: str,
    aliases: list[str],
) -> tuple[str, str]:
    """Resolve one Greenbone resource and return its ID and actual name."""
    names: list[str] = []
    for candidate in [requested_name, *aliases]:
        candidate = str(candidate or "").strip()
        if candidate and candidate not in names:
            names.append(candidate)

    for candidate in names:
        values = response.xpath(f"{element}[name='{candidate}']/@id")
        if values:
            return str(values[0]), candidate

    available = [
        str(value) for value in response.xpath(f"{element}/name/text()") if str(value).strip()
    ]
    raise GvmError(
        f"Greenbone {element} not found. Requested {requested_name!r}. "
        f"Available: {', '.join(available) or 'none returned'}."
    )


def _resource_ids_for_job(
    gmp: GMP,
    job: dict[str, Any],
) -> tuple[str, str, str, dict[str, str]]:
    """Resolve the exact scan profile, port list and scanner resources."""
    profile_name = str(job.get("profile_name") or SCAN_CONFIG_NAME)
    port_list_name = str(job.get("port_list_name") or PORT_LIST_NAME)

    config_response = gmp.get_scan_configs()
    config_id, actual_profile = _resource_id_with_aliases(
        config_response,
        "config",
        profile_name,
        ["Full and fast"],
    )

    port_response = gmp.get_port_lists()
    port_list_id, actual_port_list = _resource_id_with_aliases(
        port_response,
        "port_list",
        port_list_name,
        ["All IANA assigned TCP and UDP", "All IANA assigned TCP"],
    )

    scanner_response = gmp.get_scanners()
    scanner_id, actual_scanner = _resource_id_with_aliases(
        scanner_response,
        "scanner",
        SCANNER_NAME,
        ["OpenVAS Default"],
    )
    return (
        config_id,
        port_list_id,
        scanner_id,
        {
            "profile_name": actual_profile,
            "port_list_name": actual_port_list,
            "scanner_name": actual_scanner,
        },
    )


def _expected_task_prefix(job: dict[str, Any], asset_ip: str) -> str:
    """Return the deterministic task-name prefix for one exact job attempt."""
    run_token = str(job.get("job_uuid") or job.get("id") or "")[:8]
    attempt = int(job.get("attempt_number") or 1)
    return f"securescope-scan-{run_token}-{asset_ip}-a{attempt}-"


def _find_existing_greenbone_task(
    gmp: GMP,
    job: dict[str, Any],
    asset_ip: str,
) -> dict[str, Any] | None:
    """Find a task created before a PostgreSQL update failure.

    A deterministic job UUID prefix prevents matching another workspace, batch,
    or retry attempt. This recovery runs before creating a new target/task and
    therefore prevents duplicate Greenbone tasks after a transient database
    failure.
    """
    prefix = _expected_task_prefix(job, asset_ip)
    response = gmp.get_tasks(
        filter_string="rows=250 sort-reverse=creation_time",
    )
    nodes = list(response.xpath("task")) or list(response.xpath(".//task"))

    for node in nodes:
        name = first_text(node.xpath("name/text()"), "")
        if not name.startswith(prefix):
            continue

        progress_text = first_text(node.xpath("progress/text()"), "0")
        try:
            progress = max(0, min(100, int(float(progress_text or 0))))
        except (TypeError, ValueError):
            progress = 0

        return {
            "task_id": str(node.get("id") or ""),
            "name": name,
            "provider_status": first_text(
                node.xpath("status/text()"),
                "Unknown",
            ),
            "progress": progress,
            "target_id": first_text(node.xpath("target/@id"), ""),
            "scanner_id": first_text(node.xpath("scanner/@id"), ""),
            "report_id": first_text(
                node.xpath("last_report/report/@id"),
                "",
            ),
        }

    return None


def _attach_existing_greenbone_task(
    job: dict[str, Any],
    task: dict[str, Any],
) -> bool:
    """Attach one recovered Greenbone task to its original PostgreSQL job."""
    task_id = str(task.get("task_id") or "")
    if not task_id:
        return False

    provider_status = str(task.get("provider_status") or "Unknown")
    ui_status, stage = _normalize_greenbone_status(provider_status)
    report_id = str(task.get("report_id") or "")
    job_id = int(job["id"])

    now = utc_now()
    fields: dict[str, Any] = {
        "task_id": task_id,
        "target_id": str(task.get("target_id") or "") or None,
        "scanner_id": str(task.get("scanner_id") or "") or None,
        "report_id": report_id or None,
        "launch_report_id": report_id or None,
        "status": ui_status,
        "ui_status": ui_status,
        "provider_status": provider_status,
        "provider_task_status": provider_status,
        "provider_report_status": "",
        "provider_progress_source": "task.status",
        "stage": f"Recovered existing Greenbone task · {stage}",
        "progress": int(task.get("progress") or 0),
        "result_message": (
            "An exact task already existed in Greenbone for this job UUID. "
            "SecureScope attached it instead of creating a duplicate."
        ),
        "error": "",
        "submitted_at": job.get("submitted_at") or now,
        "last_provider_sync_at": now,
    }
    if provider_status.lower() in {"running", "processing", "processing results", "done"}:
        fields["started_at"] = job.get("started_at") or now
    update_openvas_job_by_id(job_id, **fields)
    record_openvas_job_event(
        job_id,
        "task_auto_recovered",
        provider_status=provider_status,
        ui_status=ui_status,
        stage=f"Recovered existing Greenbone task · {stage}",
        progress=int(task.get("progress") or 0),
        message=(
            f"Attached task {task_id}; report {report_id or 'pending'}; "
            "no duplicate task was created."
        ),
    )
    return True


def _prepare_one_openvas_task(
    gmp: GMP,
    job: dict[str, Any],
) -> dict[str, Any]:
    """Create one Greenbone target/task without starting the scan.

    Every selected asset therefore appears immediately in Greenbone. The
    protected queue starts only the configured number of pre-created tasks.

    Args:
        gmp: Authenticated GMP session.
        job: Exact PostgreSQL job row.

    Returns:
        IDs and resource names created for the job.

    Raises:
        GvmError: If the asset or Greenbone response is invalid.
    """
    job_id = int(job["id"])
    asset = dict(job.get("asset_payload") or {})
    asset_ip = str(job.get("asset_ip") or asset.get("ip") or "").strip()
    if not asset_ip:
        raise GvmError("Queued OpenVAS job has no valid asset IP.")

    existing_task_id = str(job.get("task_id") or "").strip()
    if existing_task_id:
        return {
            "created": False,
            "job_id": job_id,
            "asset_ip": asset_ip,
            "target_id": str(job.get("target_id") or ""),
            "task_id": existing_task_id,
            "stage": "Task already exists in Greenbone",
        }

    run_token = str(job.get("job_uuid") or job_id)[:8]
    attempt = int(job.get("attempt_number") or 1)
    timestamp = int(time.time())

    # Best-effort duplicate recovery protects a task that Greenbone accepted
    # before PostgreSQL could store its UUID.
    try:
        existing = _find_existing_greenbone_task(gmp, job, asset_ip)
    except Exception as exc:
        logger.warning(
            "Existing-task lookup skipped while preparing job %s: %s: %s",
            job_id,
            type(exc).__name__,
            exc,
        )
        existing = None

    if existing:
        task_id = str(existing.get("task_id") or "")
        if not task_id:
            raise GvmError("Recovered Greenbone task has no UUID.")
        update_openvas_job_by_id(
            job_id,
            target_id=str(existing.get("target_id") or "") or None,
            task_id=task_id,
            scanner_id=str(existing.get("scanner_id") or "") or None,
            report_id=str(existing.get("report_id") or "") or None,
            status="Queued",
            ui_status="Queued",
            provider_status="New",
            provider_task_status="New",
            provider_report_status="",
            provider_progress_source="create_task response",
            stage=("Existing Greenbone task attached; waiting for " "SecureScope scan slot"),
            progress=0,
            result_message=(
                "The exact Greenbone task already existed and was attached "
                "without creating a duplicate."
            ),
            error="",
        )
        record_openvas_job_event(
            job_id,
            "task_preparation_recovered",
            provider_status="New",
            ui_status="Queued",
            stage="Existing Greenbone task attached",
            progress=0,
            message=f"Attached pre-created task {task_id}.",
        )
        return {
            "created": False,
            "recovered": True,
            "job_id": job_id,
            "asset_ip": asset_ip,
            "target_id": str(existing.get("target_id") or ""),
            "task_id": task_id,
            "stage": "Existing Greenbone task attached",
        }

    config_id, port_list_id, scanner_id, resolved = _resource_ids_for_job(
        gmp,
        job,
    )

    update_openvas_job_by_id(
        job_id,
        status="Creating",
        ui_status="Creating",
        provider_status="Not started",
        stage="Creating OpenVAS target",
        error="",
    )
    record_openvas_job_event(
        job_id,
        "target_creation_started",
        provider_status="Not started",
        ui_status="Creating",
        stage="Creating OpenVAS target",
        message=f"Workspace {job.get('client_name')} · IP {asset_ip}",
    )

    target_name = f"securescope-target-{run_token}-{asset_ip}-a{attempt}-{timestamp}"
    target_kwargs: dict[str, Any] = {
        "name": target_name,
        "hosts": [asset_ip],
        "port_list_id": port_list_id,
    }
    if OPENVAS_USE_ALIVE_TEST:
        target_kwargs["alive_test"] = OPENVAS_ALIVE_TEST

    target_response = gmp.create_target(**target_kwargs)
    target_id = str(target_response.get("id") or "")
    if not target_id:
        raise GvmError("Greenbone accepted create_target but returned no target ID.")

    update_openvas_job_by_id(
        job_id,
        target_id=target_id,
        stage="Creating OpenVAS task",
        result_message=(f"Target {target_id[:8]} created with " f"{resolved['port_list_name']}."),
    )

    task_name = f"securescope-scan-{run_token}-{asset_ip}-a{attempt}-{timestamp}"
    task_response = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    task_id = str(task_response.get("id") or "")
    if not task_id:
        raise GvmError("OpenVAS did not return a task ID.")

    update_openvas_job_by_id(
        job_id,
        target_id=target_id,
        task_id=task_id,
        scanner_id=scanner_id,
        status="Queued",
        ui_status="Queued",
        provider_status="New",
        provider_task_status="New",
        provider_report_status="",
        provider_progress_source="create_task response",
        stage="Task created in Greenbone; waiting for SecureScope scan slot",
        progress=0,
        result_message=(
            "Target and task were created in Greenbone. "
            "The protected queue will start this exact task when a scanner "
            "slot is available. "
            f"Profile: {resolved['profile_name']}; "
            f"port list: {resolved['port_list_name']}; "
            f"task {task_id[:8]}."
        ),
        error="",
    )
    record_openvas_job_event(
        job_id,
        "task_prepared",
        provider_status="New",
        ui_status="Queued",
        stage="Task created in Greenbone; waiting for scan slot",
        progress=0,
        message=(
            f"Created target {target_id} and task {task_id}; " "task has not been started yet."
        ),
    )
    return {
        "created": True,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": asset_ip,
        "target_id": target_id,
        "task_id": task_id,
        "profile_name": resolved["profile_name"],
        "port_list_name": resolved["port_list_name"],
        "scanner_name": resolved["scanner_name"],
        "stage": "Task created in Greenbone",
    }


def _prepare_openvas_tasks_for_batch_unlocked(
    batch_id: int,
) -> dict[str, Any]:
    """Create Greenbone tasks for every eligible asset in one batch.

    This operation deliberately creates all targets/tasks first but starts none.
    The queue starter then starts only OPENVAS_MAX_CONCURRENT_SCANS tasks.

    Args:
        batch_id: Exact SecureScope batch ID.

    Returns:
        Creation counters and per-asset errors.
    """
    init_openvas_tables()
    jobs = load_openvas_batch_jobs(int(batch_id))
    eligible = [
        job
        for job in jobs
        if str(job.get("status") or "") == "Queued" and not str(job.get("task_id") or "").strip()
    ]
    already_created = sum(1 for job in jobs if str(job.get("task_id") or "").strip())

    result: dict[str, Any] = {
        "batch_id": int(batch_id),
        "total_jobs": len(jobs),
        "eligible": len(eligible),
        "created": 0,
        "recovered": 0,
        "already_created": already_created,
        "failed": 0,
        "errors": [],
        "tasks": [],
    }
    if not eligible:
        return result
    if not GVM_PASSWORD:
        result["failed"] = len(eligible)
        result["errors"].append(
            {
                "job_id": None,
                "asset_ip": "",
                "stage": "GMP authentication",
                "error": "GVM_PASSWORD is missing in .env.",
            }
        )
        return result

    with GMP(
        connection=make_gmp_connection(),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)

        for raw_job in eligible:
            job = get_openvas_job_by_id(int(raw_job["id"])) or raw_job
            try:
                prepared = _prepare_one_openvas_task(gmp, job)
                result["tasks"].append(prepared)
                if prepared.get("created"):
                    result["created"] += 1
                elif prepared.get("recovered"):
                    result["recovered"] += 1
            except Exception as exc:
                current = get_openvas_job_by_id(int(job["id"])) or job
                stage = str(current.get("stage") or "Creating OpenVAS task")
                error = f"{type(exc).__name__}: {exc}"
                update_openvas_job_by_id(
                    int(job["id"]),
                    status="Submission failed",
                    ui_status="Submission failed",
                    provider_status="Not started",
                    stage=f"{stage} failed",
                    error=error,
                    result_message=(
                        "Greenbone target/task preparation failed. "
                        "Other assets in this batch continue."
                    ),
                    completed_at=utc_now(),
                )
                record_openvas_job_event(
                    int(job["id"]),
                    "task_preparation_failed",
                    provider_status="Not started",
                    ui_status="Submission failed",
                    stage=f"{stage} failed",
                    message="Greenbone task was not created.",
                    error=error,
                )
                result["failed"] += 1
                result["errors"].append(
                    {
                        "job_id": int(job["id"]),
                        "asset_ip": str(job.get("asset_ip") or ""),
                        "stage": stage,
                        "error": error,
                    }
                )
                logger.exception(
                    "Could not prepare OpenVAS task for job %s",
                    job.get("id"),
                )

    update_batch_counters(int(batch_id))
    return result


def prepare_openvas_tasks_for_batch(
    batch_id: int,
    *,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Serialize batch task creation with the queue starter.

    Args:
        batch_id: Exact SecureScope batch ID.
        timeout_seconds: Maximum wait for another queue-start operation.

    Returns:
        Batch preparation result. A busy result contains a visible error.
    """
    acquired = _QUEUE_START_LOCK.acquire(timeout=max(1.0, float(timeout_seconds)))
    if not acquired:
        return {
            "batch_id": int(batch_id),
            "total_jobs": 0,
            "eligible": 0,
            "created": 0,
            "recovered": 0,
            "already_created": 0,
            "failed": 0,
            "errors": [
                {
                    "job_id": None,
                    "asset_ip": "",
                    "stage": "Task preparation lock",
                    "error": (
                        "Another OpenVAS queue-start operation is still "
                        "running. Retry after it finishes."
                    ),
                }
            ],
            "tasks": [],
            "busy": 1,
        }

    try:
        with _GMP_IO_LOCK:
            result = _prepare_openvas_tasks_for_batch_unlocked(int(batch_id))
        result["busy"] = 0
        return result
    finally:
        _QUEUE_START_LOCK.release()


def _is_ambiguous_gmp_transport_error(exc: Exception) -> bool:
    """Return whether a GMP command may have reached gvmd before transport loss."""
    text = f"{type(exc).__name__}: {exc}".lower()
    return isinstance(
        exc,
        (TimeoutError, socket.timeout, ConnectionError, OSError),
    ) or any(
        token in text
        for token in (
            "timed out",
            "connection reset",
            "connection aborted",
            "broken pipe",
            "forcibly closed",
            "read 0 characters",
        )
    )


def _mark_start_confirmation_pending(
    *,
    job: dict[str, Any],
    task_id: str,
    target_id: str,
    scanner_id: str,
    exc: Exception,
) -> dict[str, Any]:
    """Preserve a task after an ambiguous start_task transport timeout.

    A socket timeout does not prove that gvmd rejected start_task. The command
    may already have been accepted while only the XML response was lost. The
    reconciliation loop will read the exact task UUID. If it is still New, the
    queue starter retries the same task instead of creating a duplicate.
    """
    job_id = int(job["id"])
    asset_ip = str(job.get("asset_ip") or "")
    error = f"{type(exc).__name__}: {exc}"
    now = utc_now()
    update_openvas_job_by_id(
        job_id,
        task_id=task_id,
        target_id=target_id or None,
        scanner_id=scanner_id or None,
        status="Waiting for scanner",
        ui_status="Waiting for scanner",
        provider_status="Start confirmation pending",
        provider_task_status=str(job.get("provider_task_status") or "New"),
        provider_report_status="",
        provider_progress_source="transport timeout",
        stage="Start response timed out; verifying exact task in Greenbone",
        result_message=(
            "The start_task response timed out. SecureScope preserved the "
            "exact task UUID and will verify whether Greenbone accepted the "
            "request. No duplicate task will be created."
        ),
        error=error,
        submitted_at=now,
        last_provider_sync_at=None,
    )
    record_openvas_job_event(
        job_id,
        "task_start_confirmation_pending",
        provider_status="Start confirmation pending",
        ui_status="Waiting for scanner",
        stage="Verifying ambiguous start request",
        progress=0,
        message=(
            f"start_task response was lost for {task_id}; the exact task "
            "will be reconciled before any retry."
        ),
        error=error,
    )
    logger.warning(
        "OpenVAS start response timed out for job %s asset %s task %s; "
        "preserving the task and reconciling its real gvmd status.",
        job_id,
        asset_ip,
        task_id,
    )
    return {
        "started": True,
        "uncertain": True,
        "precreated": True,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": asset_ip,
        "target_id": target_id,
        "task_id": task_id,
        "report_id": "",
        "stage": "Start confirmation pending",
    }


def _start_one_job_with_fresh_gmp(raw_job: dict[str, Any]) -> dict[str, Any]:
    """Start one exact task on an independent GMP connection."""
    job = get_openvas_job_by_id(int(raw_job["id"])) or raw_job
    with GMP(
        connection=make_gmp_connection(
            timeout_seconds=GMP_START_TIMEOUT_SECONDS,
        ),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        return _start_claimed_openvas_job(gmp, job)


def _record_parallel_start_failure(
    job: dict[str, Any],
    exc: Exception,
) -> dict[str, Any]:
    """Persist a hard start failure, or defer a temporary gvmd lookup error."""
    current = get_openvas_job_by_id(int(job["id"])) or job
    task_id = str(current.get("task_id") or "").strip()
    if task_id and _is_transient_gvmd_internal_error(exc):
        return _defer_gvmd_task_lookup(current, task_id, exc)

    stage = str(current.get("stage") or "Starting OpenVAS task")
    error = f"{type(exc).__name__}: {exc}"
    update_openvas_job_by_id(
        int(job["id"]),
        status="Submission failed",
        ui_status="Submission failed",
        provider_status=str(current.get("provider_status") or "Start failed"),
        stage=f"{stage} failed",
        error=error,
        result_message=(
            "The Greenbone task identity was preserved. Use retry after "
            "reviewing the exact error; SecureScope will not create a "
            "duplicate task for this attempt."
        ),
        completed_at=utc_now(),
    )
    record_openvas_job_event(
        int(job["id"]),
        "parallel_start_failed",
        provider_status=str(current.get("provider_status") or "Start failed"),
        ui_status="Submission failed",
        stage=f"{stage} failed",
        progress=int(current.get("progress") or 0),
        message="Parallel batch start failed for this task.",
        error=error,
    )
    logger.exception(
        "Could not start prepared OpenVAS task for job %s",
        job.get("id"),
    )
    return {
        "job_id": int(job["id"]),
        "asset_ip": str(job.get("asset_ip") or ""),
        "stage": stage,
        "error": error,
    }


def _start_prepared_openvas_tasks_for_batch_unlocked(
    batch_id: int,
    *,
    max_parallel: int | None = None,
) -> dict[str, Any]:
    """Submit every prepared task serially over one GMP session.

    Serial here refers only to the management commands. The scans themselves
    remain concurrent after gvmd accepts each start_task request. This avoids
    overwhelming the SSH-forwarded gvmd socket with eight simultaneous GMP
    handshakes, which was the main source of intermittent 500/timeouts.
    """
    init_openvas_tables()
    jobs = load_openvas_batch_jobs(int(batch_id))
    limit = max(
        1,
        min(
            int(max_parallel or PARALLEL_BATCH_SIZE),
            int(MAX_CONCURRENT_SCANS),
        ),
    )
    batch_active = count_active_openvas_scans(batch_id=int(batch_id))
    other_recent_active = count_active_openvas_scans(
        exclude_batch_id=int(batch_id),
        fresh_seconds=ACTIVE_SLOT_FRESH_SECONDS,
    )
    available = max(0, limit - batch_active)
    eligible = [
        job
        for job in jobs
        if str(job.get("status") or "") in {"Queued", "Submission failed"}
        and str(job.get("task_id") or "").strip()
    ]
    selected = eligible[:available]
    result: dict[str, Any] = {
        "batch_id": int(batch_id),
        "parallel_limit": limit,
        "global_active_before": batch_active + other_recent_active,
        "batch_active_before": batch_active,
        "other_recent_active_before": other_recent_active,
        "active_slot_fresh_seconds": ACTIVE_SLOT_FRESH_SECONDS,
        "available_slots": available,
        "eligible": len(eligible),
        "started": 0,
        "uncertain": 0,
        "failed": 0,
        "skipped": max(0, len(eligible) - len(selected)),
        "errors": [],
        "tasks": [],
        "submission_mode": "serialized GMP commands",
    }
    if not selected:
        return result
    if not GVM_PASSWORD:
        result["failed"] = len(selected)
        result["errors"].append(
            {
                "job_id": None,
                "asset_ip": "",
                "stage": "GMP authentication",
                "error": "GVM_PASSWORD is missing in .env.",
            }
        )
        return result

    # One connection and one command stream. Reconnect only after a transport
    # failure, then continue with the remaining exact task UUIDs.
    gmp_context = None
    gmp = None
    try:
        for raw_job in selected:
            try:
                if gmp is None:
                    gmp_context = GMP(
                        connection=make_gmp_connection(
                            timeout_seconds=GMP_START_TIMEOUT_SECONDS,
                        ),
                        transform=EtreeCheckCommandTransform(),
                    )
                    gmp = gmp_context.__enter__()
                    gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)

                current_job = get_openvas_job_by_id(int(raw_job["id"])) or raw_job
                started_task = _start_claimed_openvas_job(gmp, current_job)
                result["tasks"].append(started_task)
                if bool(started_task.get("started")):
                    result["started"] += 1
                    if bool(started_task.get("uncertain")):
                        result["uncertain"] += 1
                elif bool(started_task.get("retry")):
                    result["skipped"] += 1
                elif bool(started_task.get("missing")):
                    result["failed"] += 1
                    result["errors"].append(
                        {
                            "job_id": started_task.get("job_id"),
                            "asset_ip": started_task.get("asset_ip"),
                            "stage": started_task.get("stage"),
                            "error": started_task.get("error"),
                        }
                    )
            except Exception as exc:
                result["failed"] += 1
                result["errors"].append(_record_parallel_start_failure(raw_job, exc))
                # A transport/server failure can desynchronize the GMP stream.
                # Close it before the next job; the next iteration reconnects.
                if gmp_context is not None:
                    try:
                        gmp_context.__exit__(None, None, None)
                    except Exception:
                        pass
                gmp_context = None
                gmp = None
    finally:
        if gmp_context is not None:
            try:
                gmp_context.__exit__(None, None, None)
            except Exception:
                pass

    update_batch_counters(int(batch_id))
    result["global_active_after"] = count_active_openvas_scans()
    return result


def start_openvas_batch_parallel(
    batch_id: int,
    *,
    max_parallel: int | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Start every prepared task in a batch without sequential waiting."""
    acquired = _QUEUE_START_LOCK.acquire(timeout=max(1.0, float(timeout_seconds)))
    if not acquired:
        return {
            "batch_id": int(batch_id),
            "started": 0,
            "failed": 0,
            "busy": 1,
            "errors": [
                {
                    "job_id": None,
                    "asset_ip": "",
                    "stage": "Parallel batch start lock",
                    "error": ("Another OpenVAS start operation is still running."),
                }
            ],
        }

    try:
        with _GMP_IO_LOCK:
            activate_openvas_batch_dispatch(
                int(batch_id),
                exclusive=True,
                note="Explicit serialized start requested",
            )
            result = _start_prepared_openvas_tasks_for_batch_unlocked(
                int(batch_id),
                max_parallel=max_parallel,
            )
        result["busy"] = 0
        return result
    finally:
        _QUEUE_START_LOCK.release()


def prepare_and_start_openvas_batch_parallel(
    batch_id: int,
    *,
    max_parallel: int | None = None,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    """Create every missing task, then start the batch in parallel.

    The queue lock covers both operations, preventing the background starter
    from racing with the user-triggered all-assets launch.
    """
    acquired = _QUEUE_START_LOCK.acquire(timeout=max(1.0, float(timeout_seconds)))
    if not acquired:
        return {
            "batch_id": int(batch_id),
            "busy": 1,
            "preparation": {
                "created": 0,
                "recovered": 0,
                "failed": 0,
                "errors": [],
            },
            "start": {
                "started": 0,
                "failed": 0,
                "errors": [
                    {
                        "job_id": None,
                        "asset_ip": "",
                        "stage": "Parallel batch launch lock",
                        "error": ("Another OpenVAS start operation is still running."),
                    }
                ],
            },
        }

    try:
        with _GMP_IO_LOCK:
            activate_openvas_batch_dispatch(
                int(batch_id),
                exclusive=True,
                note="Create tasks and submit starts through one GMP lane",
            )
            preparation = _prepare_openvas_tasks_for_batch_unlocked(int(batch_id))
            started = _start_prepared_openvas_tasks_for_batch_unlocked(
                int(batch_id),
                max_parallel=max_parallel,
            )
        return {
            "batch_id": int(batch_id),
            "busy": 0,
            "preparation": preparation,
            "start": started,
            "created": int(preparation.get("created") or 0),
            "recovered": int(preparation.get("recovered") or 0),
            "started": int(started.get("started") or 0),
            "failed": int(preparation.get("failed") or 0) + int(started.get("failed") or 0),
        }
    finally:
        _QUEUE_START_LOCK.release()


def _start_claimed_openvas_job(
    gmp: GMP,
    job: dict[str, Any],
) -> dict[str, Any]:
    """Create/start one queued job while preserving ambiguous start results."""
    job_id = int(job["id"])
    asset = dict(job.get("asset_payload") or {})
    asset_ip = str(job.get("asset_ip") or asset.get("ip") or "").strip()
    if not asset_ip:
        raise GvmError("Queued OpenVAS job has no valid asset IP.")

    run_token = str(job.get("job_uuid") or job_id)[:8]
    attempt = int(job.get("attempt_number") or 1)

    precreated_task_id = str(job.get("task_id") or "").strip()
    if precreated_task_id:
        update_openvas_job_by_id(
            job_id,
            status="Starting",
            ui_status="Starting",
            provider_status="Checking task",
            stage="Checking pre-created Greenbone task before start",
            error="",
            completed_at=None,
        )

        # A task created by this job and never submitted can be started directly.
        # Calling exact get_task before its first start caused some gvmd builds to
        # return Server Error 500 and incorrectly terminalized a valid task.
        raw_task_status_hint = str(job.get("provider_task_status") or "").strip().lower()
        local_provider_status = str(job.get("provider_status") or "").strip().lower()
        known_task_status = raw_task_status_hint or local_provider_status

        # submitted_at is populated when the PostgreSQL queue row is created in
        # older SecureScope releases. It is therefore not proof that start_task
        # was sent. Only a report identity or an explicit provider start state
        # counts as start evidence.
        has_start_evidence = bool(
            str(job.get("launch_report_id") or "").strip()
            or str(job.get("report_id") or "").strip()
            or local_provider_status
            in {
                "start submitted",
                "start response accepted",
                "start confirmation pending",
                "requested",
                "queued",
                "running",
                "processing",
                "processing results",
                "done",
                "stop requested",
                "resume requested",
            }
            or raw_task_status_hint
            in {
                "requested",
                "queued",
                "running",
                "processing",
                "processing results",
                "done",
                "stop requested",
                "resume requested",
            }
        )

        # A task that SecureScope itself just created and still knows as New is
        # safe to start directly. Avoid get_task/get_tasks here: some gvmd
        # builds return Server Error 500 for a newly created task even though
        # start_task succeeds for the same UUID.
        if (
            known_task_status in {"new", "created", "not started", "checking task"}
            and not has_start_evidence
        ):
            current_report_id = ""
            raw_task_status = "New"
            raw_report_status = ""
            current_status = "New"
            lowered = "new"
        else:
            # Never blindly call start_task twice after an ambiguous submission.
            # Prefer get_tasks because Greenbone's list endpoint is also the
            # authoritative lightweight source for task status and progress.
            try:
                task, lookup_source = _read_task_snapshot_resilient(gmp, precreated_task_id)
            except Exception as exc:
                if _is_missing_greenbone_task(exc):
                    return _close_missing_task_job(
                        job,
                        precreated_task_id,
                        exc,
                    )
                if _is_transient_gvmd_internal_error(exc):
                    return _defer_gvmd_task_lookup(job, precreated_task_id, exc)
                raise
            task_snapshot = _task_runtime_snapshot(task)
            current_report_id = str(task_snapshot.get("report_id") or "")
            report_snapshot = _report_runtime_snapshot(gmp, current_report_id)
            runtime = _merge_runtime_evidence(task_snapshot, report_snapshot)
            raw_task_status = str(runtime.get("task_status") or "Unknown")
            raw_report_status = str(runtime.get("report_status") or "")
            current_status = str(runtime.get("effective_status") or raw_task_status)
            lowered = current_status.strip().lower()
            logger.debug(
                "Read task %s through %s before start decision: %s",
                precreated_task_id,
                lookup_source,
                current_status,
            )
        already_started = {
            "requested",
            "queued",
            "running",
            "processing",
            "processing results",
            "done",
            "stop requested",
            "resume requested",
        }
        if lowered in already_started:
            ui_status, stage = _normalize_greenbone_status(current_status)
            now = utc_now()
            update_fields: dict[str, Any] = {
                "task_id": precreated_task_id,
                "report_id": current_report_id or None,
                "launch_report_id": current_report_id or None,
                "status": ui_status,
                "ui_status": ui_status,
                "provider_status": current_status,
                "provider_task_status": raw_task_status,
                "provider_report_status": raw_report_status,
                "provider_progress_source": str(runtime.get("progress_source") or "task.status"),
                "provider_scan_start": str(runtime.get("scan_start") or "") or None,
                "provider_scan_end": str(runtime.get("scan_end") or "") or None,
                "stage": stage,
                "progress": int(runtime.get("progress") or 0),
                "result_message": (
                    "Greenbone already accepted this exact task. SecureScope "
                    "recovered its provider state without sending a duplicate "
                    "start request."
                ),
                "error": "",
                "submitted_at": job.get("submitted_at") or now,
                "last_provider_sync_at": now,
            }
            if lowered in {"running", "processing", "processing results", "done"}:
                update_fields["started_at"] = (
                    runtime.get("scan_start") or job.get("started_at") or now
                )
            update_openvas_job_by_id(job_id, **update_fields)
            record_openvas_job_event(
                job_id,
                "task_start_confirmed",
                provider_status=current_status,
                ui_status=ui_status,
                stage=stage,
                progress=0,
                message=(
                    f"Existing task {precreated_task_id} is {current_status}; "
                    "duplicate start_task was avoided."
                ),
            )
            return {
                "started": True,
                "confirmed_existing": True,
                "uncertain": False,
                "precreated": True,
                "recovered": True,
                "job_id": job_id,
                "asset_ip": asset_ip,
                "target_id": str(job.get("target_id") or ""),
                "task_id": precreated_task_id,
                "report_id": current_report_id,
                "stage": stage,
            }

        if lowered in {"stopped", "interrupted"}:
            raise GvmError(
                f"Task {precreated_task_id} is {current_status}; create a new "
                "attempt or use the explicit resume/recover action."
            )

        update_openvas_job_by_id(
            job_id,
            status="Starting",
            ui_status="Starting",
            provider_status=current_status or "New",
            stage="Starting pre-created Greenbone task",
            error="",
        )
        record_openvas_job_event(
            job_id,
            "precreated_task_start_requested",
            provider_status=current_status or "New",
            ui_status="Starting",
            stage="Starting pre-created Greenbone task",
            progress=0,
            message=f"Starting existing task {precreated_task_id}.",
        )
        try:
            start_response = gmp.start_task(precreated_task_id)
        except Exception as exc:
            if _is_ambiguous_gmp_transport_error(exc):
                return _mark_start_confirmation_pending(
                    job=job,
                    task_id=precreated_task_id,
                    target_id=str(job.get("target_id") or ""),
                    scanner_id=str(job.get("scanner_id") or ""),
                    exc=exc,
                )
            if _is_transient_gvmd_internal_error(exc):
                return _defer_gvmd_start_request(
                    job=job,
                    task_id=precreated_task_id,
                    exc=exc,
                )
            raise

        report_id = first_text(start_response.xpath("report_id/text()"), "")
        now = utc_now()
        update_openvas_job_by_id(
            job_id,
            task_id=precreated_task_id,
            report_id=report_id or None,
            launch_report_id=report_id or None,
            status="Waiting for scanner",
            ui_status="Waiting for scanner",
            provider_status="Start submitted",
            provider_task_status=current_status or "New",
            provider_report_status="",
            provider_progress_source="start_task response",
            stage="Start submitted; awaiting Greenbone runtime state",
            progress=0,
            result_message=(
                "Greenbone accepted start_task and returned a report ID. "
                "Requested/Running is not assumed until the next provider poll. "
                f"task {precreated_task_id[:8]} · "
                f"report {report_id[:8] if report_id else 'pending'}"
            ),
            error="",
            submitted_at=now,
            last_provider_sync_at=None,
        )
        record_openvas_job_event(
            job_id,
            "task_start_submitted",
            provider_status="Start submitted",
            ui_status="Waiting for scanner",
            stage="Start submitted; awaiting Greenbone runtime state",
            progress=0,
            message=(
                f"Pre-created task {precreated_task_id} started; "
                f"launch report {report_id or 'pending'}."
            ),
        )
        return {
            "started": True,
            "uncertain": False,
            "precreated": True,
            "recovered": False,
            "job_id": job_id,
            "asset_ip": asset_ip,
            "target_id": str(job.get("target_id") or ""),
            "task_id": precreated_task_id,
            "report_id": report_id,
            "stage": "Waiting for Greenbone scanner",
        }

    if OPENVAS_RECOVER_BEFORE_CREATE:
        try:
            existing_task = _find_existing_greenbone_task(gmp, job, asset_ip)
        except Exception as exc:
            logger.warning(
                "Existing-task lookup skipped for job %s: %s: %s",
                job_id,
                type(exc).__name__,
                exc,
            )
            existing_task = None
        if existing_task:
            attached = _attach_existing_greenbone_task(job, existing_task)
            if attached:
                return {
                    "started": True,
                    "uncertain": False,
                    "recovered": True,
                    "job_id": job_id,
                    "asset_ip": asset_ip,
                    "task_id": str(existing_task.get("task_id") or ""),
                    "report_id": str(existing_task.get("report_id") or ""),
                    "stage": "Recovered existing Greenbone task",
                }

    config_id, port_list_id, scanner_id, resolved = _resource_ids_for_job(gmp, job)
    timestamp = int(time.time())

    update_openvas_job_by_id(
        job_id,
        status="Creating",
        ui_status="Creating",
        provider_status="Not started",
        stage="Creating OpenVAS target",
        error="",
    )
    record_openvas_job_event(
        job_id,
        "target_creation_started",
        provider_status="Not started",
        ui_status="Creating",
        stage="Creating OpenVAS target",
        message=f"Workspace {job.get('client_name')} · IP {asset_ip}",
    )

    target_name = f"securescope-target-{run_token}-{asset_ip}-a{attempt}-{timestamp}"
    target_kwargs: dict[str, Any] = {
        "name": target_name,
        "hosts": [asset_ip],
        "port_list_id": port_list_id,
    }
    if OPENVAS_USE_ALIVE_TEST:
        target_kwargs["alive_test"] = OPENVAS_ALIVE_TEST

    target_response = gmp.create_target(**target_kwargs)
    target_id = str(target_response.get("id") or "")
    if not target_id:
        raise GvmError("Greenbone accepted create_target but returned no target ID.")

    update_openvas_job_by_id(
        job_id,
        target_id=target_id,
        stage="Creating OpenVAS task",
        result_message=(f"Target {target_id[:8]} created with " f"{resolved['port_list_name']}."),
    )
    record_openvas_job_event(
        job_id,
        "target_created",
        provider_status="Not started",
        ui_status="Creating",
        stage="Creating OpenVAS task",
        message=f"Target {target_id} created as {target_name}.",
    )

    task_name = f"securescope-scan-{run_token}-{asset_ip}-a{attempt}-{timestamp}"
    task_response = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    task_id = str(task_response.get("id") or "")
    if not task_id:
        raise GvmError("OpenVAS did not return a task ID.")

    update_openvas_job_by_id(
        job_id,
        task_id=task_id,
        target_id=target_id,
        scanner_id=scanner_id,
        status="Starting",
        ui_status="Starting",
        provider_status="New",
        provider_task_status="New",
        provider_report_status="",
        provider_progress_source="create_task response",
        stage="Submitting start request to Greenbone",
    )
    try:
        start_response = gmp.start_task(task_id)
    except Exception as exc:
        if _is_ambiguous_gmp_transport_error(exc):
            return _mark_start_confirmation_pending(
                job=job,
                task_id=task_id,
                target_id=target_id,
                scanner_id=scanner_id,
                exc=exc,
            )
        raise

    report_id = first_text(start_response.xpath("report_id/text()"), "")
    now = utc_now()
    update_openvas_job_by_id(
        job_id,
        task_id=task_id,
        target_id=target_id,
        scanner_id=scanner_id,
        report_id=report_id or None,
        launch_report_id=report_id or None,
        status="Waiting for scanner",
        ui_status="Waiting for scanner",
        provider_status="Start submitted",
        provider_task_status="New",
        provider_report_status="",
        provider_progress_source="start_task response",
        stage="Start submitted; awaiting Greenbone runtime state",
        progress=0,
        result_message=(
            "Task created and start_task accepted by Greenbone. "
            "The next provider poll determines Requested, Running, or Done. "
            f"Profile: {resolved['profile_name']}; "
            f"port list: {resolved['port_list_name']}; "
            f"alive test: {OPENVAS_ALIVE_TEST if OPENVAS_USE_ALIVE_TEST else 'Greenbone default'}. "
            f"run {run_token} · task {task_id[:8]} · "
            f"report {report_id[:8] if report_id else 'pending'}"
        ),
        error="",
        submitted_at=now,
        last_provider_sync_at=None,
    )
    record_openvas_job_event(
        job_id,
        "task_start_submitted",
        provider_status="Start submitted",
        ui_status="Waiting for scanner",
        stage="Start submitted; awaiting Greenbone runtime state",
        progress=0,
        message=(
            f"Task {task_id} started; launch report "
            f"{report_id or 'pending'}; workspace {job.get('client_name')}."
        ),
    )
    return {
        "started": True,
        "uncertain": False,
        "recovered": False,
        "job_id": job_id,
        "asset_ip": asset_ip,
        "target_id": target_id,
        "task_id": task_id,
        "report_id": report_id,
        "stage": "Waiting for Greenbone scanner",
        "profile_name": resolved["profile_name"],
        "port_list_name": resolved["port_list_name"],
        "scanner_name": resolved["scanner_name"],
    }


def _start_queued_openvas_jobs() -> dict[str, Any]:
    """Start queued jobs and return an exact, UI-safe execution result."""
    started = 0
    failed = 0
    last_started: dict[str, Any] | None = None
    last_error = ""
    failed_job_id: int | None = None
    failed_asset_ip = ""
    failed_stage = ""

    while (
        count_active_openvas_scans(
            fresh_seconds=ACTIVE_SLOT_FRESH_SECONDS,
        )
        < MAX_CONCURRENT_SCANS
    ):
        job = claim_next_queued_openvas_job(
            max_concurrent_scans=MAX_CONCURRENT_SCANS,
            active_stale_seconds=ACTIVE_SLOT_FRESH_SECONDS,
        )
        if not job:
            break
        job = get_openvas_job_by_id(int(job["id"])) or job

        try:
            result = _start_one_job_with_fresh_gmp(job)
            update_batch_counters(int(job["batch_id"]))
            last_started = dict(result)
            if bool(result.get("started")):
                started += 1
            elif bool(result.get("missing")):
                failed += 1
                failed_job_id = int(job["id"])
                failed_asset_ip = str(job.get("asset_ip") or "")
                failed_stage = str(result.get("stage") or "Missing task")
                last_error = str(result.get("error") or "Greenbone task missing")
                # Missing tasks are terminal and must not stop newer prepared
                # tasks from being submitted in this cycle.
                continue
        except Exception as exc:
            current = get_openvas_job_by_id(int(job["id"])) or job
            current_task_id = str(current.get("task_id") or "").strip()
            if current_task_id and _is_transient_gvmd_internal_error(exc):
                last_started = _defer_gvmd_task_lookup(current, current_task_id, exc)
                update_batch_counters(int(job["batch_id"]))
                # Continue so one transient manager lookup cannot block the
                # remaining prepared assets in the same batch.
                continue

            has_task_id = bool(current_task_id)
            failed += 1
            failed_job_id = int(job["id"])
            failed_asset_ip = str(job.get("asset_ip") or "")
            failed_stage = str(current.get("stage") or "OpenVAS submission")
            last_error = f"{type(exc).__name__}: {exc}"

            # Do not silently put the job back into Queued. The old behavior
            # made the UI show 6 queued / 0 active forever while hiding the
            # real create_target/create_task/start_task failure.
            status = "Submission failed"
            provider_status = (
                str(current.get("provider_status") or "Start uncertain")
                if has_task_id
                else "Not started"
            )
            update_openvas_job_by_id(
                failed_job_id,
                status=status,
                ui_status=status,
                provider_status=provider_status,
                stage=f"{failed_stage} failed",
                error=last_error,
                result_message=(
                    f"Task identity {current.get('task_id')} was preserved."
                    if has_task_id
                    else (
                        "Greenbone task was not created. Review the exact error "
                        "shown in the live console, then queue a new attempt."
                    )
                ),
                completed_at=utc_now(),
            )
            record_openvas_job_event(
                failed_job_id,
                "submission_failed",
                provider_status=provider_status,
                ui_status=status,
                stage=f"{failed_stage} failed",
                message="Greenbone task creation/start failed.",
                error=last_error,
            )
            update_batch_counters(int(job["batch_id"]))
            logger.exception(
                "OpenVAS submission failed for job %s asset %s",
                failed_job_id,
                failed_asset_ip,
            )
            # Stop this cycle. A configuration/tunnel/resource error usually
            # affects every queued job and should not fail the whole batch.
            break

    return {
        "started": started,
        "failed": failed,
        "queued": len(list_queued_openvas_jobs(limit=500)),
        "last_started": last_started,
        "error": last_error,
        "failed_job_id": failed_job_id,
        "failed_asset_ip": failed_asset_ip,
        "failed_stage": failed_stage,
    }


def _handle_openvas_job_action(
    gmp: GMP,
    job: dict[str, Any],
) -> bool:
    """Handle one queued analyst action.

    Returns True when the cycle should not perform the normal synchronization
    path for this job again.
    """
    action = str(job.get("action_requested") or "").strip().lower()
    if not action:
        return False

    job_id = int(job["id"])
    task_id = str(job.get("task_id") or "")
    if not task_id:
        complete_openvas_job_action(
            job_id,
            error="This action requires an existing Greenbone task ID.",
        )
        return True

    if action == "refresh":
        complete_openvas_job_action(job_id)
        return False

    if action == "resume":
        if str(job.get("status") or "") != "Stopped":
            complete_openvas_job_action(
                job_id,
                error="Only a Stopped Greenbone task can be resumed.",
            )
            return True
        gmp.resume_task(task_id)
        update_openvas_job_by_id(
            job_id,
            status="Resume requested",
            ui_status="Resume requested",
            provider_status="Resume requested",
            stage="Waiting for Greenbone to resume",
            progress=0,
            result_message="The stopped task was resumed without creating a new task.",
            error="",
            finalization_status="pending",
            finalization_attempts=0,
            completed_at=None,
        )
        record_openvas_job_event(
            job_id,
            "task_resume_submitted",
            provider_status="Resume requested",
            ui_status="Resume requested",
            stage="Waiting for Greenbone to resume",
            message="Greenbone resume_task was called for the same task ID.",
        )
        complete_openvas_job_action(job_id)
        return False

    if action == "stop":
        if str(job.get("status") or "") not in {
            "Starting",
            "Waiting for scanner",
            "Running",
            "Processing results",
        }:
            complete_openvas_job_action(
                job_id,
                error="Only an active Greenbone task can be stopped.",
            )
            return True
        gmp.stop_task(task_id)
        update_openvas_job_by_id(
            job_id,
            status="Stop requested",
            ui_status="Stop requested",
            provider_status="Stop requested",
            stage="Waiting for Greenbone to stop",
            result_message="Stop request submitted for the exact task ID.",
            error="",
        )
        record_openvas_job_event(
            job_id,
            "task_stop_submitted",
            provider_status="Stop requested",
            ui_status="Stop requested",
            stage="Waiting for Greenbone to stop",
            message="Greenbone stop_task was called for the exact task ID.",
        )
        complete_openvas_job_action(job_id)
        return True

    if action == "recover":
        task = _get_task_via_official_get_tasks_command(gmp, task_id)
        task_status = _task_text(task, "status", str(job.get("status") or "Unknown"))
        report_id = (
            str(job.get("launch_report_id") or "")
            or str(job.get("report_id") or "")
            or _task_report_id(task)
        )
        update_openvas_job_by_id(
            job_id,
            status=task_status,
            stage="Recovering existing report",
            report_id=report_id or None,
            finalization_status="pending",
            finalization_attempts=0,
            error="",
        )
        refreshed = get_openvas_job_by_id(job_id) or job
        refreshed["status"] = task_status
        refreshed["report_id"] = report_id
        if not report_id:
            complete_openvas_job_action(
                job_id,
                error="Greenbone has not produced a report ID for this task.",
            )
            return True
        _finalize_job(gmp, refreshed, recovered=(task_status != "Done"))
        complete_openvas_job_action(job_id)
        return True

    complete_openvas_job_action(
        job_id,
        error=f"Unsupported queued action: {action}",
    )
    return True


def _process_openvas_worker_cycle_unlocked(
    batch_id: int | None = None,
) -> dict[str, int]:
    """Synchronize exact task/report identities and start queued jobs safely."""
    init_openvas_tables()
    if batch_id is None:
        requeue_stale_openvas_submissions(stale_seconds=120)
    jobs = list_worker_jobs(
        max_finalization_attempts=MAX_FINALIZATION_ATTEMPTS,
        batch_id=batch_id,
    )

    queued_jobs = list_queued_openvas_jobs(limit=1) if batch_id is None else []
    if not jobs and not queued_jobs:
        return {
            "jobs": 0,
            "updated": 0,
            "finalized": 0,
            "failed": 0,
            "started": 0,
        }

    if not GVM_PASSWORD:
        raise RuntimeError("GVM_PASSWORD is missing in .env.")

    updated = 0
    finalized = 0
    failed = 0
    started = 0
    affected_batches: set[int] = set()
    finalization_queue: list[dict[str, Any]] = []

    require_gmp_tunnel()

    with GMP(
        connection=make_gmp_connection(
            timeout_seconds=GMP_STATUS_TIMEOUT_SECONDS,
        ),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        live_task_nodes = _load_live_task_nodes(
            gmp,
            {str(job.get("task_id") or "") for job in jobs},
        )
        scanner_health_cache: dict[str, tuple[bool, str]] = {}

        for job in jobs:
            task_id = str(job.get("task_id") or "")
            if not task_id:
                continue
            affected_batches.add(int(job["batch_id"]))

            try:
                if _handle_openvas_job_action(gmp, job):
                    updated += 1
                    continue

                task = live_task_nodes.get(task_id)
                if task is None:
                    task = _get_task_via_official_get_tasks_command(gmp, task_id)
                task_snapshot = _task_runtime_snapshot(task)

                launch_report_id = str(job.get("launch_report_id") or "")
                persisted_report_id = str(job.get("report_id") or "")
                task_report_id = str(task_snapshot.get("report_id") or "")
                report_id = launch_report_id or persisted_report_id or task_report_id

                report_snapshot = _report_runtime_snapshot(gmp, report_id)
                # Preserve the previous report evidence if a lightweight report
                # metadata call is temporarily unavailable. A successful task
                # read is still a valid provider sync, but it must not erase a
                # previously observed scan_start or Running report state.
                if not report_snapshot.get("report_status"):
                    report_snapshot["report_status"] = str(job.get("provider_report_status") or "")
                if not report_snapshot.get("scan_start"):
                    report_snapshot["scan_start"] = str(job.get("provider_scan_start") or "")
                if not report_snapshot.get("scan_end"):
                    report_snapshot["scan_end"] = str(job.get("provider_scan_end") or "")
                if not report_snapshot.get("report_progress"):
                    report_snapshot["report_progress"] = int(job.get("progress") or 0)
                runtime = _merge_runtime_evidence(
                    task_snapshot,
                    report_snapshot,
                )
                raw_task_status = str(runtime.get("task_status") or "Unknown")
                report_status = str(runtime.get("report_status") or "")
                task_status = str(runtime.get("effective_status") or raw_task_status)
                progress = int(runtime.get("progress") or 0)
                progress_source = str(runtime.get("progress_source") or "task.status")
                scan_start = str(runtime.get("scan_start") or job.get("provider_scan_start") or "")
                scan_end = str(runtime.get("scan_end") or job.get("provider_scan_end") or "")
                if not report_status and report_id:
                    report_status = str(job.get("provider_report_status") or "")

                ui_status, stage = _normalize_greenbone_status(
                    task_status,
                    finalization_complete=(str(job.get("finalization_status") or "") == "complete"),
                )
                wait_seconds = _submitted_wait_seconds(job)
                evidence_bits = [
                    f"effective={task_status}",
                    f"task={raw_task_status}",
                    f"report={report_status or 'n/a'}",
                    f"progress={progress}% via {progress_source}",
                ]
                if scan_start:
                    evidence_bits.append(f"scan_start={scan_start}")
                if scan_end:
                    evidence_bits.append(f"scan_end={scan_end}")
                result_message = "Greenbone runtime: " + "; ".join(evidence_bits)

                if (
                    str(task_status).lower() in {"requested", "queued"}
                    and wait_seconds >= REQUESTED_DIAGNOSTIC_SECONDS
                ):
                    scanner_id = str(job.get("scanner_id") or "")
                    if scanner_id not in scanner_health_cache:
                        scanner_health_cache[scanner_id] = _scanner_health(
                            gmp,
                            scanner_id,
                        )
                    scanner_ok, scanner_message = scanner_health_cache[scanner_id]
                    result_message += (
                        f"; scanner {'verified' if scanner_ok else 'problem'}: "
                        f"{scanner_message}"
                    )

                run_identity = (
                    f"run {str(job.get('job_uuid') or '')[:8]} · "
                    f"task {task_id[:8]} · "
                    f"report {report_id[:8] if report_id else 'pending'}"
                )
                result_message = f"{result_message}; {run_identity}"

                previous_provider = str(job.get("provider_status") or "")
                previous_task_provider = str(job.get("provider_task_status") or "")
                previous_report_provider = str(job.get("provider_report_status") or "")
                previous_ui = str(job.get("ui_status") or job.get("status") or "")
                previous_stage = str(job.get("stage") or "")
                previous_progress = int(job.get("progress") or 0)

                now = utc_now()
                update_fields: dict[str, Any] = {
                    "status": ui_status,
                    "ui_status": ui_status,
                    "provider_status": task_status,
                    "provider_task_status": raw_task_status,
                    "provider_report_status": report_status,
                    "provider_progress_source": progress_source,
                    "provider_scan_start": scan_start or None,
                    "provider_scan_end": scan_end or None,
                    "stage": stage,
                    "progress": progress,
                    "report_id": report_id or None,
                    "result_message": result_message,
                    "error": "",
                    "last_provider_sync_at": now,
                }
                if str(task_status).lower() in {
                    "running",
                    "processing",
                    "processing results",
                    "done",
                }:
                    update_fields["started_at"] = scan_start or job.get("started_at") or now
                update_openvas_job(task_id, **update_fields)
                updated += 1

                meaningful_change = (
                    previous_provider != task_status
                    or previous_task_provider != raw_task_status
                    or previous_report_provider != report_status
                    or previous_ui != ui_status
                    or previous_stage != stage
                    or progress // 10 != previous_progress // 10
                )
                if meaningful_change:
                    record_openvas_job_event(
                        int(job["id"]),
                        "provider_status_changed",
                        provider_status=task_status,
                        ui_status=ui_status,
                        stage=stage,
                        progress=progress,
                        message=result_message,
                    )

                refreshed = get_openvas_job_by_task(task_id) or job
                refreshed["provider_status"] = task_status
                refreshed["provider_task_status"] = raw_task_status
                refreshed["provider_report_status"] = report_status
                refreshed["provider_progress_source"] = progress_source
                refreshed["provider_scan_start"] = scan_start
                refreshed["provider_scan_end"] = scan_end
                refreshed["status"] = ui_status
                refreshed["ui_status"] = ui_status
                refreshed["report_id"] = report_id

                if str(task_status).lower() == "done":
                    if str(refreshed.get("finalization_status") or "pending") != "complete":
                        # Refresh all task states first. Heavy report import must
                        # not freeze the remaining rows at stale 0%.
                        finalization_queue.append(refreshed)
                elif str(task_status).lower() in {"stopped", "interrupted"}:
                    # Preserve exact report identity for optional recovery.
                    update_openvas_job(
                        task_id,
                        status=ui_status,
                        ui_status=ui_status,
                        provider_status=task_status,
                        stage=stage,
                        report_id=report_id or None,
                    )
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                if _is_missing_greenbone_task(exc):
                    task_age = _submitted_wait_seconds(job)
                    if task_age < MISSING_TASK_GRACE_SECONDS:
                        logger.info(
                            "Greenbone task %s is not visible yet (%ss old); "
                            "keeping its scanner reservation during grace period.",
                            task_id,
                            task_age,
                        )
                        update_openvas_job_by_id(
                            int(job["id"]),
                            status="Waiting for scanner",
                            ui_status="Waiting for scanner",
                            provider_status="Task lookup pending",
                            stage="Waiting for Greenbone task visibility",
                            result_message=(
                                "The exact task UUID is temporarily not visible "
                                "through GMP. SecureScope will retry before "
                                "declaring it missing."
                            ),
                            error=error_text,
                        )
                        continue

                    logger.warning(
                        "Stored OpenVAS task %s no longer exists in gvmd; "
                        "releasing its scanner slot.",
                        task_id,
                    )
                    update_openvas_job_by_id(
                        int(job["id"]),
                        status="Failed",
                        ui_status="Failed",
                        provider_status="Missing",
                        stage="Greenbone task no longer exists",
                        result_message=(
                            "The stored task UUID is not present in the connected "
                            "gvmd instance. This attempt was closed so it cannot "
                            "block the queue. Queue a retry for a new task ID."
                        ),
                        error=error_text,
                        completed_at=utc_now(),
                    )
                    record_openvas_job_event(
                        int(job["id"]),
                        "task_missing",
                        provider_status="Missing",
                        ui_status="Failed",
                        stage="Greenbone task no longer exists",
                        progress=int(job.get("progress") or 0),
                        message="Orphaned task released from scanner capacity.",
                        error=error_text,
                    )
                    failed += 1
                    continue

                logger.exception("Could not synchronize OpenVAS task %s", task_id)
                update_openvas_job(
                    task_id,
                    stage="Worker synchronization failed",
                    error=error_text,
                )
                record_openvas_job_event(
                    int(job["id"]),
                    "synchronization_failed",
                    provider_status=str(job.get("provider_status") or ""),
                    ui_status=str(job.get("ui_status") or job.get("status") or ""),
                    stage="Worker synchronization failed",
                    progress=int(job.get("progress") or 0),
                    error=error_text,
                )
                failed += 1

        # Finalize after the fast provider pass. Limit heavy imports per
        # cycle so current progress/status remains responsive.
        for finalization_job in finalization_queue[:MAX_FINALIZATIONS_PER_CYCLE]:
            try:
                _finalize_job(gmp, finalization_job)
                finalized += 1
            except Exception:
                logger.exception(
                    "Unexpected finalization error for OpenVAS job %s",
                    finalization_job.get("id"),
                )
                failed += 1

        for affected_batch_id in affected_batches:
            update_batch_counters(affected_batch_id)

        # Queue creation is owned by the dedicated starter loop below.
        # Reconciliation must never delay a new queued scan while it processes
        # historical tasks, report imports, or slow provider responses.

    return {
        "jobs": len(jobs),
        "updated": updated,
        "finalized": finalized,
        "failed": failed,
        "started": started,
    }


def stop_other_securescope_tasks(
    batch_id: int,
) -> dict[str, Any]:
    """Explicitly stop/delete historical SecureScope tasks outside one batch.

    Done tasks are preserved. New tasks are moved to the Greenbone trash. Tasks
    already Requested, Queued, Running or Processing receive stop_task. This is
    never called automatically; the UI requires an explicit confirmation.
    """
    require_gmp_tunnel()
    selected_ids = {
        str(job.get("task_id") or "")
        for job in load_openvas_batch_jobs(int(batch_id))
        if str(job.get("task_id") or "")
    }
    result: dict[str, Any] = {
        "batch_id": int(batch_id),
        "selected_tasks": len(selected_ids),
        "stopped": 0,
        "deleted_new": 0,
        "skipped_done": 0,
        "errors": [],
    }
    with GMP(
        connection=make_gmp_connection(),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        response = gmp.get_tasks(
            filter_string="rows=1000 sort-reverse=creation_time",
            ignore_pagination=True,
        )
        nodes = list(response.xpath("task")) or list(response.xpath(".//task"))
        for node in nodes:
            task_id = str(node.get("id") or "")
            name = first_text(node.xpath("name/text()"), "")
            status = first_text(node.xpath("status/text()"), "Unknown")
            if not name.startswith("securescope-scan-"):
                continue
            if not task_id or task_id in selected_ids:
                continue
            lowered = status.strip().lower()
            try:
                if lowered in {"done", "stopped", "interrupted"}:
                    result["skipped_done"] += 1
                    continue
                if lowered in {"new", "created"}:
                    gmp.delete_task(task_id)
                    result["deleted_new"] += 1
                elif lowered in {
                    "requested",
                    "queued",
                    "running",
                    "processing",
                    "processing results",
                    "resume requested",
                }:
                    gmp.stop_task(task_id)
                    result["stopped"] += 1
                else:
                    result["errors"].append(
                        {
                            "task_id": task_id,
                            "name": name,
                            "status": status,
                            "error": "Unsupported cleanup status",
                        }
                    )
            except Exception as exc:
                result["errors"].append(
                    {
                        "task_id": task_id,
                        "name": name,
                        "status": status,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
    return result


def diagnose_openvas_submission_path() -> dict[str, Any]:
    """Test the exact connection/resources used before create_target.

    This function is read-only: it never creates a target, task or report.
    """
    result: dict[str, Any] = {
        "ok": False,
        "tunnel": f"{LOCAL_TUNNEL_HOST}:{LOCAL_TUNNEL_PORT}",
        "username": GVM_USERNAME,
        "profile_requested": SCAN_CONFIG_NAME,
        "port_list_requested": PORT_LIST_NAME,
        "scanner_requested": SCANNER_NAME,
    }
    if not GVM_PASSWORD:
        result["error"] = "GVM_PASSWORD is missing in .env."
        return result

    try:
        with GMP(
            connection=make_gmp_connection(),
            transform=EtreeCheckCommandTransform(),
        ) as gmp:
            result["stage"] = "Authenticating"
            gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
            result["stage"] = "Resolving Greenbone resources"
            pseudo_job = {
                "profile_name": SCAN_CONFIG_NAME,
                "port_list_name": PORT_LIST_NAME,
            }
            config_id, port_list_id, scanner_id, resolved = _resource_ids_for_job(gmp, pseudo_job)
            result.update(
                {
                    "ok": True,
                    "stage": "Ready to create target/task",
                    "config_id": config_id,
                    "port_list_id": port_list_id,
                    "scanner_id": scanner_id,
                    **resolved,
                }
            )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


_QUEUE_START_LOCK = threading.Lock()


def _run_openvas_queue_start_cycle_unlocked() -> dict[str, Any]:
    """Dispatch only the explicitly activated batch.

    Older queued batches are retained for history but are never auto-created or
    auto-started. This prevents an eight-asset launch from expanding into dozens
    of Requested tasks as the global worker discovers historical queue rows.
    """
    init_openvas_tables()

    batch_id = get_latest_dispatchable_openvas_batch_id()
    if batch_id is None:
        # Repair batches that v4.10.19 incorrectly marked dispatch-complete
        # after a transient Provider retry. Only the newest explicitly launched
        # recent batch with a real pre-created New task is eligible.
        stalled_batch_id = get_latest_prepared_openvas_batch_id()
        if stalled_batch_id is not None:
            activate_openvas_batch_dispatch(
                int(stalled_batch_id),
                exclusive=True,
                note=(
                    "Automatic recovery of pre-created New tasks that never "
                    "received a confirmed start request"
                ),
            )
            batch_id = int(stalled_batch_id)

    if batch_id is None:
        return {
            "started": 0,
            "failed": 0,
            "queued": 0,
            "dispatch_batch_id": None,
            "message": "No explicitly activated OpenVAS batch needs dispatch.",
        }

    requeue_stale_openvas_submissions(
        stale_seconds=30,
        batch_id=int(batch_id),
    )
    try:
        recovered_starts = requeue_ambiguous_openvas_start_failures(
            batch_id=int(batch_id),
        )
    except Exception:
        logger.exception(
            "Could not recover ambiguous starts for batch %s; continuing",
            batch_id,
        )
        recovered_starts = []

    for recovered in recovered_starts:
        record_openvas_job_event(
            int(recovered["id"]),
            "ambiguous_start_requeued",
            provider_status="Start confirmation pending",
            ui_status="Queued",
            stage="Retrying preserved task after transport timeout",
            message=(
                "A previous start_task timeout was recovered for this exact "
                "batch. The existing task UUID will be inspected before retry."
            ),
        )

    if not GVM_PASSWORD:
        raise RuntimeError("GVM_PASSWORD is missing in .env.")
    require_gmp_tunnel()

    preparation = _prepare_openvas_tasks_for_batch_unlocked(int(batch_id))
    started = _start_prepared_openvas_tasks_for_batch_unlocked(
        int(batch_id),
        max_parallel=MAX_CONCURRENT_SCANS,
    )
    pending = count_pending_openvas_dispatch_jobs(int(batch_id))
    if pending == 0:
        complete_openvas_batch_dispatch(
            int(batch_id),
            note=(
                "Automatic dispatch completed: every current job has a task "
                "and received a terminal start decision."
            ),
        )

    return {
        "dispatch_batch_id": int(batch_id),
        "started": int(started.get("started") or 0),
        "failed": int(preparation.get("failed") or 0) + int(started.get("failed") or 0),
        "created": int(preparation.get("created") or 0),
        "recovered": int(preparation.get("recovered") or 0),
        "queued": int(pending),
        "pending_dispatch": int(pending),
        "preparation": preparation,
        "start": started,
        "errors": list(preparation.get("errors") or []) + list(started.get("errors") or []),
    }


def process_openvas_queue_start_cycle() -> dict[str, Any]:
    """Run one non-blocking dedicated queue-start cycle."""
    if not _QUEUE_START_LOCK.acquire(blocking=False):
        return {"started": 0, "failed": 0, "queued": 0, "busy": 1}

    try:
        with _GMP_IO_LOCK:
            result = _run_openvas_queue_start_cycle_unlocked()
        result["busy"] = 0
        return result
    finally:
        _QUEUE_START_LOCK.release()


def trigger_openvas_queue_start_cycle(
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Start queued work now without waiting for reconciliation."""
    acquired = _QUEUE_START_LOCK.acquire(timeout=max(0.5, float(timeout_seconds)))
    if not acquired:
        return {
            "busy": 1,
            "started": 0,
            "message": "Queue starter is already running.",
        }

    try:
        with _GMP_IO_LOCK:
            result = _run_openvas_queue_start_cycle_unlocked()
        result["busy"] = 0
        return result
    except Exception as exc:
        logger.exception("Triggered OpenVAS queue start failed")
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "busy": 0,
            "started": 0,
        }
    finally:
        _QUEUE_START_LOCK.release()


_FAST_STATUS_GLOBAL_LOCK = threading.Lock()
_FAST_STATUS_BATCH_LOCKS: dict[int, threading.Lock] = {}
_FAST_STATUS_BATCH_LOCKS_GUARD = threading.Lock()


def _fast_status_lock_for_batch(batch_id: int | None) -> threading.Lock:
    """Return an independent lock for global or exact-batch synchronization.

    The old implementation used one global lock for both background polling and
    the visible batch's manual sync. A long historical/global poll therefore
    made Wake worker and Sync live status now ineffective. Exact-batch sync now
    owns a separate lock and a separate GMP connection path.
    """
    if batch_id is None:
        return _FAST_STATUS_GLOBAL_LOCK
    normalized = int(batch_id)
    with _FAST_STATUS_BATCH_LOCKS_GUARD:
        return _FAST_STATUS_BATCH_LOCKS.setdefault(
            normalized,
            threading.Lock(),
        )


def _persist_fast_task_snapshot(
    job: dict[str, Any],
    task: Any,
) -> dict[str, int]:
    """Persist one exact Greenbone task snapshot immediately."""
    task_id = str(job.get("task_id") or "").strip()
    task_snapshot = _task_runtime_snapshot(task)

    # Fast status uses only evidence returned with the current task snapshot.
    # Previously stored report state may belong to an older provider poll.
    runtime = _merge_runtime_evidence(task_snapshot, {})
    raw_task_status = str(runtime.get("task_status") or "Unknown").strip()
    effective_status = str(runtime.get("effective_status") or raw_task_status).strip()
    embedded_report_status = str(runtime.get("report_status") or "").strip()
    progress = int(runtime.get("progress") or 0)
    progress_source = str(runtime.get("progress_source") or "task.status")
    scan_start = str(runtime.get("scan_start") or "").strip()
    scan_end = str(runtime.get("scan_end") or "").strip()
    task_report_id = str(task_snapshot.get("report_id") or "").strip()
    report_id = (
        task_report_id
        or str(job.get("launch_report_id") or "").strip()
        or str(job.get("report_id") or "").strip()
    )

    ui_status, stage = _normalize_greenbone_status(
        effective_status,
        finalization_complete=(str(job.get("finalization_status") or "") == "complete"),
    )
    now = utc_now()
    result_message = (
        "Fast Greenbone task sync: "
        f"effective={effective_status}; "
        f"task={raw_task_status}; "
        f"progress={progress}% via {progress_source}; "
        f"task={task_id[:8]}; "
        f"report={report_id[:8] if report_id else 'pending'}"
    )

    previous_provider = str(job.get("provider_status") or "")
    previous_raw = str(job.get("provider_task_status") or "")
    previous_progress = int(job.get("progress") or 0)
    previous_ui = str(job.get("ui_status") or job.get("status") or "")

    update_fields: dict[str, Any] = {
        "status": ui_status,
        "ui_status": ui_status,
        "provider_status": effective_status,
        "provider_task_status": raw_task_status,
        "provider_report_status": embedded_report_status,
        "provider_progress_source": progress_source,
        "provider_scan_start": scan_start or None,
        "provider_scan_end": scan_end or None,
        "stage": stage,
        "progress": progress,
        "report_id": report_id or None,
        "result_message": result_message,
        "error": "",
        "last_provider_sync_at": now,
    }
    lowered = effective_status.lower()
    if lowered in {"running", "processing", "processing results", "done"}:
        update_fields["started_at"] = scan_start or job.get("started_at") or now
    if lowered in {"stopped", "interrupted"}:
        update_fields["completed_at"] = now

    # Update by database identity, not only task UUID. This preserves the exact
    # workspace/batch/job row even if historical data contains a duplicate task
    # UUID from an earlier broken release.
    update_openvas_job_by_id(int(job["id"]), **update_fields)

    if (
        previous_provider != effective_status
        or previous_raw != raw_task_status
        or previous_ui != ui_status
        or previous_progress != progress
    ):
        record_openvas_job_event(
            int(job["id"]),
            "fast_provider_status_changed",
            provider_status=effective_status,
            ui_status=ui_status,
            stage=stage,
            progress=progress,
            message=result_message,
        )
    return {"updated": 1, "failed": 0, "missing": 0}


def _handle_fast_status_exception(
    job: dict[str, Any],
    task_id: str,
    exc: Exception,
) -> dict[str, int]:
    """Persist one fast-sync failure without blocking the rest of the batch."""
    error_text = f"{type(exc).__name__}: {exc}"
    if _is_missing_greenbone_task(exc):
        task_age = _submitted_wait_seconds(job)
        if task_age >= MISSING_TASK_GRACE_SECONDS:
            _close_missing_task_job(job, task_id, exc)
            return {"updated": 0, "failed": 0, "missing": 1}
        update_openvas_job_by_id(
            int(job["id"]),
            stage="Waiting for Greenbone task visibility",
            error=error_text,
        )
        return {"updated": 0, "failed": 0, "missing": 0}

    logger.warning(
        "Fast OpenVAS status sync failed for task %s: %s",
        task_id,
        error_text,
    )
    transient_internal = _is_transient_gvmd_internal_error(exc)
    update_openvas_job_by_id(
        int(job["id"]),
        provider_status=(
            "Provider error"
            if transient_internal
            else str(job.get("provider_status") or "Provider unavailable")
        ),
        stage=(
            "gvmd internal error during live task lookup; retrying"
            if transient_internal
            else "Fast provider synchronization failed"
        ),
        error=error_text,
    )
    return {"updated": 0, "failed": 1, "missing": 0}


def _sync_one_fast_job_with_fresh_gmp(
    job: dict[str, Any],
) -> dict[str, int]:
    """Read one exact task through its own short-lived GMP connection."""
    task_id = str(job.get("task_id") or "").strip()
    if not task_id:
        return {"updated": 0, "failed": 0, "missing": 0}
    try:
        with GMP(
            connection=make_gmp_connection(
                timeout_seconds=GMP_FAST_STATUS_TIMEOUT_SECONDS,
            ),
            transform=EtreeCheckCommandTransform(),
        ) as gmp:
            gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
            task = _get_task_via_official_get_tasks_command(gmp, task_id)
        return _persist_fast_task_snapshot(job, task)
    except Exception as exc:
        return _handle_fast_status_exception(job, task_id, exc)


def _process_openvas_fast_status_cycle_unlocked(
    batch_id: int | None = None,
) -> dict[str, Any]:
    """Refresh all selected task states through one authenticated GMP lane.

    The task list is read once. Any UUID absent from that list is queried with
    the official ``<get_tasks task_id="..."/>`` command on the same session.
    No per-task threads or parallel GMP sockets are opened.
    """
    init_openvas_tables()
    jobs = list_worker_jobs(
        limit=FAST_STATUS_JOB_LIMIT,
        max_finalization_attempts=MAX_FINALIZATION_ATTEMPTS,
        batch_id=batch_id,
    )
    if not jobs:
        return {
            "jobs": 0,
            "updated": 0,
            "failed": 0,
            "missing": 0,
            "batch_id": int(batch_id) if batch_id is not None else None,
        }

    require_gmp_tunnel()
    updated = 0
    failed = 0
    missing = 0
    affected_batches = {int(job["batch_id"]) for job in jobs}

    with GMP(
        connection=make_gmp_connection(
            timeout_seconds=GMP_FAST_STATUS_TIMEOUT_SECONDS,
        ),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        live_task_nodes = _load_live_task_nodes(
            gmp,
            {str(job.get("task_id") or "") for job in jobs},
        )

        for job in jobs:
            task_id = str(job.get("task_id") or "").strip()
            if not task_id:
                continue
            try:
                task = live_task_nodes.get(task_id)
                if task is None:
                    task = _get_task_via_official_get_tasks_command(gmp, task_id)
                result = _persist_fast_task_snapshot(job, task)
            except Exception as exc:
                result = _handle_fast_status_exception(job, task_id, exc)
            updated += int(result.get("updated") or 0)
            failed += int(result.get("failed") or 0)
            missing += int(result.get("missing") or 0)

    for affected_batch_id in affected_batches:
        update_batch_counters(affected_batch_id)

    return {
        "jobs": len(jobs),
        "updated": updated,
        "failed": failed,
        "missing": missing,
        "batch_id": int(batch_id) if batch_id is not None else None,
        "sync_mode": "single GMP session",
    }


def process_openvas_fast_status_cycle(
    batch_id: int | None = None,
) -> dict[str, Any]:
    """Run one non-blocking lightweight task-status cycle."""
    lock = _fast_status_lock_for_batch(batch_id)
    if not lock.acquire(blocking=False):
        return {
            "jobs": 0,
            "updated": 0,
            "failed": 0,
            "missing": 0,
            "busy": 1,
            "batch_id": int(batch_id) if batch_id is not None else None,
        }
    try:
        with _GMP_IO_LOCK:
            result = _process_openvas_fast_status_cycle_unlocked(batch_id=batch_id)
        result["busy"] = 0
        return result
    finally:
        lock.release()


def trigger_openvas_fast_status_cycle(
    batch_id: int | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Force an exact-batch refresh independent from global reconciliation."""
    lock = _fast_status_lock_for_batch(batch_id)
    acquired = lock.acquire(timeout=max(0.5, float(timeout_seconds)))
    if not acquired:
        return {
            "busy": 1,
            "message": (
                f"Batch #{batch_id} live synchronization is already running."
                if batch_id is not None
                else "Global fast status cycle is already running."
            ),
        }
    try:
        with _GMP_IO_LOCK:
            result = _process_openvas_fast_status_cycle_unlocked(batch_id=batch_id)
        result["busy"] = 0
        return result
    except Exception as exc:
        logger.exception("Triggered fast OpenVAS status cycle failed")
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "busy": 0,
            "batch_id": int(batch_id) if batch_id is not None else None,
        }
    finally:
        lock.release()


_WORKER_CYCLE_LOCK = threading.Lock()


def process_openvas_worker_cycle(
    batch_id: int | None = None,
) -> dict[str, int]:
    """Run one serialized reconciliation cycle.

    The optional batch_id allows the visible Streamlit table to reconcile only
    its own tasks. No target, task or scan is created by this function.
    """
    if not _WORKER_CYCLE_LOCK.acquire(blocking=False):
        return {
            "jobs": 0,
            "updated": 0,
            "finalized": 0,
            "failed": 0,
            "started": 0,
            "busy": 1,
        }

    try:
        with _GMP_IO_LOCK:
            result = _process_openvas_worker_cycle_unlocked(batch_id=batch_id)
        result["busy"] = 0
        return result
    finally:
        _WORKER_CYCLE_LOCK.release()


def trigger_openvas_worker_cycle(
    batch_id: int | None = None,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Force an immediate provider reconciliation cycle."""
    init_openvas_tables()
    requeue_stale_openvas_submissions(stale_seconds=30)

    acquired = _WORKER_CYCLE_LOCK.acquire(timeout=max(0.5, float(timeout_seconds)))
    if not acquired:
        return {"busy": 1, "message": "Worker cycle currently running."}
    try:
        result = _process_openvas_worker_cycle_unlocked(batch_id=batch_id)
        result["busy"] = 0
        return result
    except Exception as exc:
        logger.exception("Triggered OpenVAS worker cycle failed")
        return {"error": f"{type(exc).__name__}: {exc}", "busy": 0}
    finally:
        _WORKER_CYCLE_LOCK.release()


def _resource_id_by_name(response: Any, element: str, name: str) -> str:
    values = response.xpath(f"{element}[name='{name}']/@id")
    if not values:
        raise GvmError(f"OpenVAS resource not found: {name}")
    return str(values[0])


def retry_openvas_jobs(
    client_name: str,
    source_job_ids: list[int],
    *,
    reason: str,
    allow_completed: bool = False,
) -> dict[str, Any]:
    """Queue new attempts while preserving old tasks/reports and workspace."""
    source_jobs = [
        job for job_id in source_job_ids if (job := get_openvas_job_by_id(int(job_id))) is not None
    ]
    if not source_jobs:
        raise ValueError("Select at least one OpenVAS job to retry.")

    for job in source_jobs:
        if str(job.get("client_name") or "") != str(client_name):
            raise ValueError("A selected job belongs to another client workspace.")

    allowed_statuses = {
        "Failed",
        "Stopped",
        "Interrupted",
        "Submission failed",
        "Submission blocked",
        "Abandoned",
        "Cancelled",
    }
    if allow_completed:
        allowed_statuses.update({"Completed", "Recovered report"})

    invalid = [job for job in source_jobs if str(job.get("status") or "") not in allowed_statuses]
    if invalid:
        labels = ", ".join(f"{job.get('asset_ip')} ({job.get('status')})" for job in invalid)
        raise ValueError(f"These jobs are not retryable: {labels}")

    first = source_jobs[0]
    batch = create_openvas_batch(
        client_name,
        label="Retry queue · " + datetime.now().strftime("%Y-%m-%d %H:%M"),
        scan_mode="Retry selected assets",
        profile_name=str(first.get("profile_name") or SCAN_CONFIG_NAME),
        port_list_name=str(first.get("port_list_name") or PORT_LIST_NAME),
        sync_to_ciso=bool(first.get("sync_to_ciso")),
        status="Queued",
    )
    batch_id = int(batch["id"])
    created: list[dict[str, Any]] = []

    for position, source in enumerate(source_jobs, start=1):
        logical_id = str(source.get("logical_job_id") or f"legacy-{source['id']}")
        active = get_active_openvas_attempt(
            logical_id,
            exclude_job_id=int(source["id"]),
        )
        if active:
            continue

        attempt = int(source.get("attempt_number") or 1) + 1
        asset = dict(source.get("asset_payload") or {})
        queued = create_or_update_openvas_job(
            client_name,
            batch_id=batch_id,
            asset=asset,
            status="Queued",
            ui_status="Queued",
            provider_status="Not started",
            stage="Waiting for SecureScope scan slot",
            progress=0,
            queue_position=position,
            result_message=(f"Attempt {attempt} queued. Previous attempt and report preserved."),
            sync_to_ciso=bool(source.get("sync_to_ciso")),
            logical_job_id=logical_id,
            attempt_number=attempt,
            retry_of_job_id=int(source["id"]),
            retry_reason=reason.strip(),
            is_current_attempt=True,
        )
        set_current_openvas_attempt(logical_id, int(queued["id"]))
        update_openvas_job_by_id(
            int(source["id"]),
            result_message=f"Superseded by queued attempt {attempt}.",
        )
        record_openvas_job_event(
            int(queued["id"]),
            "retry_queued",
            provider_status="Not started",
            ui_status="Queued",
            stage="Waiting for SecureScope scan slot",
            progress=0,
            message=reason.strip() or "Retry requested by analyst.",
        )
        created.append(queued)

    update_batch_counters(batch_id)
    return {
        "batch_id": batch_id,
        "created": len(created),
        "failed": len(source_jobs) - len(created),
        "failures": [],
        "message": (
            f"Retry batch #{batch_id}: {len(created)} asset(s) queued. "
            f"Concurrency limit: {MAX_CONCURRENT_SCANS}."
        ),
    }


_IP_PATTERN = re.compile(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)")


def _task_ip(name: str) -> str:
    matches = _IP_PATTERN.findall(name)
    for candidate in reversed(matches):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ""


def recover_recent_securescope_tasks(
    client_name: str,
    *,
    limit: int = 100,
) -> dict[str, Any]:
    """Attach untracked existing Greenbone tasks without creating a rescan."""
    init_openvas_tables()
    if not GVM_PASSWORD:
        raise RuntimeError("GVM_PASSWORD is missing in .env.")

    assets = {
        str(asset.get("ip") or ""): dict(asset) for asset in load_assets_for_client(client_name)
    }
    candidates: list[dict[str, Any]] = []

    with GMP(
        connection=make_gmp_connection(),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        response = gmp.get_tasks(
            filter_string=f"rows={max(10, limit)} sort-reverse=creation_time",
        )
        nodes = list(response.xpath("task"))
        if not nodes:
            nodes = list(response.xpath(".//task"))

        for node in nodes:
            task_id = str(node.get("id") or "")
            name = first_text(node.xpath("name/text()"), "")
            if not task_id or openvas_task_exists(task_id):
                continue
            if not (name.startswith("securescope-scan-") or name.startswith("scan-")):
                continue

            asset_ip = _task_ip(name)
            if not asset_ip:
                continue

            status = first_text(
                node.xpath("status/text()"),
                "Unknown",
            )
            progress_text = first_text(
                node.xpath("progress/text()"),
                "0",
            )
            try:
                progress = int(float(progress_text or 0))
            except ValueError:
                progress = 0
            report_id = first_text(
                node.xpath("last_report/report/@id"),
                "",
            )
            target_id = first_text(
                node.xpath("target/@id"),
                "",
            )
            scanner_id = first_text(
                node.xpath("scanner/@id"),
                "",
            )

            candidates.append(
                {
                    "task_id": task_id,
                    "name": name,
                    "asset_ip": asset_ip,
                    "status": status,
                    "progress": progress,
                    "report_id": report_id,
                    "target_id": target_id,
                    "scanner_id": scanner_id,
                }
            )

    if not candidates:
        return {
            "recovered": 0,
            "batch_id": None,
            "message": "No untracked SecureScope tasks were found.",
        }

    batch = create_openvas_batch(
        client_name,
        label=("Recovered Greenbone tasks " + datetime.now().strftime("%Y-%m-%d %H:%M")),
        scan_mode="Recovered existing tasks",
        profile_name="Existing Greenbone task",
        port_list_name="Existing target configuration",
        sync_to_ciso=True,
        status="Running",
    )

    for item in candidates:
        asset = assets.get(item["asset_ip"]) or {
            "ip": item["asset_ip"],
            "asset_tag": f"RECOVERED-{item['asset_ip']}",
            "hostname": "Unknown",
            "operating_system": "Not inspected",
            "device_type": "Not inspected",
            "criticality": "Medium",
        }
        recovered_ui_status, recovered_stage = _normalize_greenbone_status(
            str(item["status"]),
        )
        create_or_update_openvas_job(
            client_name,
            batch_id=int(batch["id"]),
            asset=asset,
            target_id=item["target_id"],
            task_id=item["task_id"],
            report_id=item["report_id"],
            launch_report_id=item["report_id"],
            scanner_id=item["scanner_id"],
            status=recovered_ui_status,
            ui_status=recovered_ui_status,
            provider_status=str(item["status"]),
            stage=f"Recovered from Greenbone · {recovered_stage}",
            progress=item["progress"],
            result_message=("Attached to an existing task. No scan was started."),
            sync_to_ciso=True,
        )

    update_batch_counters(int(batch["id"]))
    return {
        "recovered": len(candidates),
        "batch_id": int(batch["id"]),
        "message": (
            f"Recovered {len(candidates)} existing Greenbone task(s) " "without starting a rescan."
        ),
    }
