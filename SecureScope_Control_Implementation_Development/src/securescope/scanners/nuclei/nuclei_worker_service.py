"""Standalone Nuclei worker for SecureScope.

Streamlit never owns the scanner lifecycle. The worker launches one detached
runner per job, reconciles durable result files and stores normalized findings,
PDF evidence and provider-neutral scan history in PostgreSQL.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
from dotenv import load_dotenv

from securescope.integrations.ciso_assistant_service import (
    CisoApiError,
    CisoAssistantClient,
    format_nmap_asset_description,
    load_ciso_config,
)
from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.db_service import (
    get_client_name_by_id,
    mark_asset_scanned_for_engine,
    upsert_scan_record_for_client,
)
from securescope.persistence.nuclei_persistence import (
    claim_queued_nuclei_jobs,
    consume_wake_requests,
    count_active_nuclei_jobs,
    get_database_url,
    get_nuclei_batch,
    get_nuclei_job,
    init_nuclei_tables,
    list_jobs_for_provider_sync,
    update_nuclei_batch_counters,
    update_nuclei_job,
    update_worker_heartbeat,
)
from securescope.reporting.nuclei_report import (
    count_jsonl_findings,
    generate_nuclei_pdf,
    parse_nuclei_jsonl,
    save_report_bundle,
)
from securescope.scanners.nuclei.nuclei_client import NucleiClient, NucleiError

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)

logger = logging.getLogger("securescope.nuclei.worker")

WORKER_NAME = os.getenv("NUCLEI_WORKER_NAME", "nuclei-monitor")
POLL_SECONDS = max(2, int(os.getenv("NUCLEI_WORKER_POLL_SECONDS", "5")))
ERROR_RETRY_SECONDS = max(
    5,
    int(os.getenv("NUCLEI_WORKER_ERROR_RETRY_SECONDS", "10")),
)
MAX_CONCURRENT_SCANS = max(
    1,
    int(os.getenv("NUCLEI_MAX_CONCURRENT_SCANS", "2")),
)
SYNC_LIMIT = max(1, int(os.getenv("NUCLEI_SYNC_LIMIT", "100")))
FINALIZATION_ATTEMPTS = max(
    1,
    int(os.getenv("NUCLEI_MAX_FINALIZATION_ATTEMPTS", "3")),
)
RUNNER_TIMEOUT_SECONDS = max(
    300,
    int(os.getenv("NUCLEI_JOB_TIMEOUT_SECONDS", "7200")),
)
RUNNER_RESULT_GRACE_SECONDS = max(
    15,
    int(os.getenv("NUCLEI_RUNNER_RESULT_GRACE_SECONDS", "45")),
)
CISO_MIN_CVSS_FOR_RISK = float(os.getenv("CISO_MIN_CVSS_FOR_RISK", "4.0"))
LOCK_KEY = int(os.getenv("NUCLEI_WORKER_LOCK_KEY", "81304522"))
WORK_ROOT = Path(os.getenv("NUCLEI_WORK_ROOT", str(APP_DIR / "logs" / "nuclei_jobs")))
REPORT_OUTPUT_ROOT = Path(os.getenv("NUCLEI_REPORT_OUTPUT_ROOT", str(APP_DIR / "reports")))

CREATE_NEW_PROCESS_GROUP = 0x00000200 if os.name == "nt" else 0
DETACHED_PROCESS = 0x00000008 if os.name == "nt" else 0


class WorkerAlreadyRunningError(RuntimeError):
    """Raised when another Nuclei worker owns the advisory lock."""


class ProviderWorkerLock:
    """Hold one PostgreSQL advisory lock for the worker lifetime."""

    def __init__(self, lock_key: int = LOCK_KEY) -> None:
        """Initialize the lock holder.

        Args:
            lock_key: PostgreSQL advisory-lock key.
        """

        self.lock_key = int(lock_key)
        self.connection: Any = None

    def acquire(self) -> None:
        """Acquire the provider lock.

        Raises:
            WorkerAlreadyRunningError: If another worker owns the lock.
            psycopg2.Error: If PostgreSQL cannot be reached.
        """

        self.connection = psycopg2.connect(get_database_url())
        self.connection.autocommit = True
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_try_advisory_lock(%s);",
                (self.lock_key,),
            )
            row = cursor.fetchone()
            if not row or not bool(row[0]):
                self.connection.close()
                self.connection = None
                raise WorkerAlreadyRunningError(
                    "Another SecureScope Nuclei worker already owns the lock."
                )

    def release(self) -> None:
        """Release the provider lock and close its connection."""

        if self.connection is None:
            return
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_unlock(%s);",
                    (self.lock_key,),
                )
        finally:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> "ProviderWorkerLock":
        """Acquire and return the lock holder."""

        self.acquire()
        return self

    def __exit__(self, *_args: Any) -> None:
        """Release the provider lock."""

        self.release()


def utc_now_iso() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _age_seconds(value: Any) -> float:
    """Return elapsed seconds from a datetime-like value."""

    if not value:
        return 999999.0
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    except (TypeError, ValueError):
        return 999999.0


def _usable_hostname(value: Any) -> str:
    """Return a usable hostname or an empty string."""

    text = str(value or "").strip()
    if text.lower() in {
        "",
        "unknown",
        "not detected",
        "n/a",
        "none",
    }:
        return ""
    return text


def build_asset_targets(asset: dict[str, Any]) -> list[str]:
    """Build Nuclei targets from one Nmap-enriched asset.

    The bare IP enables network, DNS and SSL templates. HTTP/HTTPS URLs are
    added for ports or service names that Nmap identified as web services.

    Args:
        asset: Normalized SecureScope asset record.

    Returns:
        A stable, duplicate-free target list.
    """

    asset_ip = str(asset.get("ip") or "").strip()
    if not asset_ip:
        return []
    hostname = _usable_hostname(asset.get("hostname"))
    hosts = [asset_ip]
    if hostname and hostname != asset_ip:
        hosts.append(hostname)

    targets: list[str] = []

    def add(value: str) -> None:
        if value and value not in targets:
            targets.append(value)

    add(asset_ip)
    if hostname:
        add(hostname)

    raw_ports = asset.get("open_ports") or ""
    port_records: list[tuple[int, str, str]] = []
    if isinstance(raw_ports, list):
        for item in raw_ports:
            if not isinstance(item, dict):
                continue
            try:
                port = int(item.get("port") or item.get("portid"))
            except (TypeError, ValueError):
                continue
            protocol = str(item.get("protocol") or "tcp").lower()
            service = str(item.get("service") or item.get("name") or "").lower()
            state = str(item.get("state") or "open").lower()
            if state == "open":
                port_records.append((port, protocol, service))
    else:
        pattern = re.compile(
            r"(?P<port>\d{1,5})/(?P<protocol>tcp|udp)\s+(?P<service>[^;()\s]+)",
            re.I,
        )
        for match in pattern.finditer(str(raw_ports)):
            port_records.append(
                (
                    int(match.group("port")),
                    match.group("protocol").lower(),
                    match.group("service").lower(),
                )
            )

    secure_web_ports = {443, 4443, 7443, 8443, 9443, 10443}
    plain_web_ports = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888}

    for port, protocol, service in port_records:
        if protocol != "tcp":
            continue

        is_https = port in secure_web_ports or "https" in service or "ssl" in service
        is_http = (
            is_https
            or port in plain_web_ports
            or "http" in service
            or service in {"www", "web", "http-proxy"}
        )
        if not is_http:
            continue

        scheme = "https" if is_https else "http"
        for host in hosts:
            default_port = 443 if scheme == "https" else 80
            suffix = "" if port == default_port else f":{port}"
            add(f"{scheme}://{host}{suffix}")

    return targets


def _process_alive(pid: Any) -> bool:
    """Return whether a process identifier currently exists."""

    try:
        resolved_pid = int(pid)
    except (TypeError, ValueError):
        return False
    if resolved_pid <= 0:
        return False
    try:
        os.kill(resolved_pid, 0)
    except OSError:
        return False
    return True


def _tail(path: str | Path, limit: int = 4000) -> str:
    """Return the tail of one text log without raising on missing files."""

    candidate = Path(path)
    if not candidate.is_file():
        return ""
    text = candidate.read_text(encoding="utf-8", errors="replace")
    return text[-limit:].strip()


def _latest_stats(path: str | Path) -> dict[str, Any]:
    """Return the newest JSON statistics object written by Nuclei."""

    candidate = Path(path)
    if not candidate.is_file():
        return {}
    lines = candidate.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()
    for line in reversed(lines[-200:]):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and any(
            key in payload
            for key in (
                "requests",
                "matched",
                "errors",
                "duration",
                "rps",
                "templates",
                "hosts",
            )
        ):
            return payload
    return {}


def _progress_from_stats(stats: dict[str, Any]) -> int:
    """Return a bounded live percentage from Nuclei stats JSON.

    Args:
        stats: Latest decoded Nuclei statistics line.

    Returns:
        A percentage between 10 and 94 while the process is active.
    """

    raw = str(stats.get("percent") or "").strip().rstrip("%")
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        return 10
    return max(10, min(94, value))


def _runner_command(
    *,
    command_path: Path,
    result_path: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> list[str]:
    """Build the detached Python runner command."""

    return [
        sys.executable,
        "-m",
        "securescope.scanners.nuclei.nuclei_job_runner",
        "--command-file",
        str(command_path),
        "--result-file",
        str(result_path),
        "--stdout-file",
        str(stdout_path),
        "--stderr-file",
        str(stderr_path),
        "--timeout-seconds",
        str(RUNNER_TIMEOUT_SECONDS),
    ]


def _start_claimed_job(client: NucleiClient, job: dict[str, Any]) -> None:
    """Prepare and launch one exact Nuclei attempt."""

    job_id = int(job["id"])
    job_uuid = str(job["job_uuid"])
    run_directory = WORK_ROOT / job_uuid
    run_directory.mkdir(parents=True, exist_ok=True)

    target_path = run_directory / "targets.txt"
    output_path = run_directory / "findings.jsonl"
    stdout_path = run_directory / "stdout.log"
    stderr_path = run_directory / "stderr.log"
    result_path = run_directory / "result.json"
    command_path = run_directory / "command.json"
    project_directory = run_directory / "project"

    asset = dict(job.get("asset_payload") or {})
    asset.setdefault("ip", str(job.get("asset_ip") or ""))
    targets = build_asset_targets(asset)
    if not targets:
        raise NucleiError("No usable Nuclei target could be derived from the asset.")

    batch = get_nuclei_batch(int(job["batch_id"]))
    profile_name = str(batch.get("profile_name") or "standard")
    target_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    command = client.build_scan_command(
        target_file=target_path,
        output_file=output_path,
        profile_name=profile_name,
        scan_name=str(job["scan_name"]),
        project_directory=project_directory,
    )
    command_path.write_text(
        json.dumps(command, indent=2) + "\n",
        encoding="utf-8",
    )

    for path in (result_path, stdout_path, stderr_path, output_path):
        path.unlink(missing_ok=True)
    # A successful scan with zero matches still has an explicit empty JSONL artifact.
    output_path.touch(exist_ok=False)

    popen_kwargs: dict[str, Any] = {
        "cwd": APP_DIR,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    else:
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(
            _runner_command(
                command_path=command_path,
                result_path=result_path,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            ),
            **popen_kwargs,
        )
    except OSError as exc:
        update_nuclei_job(
            job_id,
            status="Failed",
            provider_status="Launch failed",
            ui_status="Failed",
            stage="Could not start Nuclei runner",
            error=f"{type(exc).__name__}: {exc}",
            completed_at=utc_now_iso(),
            event_type="runner_launch_failed",
            message="The scanner process was not started.",
        )
        return

    update_nuclei_job(
        job_id,
        targets=targets,
        runner_pid=int(process.pid),
        command_path=str(command_path),
        target_path=str(target_path),
        output_path=str(output_path),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        result_path=str(result_path),
        status="Running",
        provider_status="Executing",
        ui_status="Running",
        stage=f"Nuclei profile '{profile_name}' is executing",
        progress=10,
        started_at=utc_now_iso(),
        last_provider_sync_at=utc_now_iso(),
        error="",
        event_type="runner_started",
        message=f"Started detached Nuclei runner PID {process.pid}.",
    )


def _sync_ciso(
    *,
    job: dict[str, Any],
    client_name: str,
    findings: list[dict[str, Any]],
    report_id: str,
) -> tuple[str, dict[str, Any]]:
    """Synchronize one completed Nuclei report to CISO Assistant."""

    if not bool(job.get("sync_to_ciso")):
        return "Not requested", {}

    try:
        ciso = CisoAssistantClient(load_ciso_config())
        folder, perimeter = ciso.bootstrap_scope()
        folder_id = str(folder.get("id") or "")
        perimeter_id = str(perimeter.get("id") or "")
        if not folder_id or not perimeter_id:
            raise CisoApiError("CISO scope did not return usable IDs.")

        asset = dict(job.get("asset_payload") or {})
        asset_ip = str(job["asset_ip"])
        ciso_asset, _created = ciso.sync_asset(
            folder_id=folder_id,
            name=str(asset.get("hostname") or asset.get("asset_tag") or asset_ip),
            description=format_nmap_asset_description(asset),
            ref_id=f"securescope-asset-{job['client_id']}-{asset_ip}",
        )
        asset_id = str(ciso_asset.get("id") or "")
        if not asset_id:
            raise CisoApiError("CISO asset synchronization returned no ID.")

        result = ciso.sync_scanner_findings(
            findings=findings,
            folder_id=folder_id,
            perimeter_id=perimeter_id,
            asset_id=asset_id,
            report_id=report_id,
            target_ip=asset_ip,
            risk_min_cvss=CISO_MIN_CVSS_FOR_RISK,
        )
        result["ciso_asset_id"] = asset_id
        return "Synchronized", result
    except CisoApiError as exc:
        return "Failed", {"error": str(exc), "client": client_name}


def _finalize_job(job: dict[str, Any], result: dict[str, Any]) -> None:
    """Parse one completed runner output and save final evidence."""

    if result.get("exit_code") != 0:
        raise ValueError("Only a successful Nuclei process can be finalized.")
    job_id = int(job["id"])
    failures = int(job.get("finalization_attempts") or 0)
    update_nuclei_job(
        job_id,
        status="Finalizing",
        provider_status="Completed",
        ui_status="Finalizing",
        stage="Parsing Nuclei JSONL and generating evidence",
        progress=95,
        event_type="report_finalization_started",
        message="Nuclei process completed successfully.",
    )

    try:
        current = get_nuclei_job(job_id)
        output_path = Path(str(current.get("output_path") or ""))
        if not output_path.is_file():
            raise FileNotFoundError("Nuclei findings.jsonl is missing; cannot verify collection.")
        source_bytes = output_path.read_bytes()
        report_id = f"nuclei-{current['job_uuid']}-a" f"{int(current.get('attempt_number') or 1)}"
        findings, metadata = parse_nuclei_jsonl(
            source_bytes,
            report_id=report_id,
            asset_ip=str(current["asset_ip"]),
        )
        client_name = get_client_name_by_id(int(current["client_id"]))
        batch = get_nuclei_batch(int(current["batch_id"]))
        scanned_at = str(result.get("completed_at") or utc_now_iso())
        from datetime import datetime

        from securescope.evidence.evidence_service import ingest_nuclei_scan_output

        ingest_nuclei_scan_output(
            client_name,
            job_uuid=str(current["job_uuid"]),
            attempt_number=int(current.get("attempt_number") or 1),
            report_id=report_id,
            asset_ip=str(current["asset_ip"]),
            profile=str(batch.get("profile_name") or "standard"),
            collected_at=datetime.fromisoformat(scanned_at.replace("Z", "+00:00")),
            content=source_bytes,
            successful=True,
        )
        pdf_record = {
            "scanner": "ProjectDiscovery Nuclei",
            "scanner_engine": "Nuclei",
            "asset": dict(current.get("asset_payload") or {}),
            "asset_ip": str(current["asset_ip"]),
            "report_id": report_id,
            "scanned_at": result.get("completed_at") or utc_now_iso(),
            "findings": findings,
        }
        pdf_bytes = generate_nuclei_pdf(
            pdf_record,
            client_name=client_name,
        )
        source_path, pdf_path = save_report_bundle(
            output_root=REPORT_OUTPUT_ROOT,
            client_name=client_name,
            asset_ip=str(current["asset_ip"]),
            report_id=report_id,
            source_bytes=source_bytes,
            pdf_bytes=pdf_bytes,
        )
        ciso_status, ciso_payload = _sync_ciso(
            job=current,
            client_name=client_name,
            findings=findings,
            report_id=report_id,
        )
        scan_record = {
            "report_id": report_id,
            "scanner": "ProjectDiscovery Nuclei",
            "scanner_engine": "Nuclei",
            "final_status": "Completed",
            "asset": dict(current.get("asset_payload") or {}),
            "asset_ip": str(current["asset_ip"]),
            "asset_tag": str(current.get("asset_tag") or ""),
            "scanned_at": scanned_at,
            "batch_id": int(current["batch_id"]),
            "job_id": job_id,
            "job_uuid": str(current["job_uuid"]),
            "attempt_number": int(current.get("attempt_number") or 1),
            "profile_name": str(batch.get("profile_name") or "standard"),
            "targets": list(current.get("targets") or []),
            "runner_pid": current.get("runner_pid"),
            "findings": findings,
            "findings_count": int(metadata["findings_count"]),
            "critical_count": int(metadata["critical_count"]),
            "high_count": int(metadata["high_count"]),
            "medium_count": int(metadata["medium_count"]),
            "low_count": int(metadata["low_count"]),
            "pdf_path": str(pdf_path),
            "source_path": str(source_path),
            "source_format": "jsonl",
            "ciso_status": ciso_status,
            "ciso_sync": (ciso_payload if ciso_status == "Synchronized" else None),
            "ciso_asset_id": (
                ciso_payload.get("ciso_asset_id") if isinstance(ciso_payload, dict) else None
            ),
        }
        upsert_scan_record_for_client(client_name, scan_record)
        mark_asset_scanned_for_engine(
            client_name,
            str(current["asset_ip"]),
            scanned_at,
            "Nuclei",
        )
        update_nuclei_job(
            job_id,
            source_path=str(source_path),
            report_path=str(pdf_path),
            status="Completed",
            provider_status="Completed",
            ui_status="Completed",
            stage="Report finalized",
            progress=100,
            result_message=(f"Saved {len(findings)} finding(s) and generated PDF evidence."),
            findings_count=int(metadata["findings_count"]),
            critical_count=int(metadata["critical_count"]),
            high_count=int(metadata["high_count"]),
            medium_count=int(metadata["medium_count"]),
            low_count=int(metadata["low_count"]),
            ciso_status=ciso_status,
            ciso_payload=ciso_payload,
            completed_at=scanned_at,
            last_provider_sync_at=utc_now_iso(),
            error="",
            event_type="report_finalized",
            message=f"Finalized report {report_id}.",
        )
    except Exception as exc:
        logger.exception("Nuclei finalization failed for job %s", job_id)
        failures += 1
        if failures < FINALIZATION_ATTEMPTS:
            update_nuclei_job(
                job_id,
                status="Processing",
                provider_status="Completed",
                ui_status="Processing",
                finalization_attempts=failures,
                stage=(
                    "Report finalization retry pending " f"({failures}/{FINALIZATION_ATTEMPTS})"
                ),
                error=f"{type(exc).__name__}: {exc}",
                event_type="report_finalization_retry_pending",
                message="The exact JSONL evidence paths remain preserved.",
            )
            return

        update_nuclei_job(
            job_id,
            status="Failed",
            provider_status="Completed",
            ui_status="Failed",
            finalization_attempts=failures,
            stage="Report finalization failed",
            error=f"{type(exc).__name__}: {exc}",
            completed_at=utc_now_iso(),
            event_type="report_finalization_failed",
            message="Maximum finalization attempts reached.",
        )


def _sync_running_job(job: dict[str, Any]) -> None:
    """Reconcile one running or finalizing Nuclei job."""

    job_id = int(job["id"])
    result_path = Path(str(job.get("result_path") or ""))
    output_path = Path(str(job.get("output_path") or ""))
    stderr_path = Path(str(job.get("stderr_path") or ""))

    if result_path.is_file():
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            update_nuclei_job(
                job_id,
                status="Processing",
                provider_status="Completed",
                ui_status="Processing",
                stage="Waiting for a readable runner result",
                error=f"{type(exc).__name__}: {exc}",
                last_provider_sync_at=utc_now_iso(),
            )
            return

        exit_code = int(result.get("exit_code") or 0)
        if exit_code == 0:
            _finalize_job(job, result)
            return

        error = str(result.get("error") or "").strip()
        stderr_tail = _tail(stderr_path)
        detail = error or stderr_tail or f"Nuclei exited with code {exit_code}."
        update_nuclei_job(
            job_id,
            status="Failed",
            provider_status=f"Exit code {exit_code}",
            ui_status="Failed",
            stage="Nuclei process failed",
            progress=100,
            findings_count=count_jsonl_findings(output_path),
            error=detail[:4000],
            completed_at=str(result.get("completed_at") or utc_now_iso()),
            last_provider_sync_at=utc_now_iso(),
            event_type="runner_failed",
            message="The raw logs and partial JSONL evidence remain available.",
        )
        return

    if str(job.get("ui_status")) in {"Processing", "Finalizing"}:
        # A previous finalization retry already has durable process output.
        synthetic_result = {
            "completed_at": job.get("completed_at") or utc_now_iso(),
            "exit_code": 0,
        }
        _finalize_job(job, synthetic_result)
        return

    runner_pid = job.get("runner_pid")
    if _process_alive(runner_pid):
        findings_count = count_jsonl_findings(output_path)
        stats = _latest_stats(stderr_path)
        elapsed = int(_age_seconds(job.get("started_at")))
        requests = stats.get("requests") or stats.get("total") or 0
        matched = stats.get("matched") or findings_count
        errors = stats.get("errors") or 0
        update_nuclei_job(
            job_id,
            status="Running",
            provider_status="Executing",
            ui_status="Running",
            stage=(
                f"Nuclei executing · {elapsed}s elapsed · "
                f"{matched} match(es) · {requests} request(s) · "
                f"{errors} error(s)"
            ),
            progress=_progress_from_stats(stats),
            stats_payload=stats,
            findings_count=findings_count,
            last_provider_sync_at=utc_now_iso(),
            error="",
        )
        return

    age = _age_seconds(job.get("started_at"))
    if age <= RUNNER_RESULT_GRACE_SECONDS:
        update_nuclei_job(
            job_id,
            provider_status="Awaiting runner result",
            stage="Process ended; waiting for durable result marker",
            last_provider_sync_at=utc_now_iso(),
        )
        return

    update_nuclei_job(
        job_id,
        status="Interrupted",
        provider_status="Runner missing",
        ui_status="Interrupted",
        stage="Nuclei runner ended without a result marker",
        findings_count=count_jsonl_findings(output_path),
        error=(
            "The stored runner PID is not active and no result.json was "
            "written. Review stdout.log and stderr.log before retrying."
        ),
        completed_at=utc_now_iso(),
        last_provider_sync_at=utc_now_iso(),
        event_type="runner_missing",
        message="The exact attempt files remain preserved for diagnosis.",
    )


def process_worker_cycle(client: NucleiClient | None = None) -> dict[str, int]:
    """Run one bounded Nuclei worker cycle."""

    init_nuclei_tables()
    scanner = client or NucleiClient()
    scanner.resolved_binary()
    consume_wake_requests()

    active = count_active_nuclei_jobs()
    capacity = max(0, MAX_CONCURRENT_SCANS - active)
    claimed = claim_queued_nuclei_jobs(capacity)
    started = 0
    for job in claimed:
        try:
            _start_claimed_job(scanner, job)
            started += 1
        except Exception as exc:
            logger.exception("Could not start Nuclei job %s", job.get("id"))
            update_nuclei_job(
                int(job["id"]),
                status="Failed",
                provider_status="Preparation failed",
                ui_status="Failed",
                stage="Nuclei job preparation failed",
                error=f"{type(exc).__name__}: {exc}",
                completed_at=utc_now_iso(),
                event_type="job_preparation_failed",
                message="The job can be retried after correcting the configuration.",
            )

    sync_jobs = list_jobs_for_provider_sync(limit=SYNC_LIMIT)
    synchronized = 0
    batch_ids: set[int] = {int(job["batch_id"]) for job in claimed}
    for job in sync_jobs:
        _sync_running_job(job)
        synchronized += 1
        batch_ids.add(int(job["batch_id"]))

    for batch_id in batch_ids:
        update_nuclei_batch_counters(batch_id)

    return {
        "claimed": len(claimed),
        "started": started,
        "synchronized": synchronized,
    }


def run_worker_forever() -> None:
    """Run the standalone Nuclei worker until stopped."""

    init_nuclei_tables()
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    REPORT_OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    with ProviderWorkerLock():
        client = NucleiClient()
        health = client.health()
        update_worker_heartbeat(
            worker_name=WORKER_NAME,
            pid=os.getpid(),
            status="running",
            message=(
                f"Nuclei worker started · engine {health.get('version')} · "
                f"templates {health.get('templates_version')}"
            ),
        )
        while True:
            try:
                result = process_worker_cycle(client)
                message = (
                    f"claimed={result['claimed']} "
                    f"started={result['started']} "
                    f"synced={result['synchronized']}"
                )
                update_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    pid=os.getpid(),
                    status="running",
                    message=message,
                )
                time.sleep(POLL_SECONDS)
            except KeyboardInterrupt:
                update_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    pid=os.getpid(),
                    status="stopped",
                    message="Worker stopped by operator.",
                )
                return
            except NucleiError as exc:
                logger.exception("Nuclei provider cycle failed")
                update_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    pid=os.getpid(),
                    status="error",
                    message=f"{type(exc).__name__}: {exc}",
                )
                time.sleep(ERROR_RETRY_SECONDS)
            except Exception as exc:
                logger.exception("Unexpected Nuclei worker cycle failure")
                update_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    pid=os.getpid(),
                    status="error",
                    message=f"{type(exc).__name__}: {exc}",
                )
                time.sleep(ERROR_RETRY_SECONDS)
