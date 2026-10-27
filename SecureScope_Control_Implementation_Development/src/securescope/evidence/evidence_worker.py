"""Independent persistent worker for allowlisted defensive collectors."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from securescope.evidence.connector_runner import (
    ConnectorPlanError,
    build_collection_plan,
    execute_collection_plan,
)
from securescope.evidence.evidence_service import ingest_collector_output
from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    claim_evidence_job,
    complete_evidence_job,
)
from securescope.persistence.migration_service import run_pending_migrations

load_dotenv(dotenv_path=ENV_FILE, override=False)

LOGGER = logging.getLogger("securescope.evidence.worker")
FORMAT_HINTS = {
    "theharvester": "json",
    "wapiti": "json",
    "lynis": "dat",
    "openscap": "arf",
    "prowler": "json",
    "scoutsuite": "json",
}


def _work_root() -> Path:
    """Return a dedicated worker directory, separate from immutable artifacts."""

    configured = os.getenv("SECURESCOPE_EVIDENCE_WORK_ROOT", "logs/evidence_jobs")
    root = Path(configured)
    if not root.is_absolute():
        root = PROJECT_ROOT / root
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def process_job(job: dict[str, Any]) -> int:
    """Execute and ingest one already-claimed client-scoped collector job."""

    payload = dict(job.get("request_payload") or {})
    tool_id = str(job["tool_id"])
    target = str(payload.get("target") or "")
    job_directory = (_work_root() / str(job["job_uuid"])).resolve()
    if _work_root() not in job_directory.parents:
        raise ConnectorPlanError("Invalid evidence worker job path.")
    allowed_root_value = os.getenv("SECURESCOPE_COLLECTOR_ALLOWED_ROOT", "").strip()
    allowed_root = Path(allowed_root_value).resolve() if allowed_root_value else None
    plan = build_collection_plan(
        tool_id,
        target,
        job_directory,
        allowed_root=allowed_root,
        profile=str(payload.get("profile") or ""),
        timeout_seconds=int(payload.get("timeout_seconds") or 1800),
    )
    report = execute_collection_plan(plan)
    filename = plan.output_path.name
    if "." not in filename:
        filename += ".json"
    return ingest_collector_output(
        str(job["client_name"]),
        tool_id=tool_id,
        filename=filename,
        content=report,
        requested_by=str(job["requested_by"]),
        target=target,
        format_hint=FORMAT_HINTS.get(tool_id),
        engagement_id=payload.get("engagement_id"),
        scope_id=payload.get("scope_id"),
    )


def run_worker(*, once: bool = False) -> int:
    """Poll PostgreSQL for jobs; scanner/UI failures cannot stop this process."""

    run_pending_migrations()
    worker_name = os.getenv("EVIDENCE_WORKER_NAME", "evidence-worker").strip()
    poll_seconds = max(1, int(os.getenv("EVIDENCE_WORKER_POLL_SECONDS", "5")))
    failures = 0
    next_assurance_refresh = 0.0
    while True:
        if time.monotonic() >= next_assurance_refresh:
            from securescope.evidence.continuous_assurance import refresh_continuous_assurance
            from securescope.persistence.db_service import DatabaseError

            try:
                refresh_continuous_assurance(max_profiles=20)
                from securescope.evidence.wazuh_scheduled import refresh_pending

                refresh_pending(worker_name)
            except (DatabaseError, EvidenceRepositoryError) as exc:
                LOGGER.warning("Continuous assurance refresh unavailable: %s", type(exc).__name__)
            next_assurance_refresh = time.monotonic() + 300
        from securescope.evidence.collection_scheduler import tick
        from securescope.evidence.wazuh_scheduled import process_scheduled_job
        from securescope.persistence import evidence_schedule_repository as schedules
        from securescope.persistence.db_service import DatabaseError

        scheduled = None
        try:
            tick(worker_name)
            scheduled = schedules.claim(worker_name)
            if scheduled:
                process_scheduled_job(scheduled)
        except (DatabaseError, EvidenceRepositoryError) as exc:
            # Persisted lease expiry recovers an interrupted operation. Never log response bodies.
            LOGGER.warning("Scheduled evidence unavailable: %s", type(exc).__name__)
        if once and scheduled:
            return 0
        try:
            job = claim_evidence_job(worker_name, schema_initialized=True)
        except EvidenceRepositoryError as exc:
            LOGGER.error("Unable to claim evidence job: %s", exc)
            failures += 1
            if once:
                return 1
            time.sleep(min(poll_seconds * max(failures, 1), 30))
            continue
        if not job:
            if once:
                return 0
            time.sleep(poll_seconds)
            continue
        failures = 0
        try:
            evidence_id = process_job(job)
        except Exception as exc:  # Worker boundary: retain job state for diagnosis.
            LOGGER.exception("Evidence job %s failed", job.get("job_uuid"))
            complete_evidence_job(
                int(job["client_id"]),
                int(job["id"]),
                succeeded=False,
                evidence_id=None,
                error=str(exc),
            )
        else:
            complete_evidence_job(
                int(job["client_id"]),
                int(job["id"]),
                succeeded=True,
                evidence_id=evidence_id,
            )
        if once:
            return 0


def main() -> None:
    """Console entry point."""

    logging.basicConfig(
        level=os.getenv("EVIDENCE_WORKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    raise SystemExit(run_worker())


if __name__ == "__main__":
    main()
