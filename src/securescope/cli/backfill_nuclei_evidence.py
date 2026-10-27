"""Idempotent historical Nuclei ingestion using the live canonical bridge."""

import argparse
import logging
from pathlib import Path

from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from securescope.evidence.evidence_service import EvidenceServiceError, ingest_nuclei_scan_output
from securescope.evidence.storage import EvidenceStorageError
from securescope.paths import ENV_FILE
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    repair_nuclei_evidence,
)
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


def backfill(client, dry_run=False):
    """Ingest completed jobs and repair deterministic links without duplicating evidence.

    Args:
        client: Exact existing client name; never scans other tenants.
        dry_run: Inspect candidates without writes or artifact creation.
    Returns:
        Counts for created, revisited, unavailable artifacts and errors.
    Raises:
        DatabaseError: If database access fails.
    """
    if not dry_run:
        run_pending_migrations()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT j.*,b.profile_name,c.name AS client_name,e.id AS evidence_id "
                "FROM securescope_nuclei_jobs j JOIN securescope_clients c ON c.id=j.client_id "
                "JOIN securescope_nuclei_batches b ON b.client_id=j.client_id AND b.id=j.batch_id "
                "LEFT JOIN securescope_evidence_records e ON e.client_id=j.client_id "
                "AND e.tool_id='nuclei' AND e.source_key='nuclei:' || j.job_uuid::text "
                "|| ':attempt:' || j.attempt_number::text "
                "WHERE c.name=%s AND j.provider_status='Completed' "
                "AND j.status IN ('Completed','Finalizing') ORDER BY j.id",
                (client,),
            )
            jobs = [dict(row) for row in cursor.fetchall()]
    counts = dict(created=0, revisited=0, unavailable=0, errors=0, candidates=len(jobs))
    for job in jobs:
        if job["evidence_id"]:
            if not dry_run:
                try:
                    repaired = repair_nuclei_evidence(client, int(job["evidence_id"]))
                except (EvidenceRepositoryError, DatabaseError) as exc:
                    counts["errors"] += 1
                    LOGGER.error("Job %s evidence repair failed: %s", job["id"], exc)
                else:
                    counts["revisited" if repaired else "unavailable"] += 1
            continue
        path = Path(job.get("output_path") or "")
        if not path.is_file():
            counts["unavailable"] += 1
            LOGGER.warning(
                "Job %s has no retained JSONL artifact; no evidence invented.", job["id"]
            )
            continue
        if dry_run:
            continue
        try:
            ingest_nuclei_scan_output(
                client,
                job_uuid=str(job["job_uuid"]),
                attempt_number=int(job["attempt_number"]),
                report_id=str(job.get("report_id") or job["job_uuid"]),
                asset_ip=job["asset_ip"],
                profile=job["profile_name"],
                collected_at=job.get("completed_at") or job.get("updated_at"),
                content=path.read_bytes(),
                successful=True,
            )
            counts["revisited" if job["evidence_id"] else "created"] += 1
        except (
            OSError,
            EvidenceServiceError,
            EvidenceStorageError,
            EvidenceRepositoryError,
            DatabaseError,
        ) as exc:
            counts["errors"] += 1
            LOGGER.error("Job %s backfill failed: %s", job["id"], exc)
    return counts


def main() -> int:
    """Run the repair CLI with canonical environment configuration.

    Args:
        None; options are read from the command line.
    Returns:
        Zero on success, one when any individual repair fails.
    Raises:
        DatabaseError: If candidate discovery cannot access PostgreSQL.
    """
    load_dotenv(dotenv_path=ENV_FILE, override=False)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, help="Exact workspace name")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    counts = backfill(args.client, args.dry_run)
    print(counts)
    return int(bool(counts["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
