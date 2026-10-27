"""PostgreSQL persistence for SecureScope Nuclei batches and jobs.

Every attempt is identified by client, batch UUID, job UUID and attempt number.
An asset IP is target data and is never used as the sole scan identity.
"""

from __future__ import annotations

import os
import socket
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import get_database_url, init_database

_NUCLEI_INITIALIZED = False
_NUCLEI_INIT_LOCK = threading.Lock()
_NUCLEI_DDL_LOCK_KEY = 74109003

ACTIVE_UI_STATUSES = {
    "Starting",
    "Running",
    "Processing",
    "Finalizing",
}
TERMINAL_UI_STATUSES = {
    "Completed",
    "Stopped",
    "Interrupted",
    "Failed",
    "Abandoned",
}


class NucleiDatabaseError(RuntimeError):
    """Raised when Nuclei persistence fails."""


@contextmanager
def connect() -> Iterator[Any]:
    """Open one transactional PostgreSQL connection.

    Yields:
        A PostgreSQL connection.

    Raises:
        NucleiDatabaseError: If PostgreSQL returns an error.
    """

    connection = None
    try:
        connection = psycopg2.connect(get_database_url())
        yield connection
        connection.commit()
    except psycopg2.Error as exc:
        if connection is not None:
            connection.rollback()
        raise NucleiDatabaseError(str(exc)) from exc
    finally:
        if connection is not None:
            connection.close()


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(timezone.utc)


def _row_dict(row: Any) -> dict[str, Any]:
    """Normalize a PostgreSQL row into a dictionary."""

    return dict(row) if row else {}


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve an existing workspace; stale jobs cannot recreate a deleted client."""
    from securescope.persistence.db_service import _get_client_id

    return _get_client_id(cursor, client_name, create=False)


def init_nuclei_tables() -> None:
    """Create or migrate Nuclei persistence tables once per process."""

    global _NUCLEI_INITIALIZED
    if _NUCLEI_INITIALIZED:
        return

    with _NUCLEI_INIT_LOCK:
        if _NUCLEI_INITIALIZED:
            return

        init_database()
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s);",
                    (_NUCLEI_DDL_LOCK_KEY,),
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_nuclei_batches (
                        id BIGSERIAL PRIMARY KEY,
                        batch_uuid TEXT NOT NULL UNIQUE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        label TEXT NOT NULL,
                        scan_mode TEXT NOT NULL,
                        profile_name TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'Queued',
                        sync_to_ciso BOOLEAN NOT NULL DEFAULT FALSE,
                        submitted_count INTEGER NOT NULL DEFAULT 0,
                        completed_count INTEGER NOT NULL DEFAULT 0,
                        failed_count INTEGER NOT NULL DEFAULT 0,
                        dispatch_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        dispatch_requested_at TIMESTAMPTZ,
                        started_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_nuclei_jobs (
                        id BIGSERIAL PRIMARY KEY,
                        batch_id BIGINT NOT NULL
                            REFERENCES securescope_nuclei_batches(id)
                            ON DELETE CASCADE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id)
                            ON DELETE CASCADE,
                        logical_job_id TEXT NOT NULL,
                        job_uuid TEXT NOT NULL UNIQUE,
                        attempt_number INTEGER NOT NULL DEFAULT 1,
                        retry_of_job_id BIGINT NULL
                            REFERENCES securescope_nuclei_jobs(id)
                            ON DELETE SET NULL,
                        is_current_attempt BOOLEAN NOT NULL DEFAULT TRUE,
                        asset_ip TEXT NOT NULL,
                        asset_tag TEXT,
                        asset_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                        targets JSONB NOT NULL DEFAULT '[]'::jsonb,
                        scan_name TEXT NOT NULL,
                        runner_pid INTEGER,
                        command_path TEXT,
                        target_path TEXT,
                        output_path TEXT,
                        stdout_path TEXT,
                        stderr_path TEXT,
                        result_path TEXT,
                        source_path TEXT,
                        status TEXT NOT NULL DEFAULT 'Queued',
                        provider_status TEXT NOT NULL DEFAULT 'Not started',
                        ui_status TEXT NOT NULL DEFAULT 'Queued',
                        stage TEXT NOT NULL DEFAULT 'Preparing Nuclei scan',
                        progress INTEGER NOT NULL DEFAULT 0,
                        stats_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                        result_message TEXT,
                        error TEXT,
                        findings_count INTEGER NOT NULL DEFAULT 0,
                        critical_count INTEGER NOT NULL DEFAULT 0,
                        high_count INTEGER NOT NULL DEFAULT 0,
                        medium_count INTEGER NOT NULL DEFAULT 0,
                        low_count INTEGER NOT NULL DEFAULT 0,
                        report_path TEXT,
                        sync_to_ciso BOOLEAN NOT NULL DEFAULT FALSE,
                        ciso_status TEXT,
                        ciso_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                        submission_attempts INTEGER NOT NULL DEFAULT 0,
                        finalization_attempts INTEGER NOT NULL DEFAULT 0,
                        submitted_at TIMESTAMPTZ,
                        started_at TIMESTAMPTZ,
                        last_provider_sync_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (batch_id, asset_ip, attempt_number)
                    );
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_nuclei_job_events (
                        id BIGSERIAL PRIMARY KEY,
                        job_id BIGINT REFERENCES securescope_nuclei_jobs(id)
                            ON DELETE CASCADE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id)
                            ON DELETE CASCADE,
                        batch_id BIGINT NOT NULL
                            REFERENCES securescope_nuclei_batches(id)
                            ON DELETE CASCADE,
                        event_type TEXT NOT NULL,
                        provider_status TEXT,
                        ui_status TEXT,
                        stage TEXT,
                        progress INTEGER,
                        message TEXT,
                        error TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_nuclei_worker_state (
                        worker_name TEXT PRIMARY KEY,
                        pid INTEGER,
                        hostname TEXT,
                        status TEXT,
                        message TEXT,
                        heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_nuclei_wake_requests (
                        id BIGSERIAL PRIMARY KEY,
                        batch_id BIGINT NULL
                            REFERENCES securescope_nuclei_batches(id)
                            ON DELETE CASCADE,
                        reason TEXT,
                        requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        consumed_at TIMESTAMPTZ
                    );
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_nuclei_batches_client
                        ON securescope_nuclei_batches
                        (client_id, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_nuclei_jobs_batch
                        ON securescope_nuclei_jobs (batch_id, id);
                    CREATE INDEX IF NOT EXISTS idx_nuclei_jobs_dispatch
                        ON securescope_nuclei_jobs
                        (ui_status, is_current_attempt, updated_at);
                    CREATE INDEX IF NOT EXISTS idx_nuclei_events_job
                        ON securescope_nuclei_job_events
                        (job_id, created_at DESC);
                    """
                )

        _NUCLEI_INITIALIZED = True


def deterministic_scan_name(
    *,
    client_id: int,
    batch_uuid: str,
    job_uuid: str,
    asset_ip: str,
    attempt_number: int,
) -> str:
    """Build an exact, reproducible Nuclei run name."""

    compact_ip = asset_ip.replace(":", "-").replace("/", "-")
    return (
        f"securescope-nuclei-c{client_id}-{batch_uuid[:8]}-"
        f"{job_uuid[:8]}-{compact_ip}-a{attempt_number}"
    )[:128]


def _record_event_with_cursor(
    cursor: Any,
    *,
    job: dict[str, Any],
    event_type: str,
    message: str = "",
    error: str = "",
) -> None:
    """Insert an immutable job event using an existing cursor."""

    cursor.execute(
        """
        INSERT INTO securescope_nuclei_job_events (
            job_id,
            client_id,
            batch_id,
            event_type,
            provider_status,
            ui_status,
            stage,
            progress,
            message,
            error
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (
            job.get("id"),
            job.get("client_id"),
            job.get("batch_id"),
            event_type,
            job.get("provider_status"),
            job.get("ui_status"),
            job.get("stage"),
            int(job.get("progress") or 0),
            message,
            error,
        ),
    )


def create_nuclei_batch(
    *,
    client_name: str,
    assets: list[dict[str, Any]],
    scan_mode: str,
    profile_name: str,
    sync_to_ciso: bool = False,
    collection_context: dict | None = None,
    actor: str = "",
) -> dict[str, Any]:
    """Create one workspace-scoped batch and one job per unique asset."""

    init_nuclei_tables()
    unique_assets: dict[str, dict[str, Any]] = {}
    for asset in assets:
        asset_ip = str(asset.get("ip") or "").strip()
        if asset_ip:
            unique_assets[asset_ip] = dict(asset)
    if not unique_assets:
        raise NucleiDatabaseError("No usable assets were supplied.")

    batch_uuid = str(uuid.uuid4())
    label = f"{scan_mode} · {utc_now().astimezone().strftime('%Y-%m-%d %H:%M')}"

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            client_id = _client_id(cursor, client_name)
            cursor.execute(
                """
                INSERT INTO securescope_nuclei_batches (
                    batch_uuid,
                    client_id,
                    label,
                    scan_mode,
                    profile_name,
                    status,
                    sync_to_ciso,
                    submitted_count,
                    dispatch_enabled,
                    dispatch_requested_at,
                    started_at
                )
                VALUES (%s, %s, %s, %s, %s, 'Queued', %s, %s, TRUE, NOW(), NOW())
                RETURNING *;
                """,
                (
                    batch_uuid,
                    client_id,
                    label,
                    scan_mode,
                    profile_name,
                    bool(sync_to_ciso),
                    len(unique_assets),
                ),
            )
            batch = _row_dict(cursor.fetchone())
            batch_id = int(batch["id"])

            if collection_context:
                from securescope.persistence.foundation_repository import member_role

                if member_role(cursor, client_id, actor) not in {"Administrator", "Consultant"}:
                    raise NucleiDatabaseError(
                        "Requirement collection requires an authorized workspace member."
                    )
                if collection_context.get("client") != client_name:
                    raise NucleiDatabaseError("Collection origin belongs to another workspace.")
                cursor.execute(
                    "SELECT id FROM securescope_scope_definitions WHERE client_id=%s "
                    "AND id=%s AND engagement_id=%s AND NOT archived",
                    (
                        client_id,
                        collection_context.get("scope_id"),
                        collection_context.get("engagement_id"),
                    ),
                )
                if not cursor.fetchone():
                    raise NucleiDatabaseError("Collection scope is unavailable.")
            for asset_ip, asset in unique_assets.items():
                asset.pop("evidence_collection_context", None)
                from securescope.persistence.requirement_evidence_repository import freeze_targets

                try:
                    asset["m3_requirement_targets"] = freeze_targets(
                        cursor, client_id, asset_ip, collection_context
                    )
                except ValueError as exc:
                    raise NucleiDatabaseError(str(exc)) from exc
                if collection_context:
                    asset["evidence_collection_context"] = dict(collection_context)
                job_uuid = str(uuid.uuid4())
                logical_job_id = str(uuid.uuid4())
                scan_name = deterministic_scan_name(
                    client_id=client_id,
                    batch_uuid=batch_uuid,
                    job_uuid=job_uuid,
                    asset_ip=asset_ip,
                    attempt_number=1,
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_nuclei_jobs (
                        batch_id,
                        client_id,
                        logical_job_id,
                        job_uuid,
                        attempt_number,
                        asset_ip,
                        asset_tag,
                        asset_payload,
                        scan_name,
                        status,
                        provider_status,
                        ui_status,
                        stage,
                        sync_to_ciso,
                        submitted_at
                    )
                    VALUES (
                        %s, %s, %s, %s, 1, %s, %s, %s, %s,
                        'Queued', 'Not started', 'Queued',
                        'Preparing Nuclei scan', %s, NOW()
                    )
                    RETURNING *;
                    """,
                    (
                        batch_id,
                        client_id,
                        logical_job_id,
                        job_uuid,
                        asset_ip,
                        str(asset.get("asset_tag") or ""),
                        Json(asset),
                        scan_name,
                        bool(sync_to_ciso),
                    ),
                )
                job = _row_dict(cursor.fetchone())
                _record_event_with_cursor(
                    cursor,
                    job=job,
                    event_type="job_saved",
                    message=(
                        "Saved in the client workspace. The standalone Nuclei "
                        "worker will execute this exact attempt."
                    ),
                )

            request_wake_cursor(
                cursor,
                batch_id=batch_id,
                reason="New Nuclei batch created by the UI.",
            )
            return batch


def record_nuclei_event(
    *,
    job_id: int,
    event_type: str,
    message: str = "",
    error: str = "",
) -> None:
    """Persist one immutable Nuclei job event."""

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM securescope_nuclei_jobs WHERE id = %s;",
                (int(job_id),),
            )
            job = _row_dict(cursor.fetchone())
            if not job:
                raise NucleiDatabaseError(f"Nuclei job not found: {job_id}")
            _record_event_with_cursor(
                cursor,
                job=job,
                event_type=event_type,
                message=message,
                error=error,
            )


def request_wake_cursor(
    cursor: Any,
    *,
    batch_id: int | None,
    reason: str,
) -> None:
    """Insert one worker wake request using an existing cursor."""

    cursor.execute(
        """
        INSERT INTO securescope_nuclei_wake_requests (batch_id, reason)
        VALUES (%s, %s);
        """,
        (batch_id, reason),
    )


def request_nuclei_worker_wake(
    *,
    batch_id: int | None = None,
    reason: str = "Manual wake request.",
) -> None:
    """Wake the standalone worker without opening a scanner process."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor() as cursor:
            request_wake_cursor(cursor, batch_id=batch_id, reason=reason)


def consume_wake_requests() -> list[dict[str, Any]]:
    """Mark pending wake requests consumed and return them."""

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                UPDATE securescope_nuclei_wake_requests
                SET consumed_at = NOW()
                WHERE id IN (
                    SELECT id
                    FROM securescope_nuclei_wake_requests
                    WHERE consumed_at IS NULL
                    ORDER BY requested_at
                    LIMIT 100
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING *;
                """
            )
            return [dict(row) for row in cursor.fetchall()]


def list_nuclei_batches(
    client_name: str,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return recent Nuclei batches for one client workspace."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            client_id = _client_id(cursor, client_name)
            cursor.execute(
                """
                SELECT *
                FROM securescope_nuclei_batches
                WHERE client_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s;
                """,
                (client_id, max(1, int(limit))),
            )
            return [dict(row) for row in cursor.fetchall()]


def get_nuclei_batch(batch_id: int) -> dict[str, Any]:
    """Return one Nuclei batch."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM securescope_nuclei_batches WHERE id = %s;",
                (int(batch_id),),
            )
            return _row_dict(cursor.fetchone())


def load_nuclei_batch_jobs(batch_id: int) -> list[dict[str, Any]]:
    """Return current and historical attempts for one batch."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT *
                FROM securescope_nuclei_jobs
                WHERE batch_id = %s
                ORDER BY asset_ip, attempt_number, id;
                """,
                (int(batch_id),),
            )
            return [dict(row) for row in cursor.fetchall()]


def get_nuclei_job(job_id: int) -> dict[str, Any]:
    """Return one Nuclei job attempt."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM securescope_nuclei_jobs WHERE id = %s;",
                (int(job_id),),
            )
            return _row_dict(cursor.fetchone())


def list_nuclei_job_events(
    job_id: int,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return recent immutable events for one job."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT *
                FROM securescope_nuclei_job_events
                WHERE job_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s;
                """,
                (int(job_id), max(1, int(limit))),
            )
            return [dict(row) for row in cursor.fetchall()]


def count_active_nuclei_jobs() -> int:
    """Return the number of current jobs consuming process capacity."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM securescope_nuclei_jobs
                WHERE is_current_attempt = TRUE
                  AND ui_status = ANY(%s);
                """,
                (list(ACTIVE_UI_STATUSES),),
            )
            row = cursor.fetchone()
            return int(row[0] if row else 0)


def claim_queued_nuclei_jobs(limit: int) -> list[dict[str, Any]]:
    """Atomically claim queued jobs from dispatch-enabled batches."""

    if limit <= 0:
        return []
    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                WITH selected AS (
                    SELECT j.id
                    FROM securescope_nuclei_jobs j
                    JOIN securescope_nuclei_batches b ON b.id = j.batch_id
                    WHERE j.is_current_attempt = TRUE
                      AND j.ui_status = 'Queued'
                      AND j.runner_pid IS NULL
                      AND b.dispatch_enabled = TRUE
                    ORDER BY b.dispatch_requested_at NULLS LAST,
                             b.created_at,
                             j.id
                    LIMIT %s
                    FOR UPDATE OF j SKIP LOCKED
                )
                UPDATE securescope_nuclei_jobs j
                SET status = 'Starting',
                    ui_status = 'Starting',
                    provider_status = 'Preparing process',
                    stage = 'Building Nuclei command and target list',
                    submission_attempts = submission_attempts + 1,
                    updated_at = NOW()
                FROM selected
                WHERE j.id = selected.id
                RETURNING j.*;
                """,
                (int(limit),),
            )
            jobs = [dict(row) for row in cursor.fetchall()]
            for job in jobs:
                _record_event_with_cursor(
                    cursor,
                    job=job,
                    event_type="job_claimed",
                    message="Claimed by the standalone Nuclei worker.",
                )
            return jobs


def list_jobs_for_provider_sync(limit: int = 200) -> list[dict[str, Any]]:
    """Return running or finalizing jobs that require worker reconciliation."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT *
                FROM securescope_nuclei_jobs
                WHERE is_current_attempt = TRUE
                  AND ui_status = ANY(%s)
                ORDER BY last_provider_sync_at NULLS FIRST, updated_at, id
                LIMIT %s;
                """,
                (list(ACTIVE_UI_STATUSES), max(1, int(limit))),
            )
            return [dict(row) for row in cursor.fetchall()]


def update_nuclei_job(
    job_id: int,
    *,
    event_type: str | None = None,
    message: str = "",
    **changes: Any,
) -> dict[str, Any]:
    """Update selected fields on one job and optionally append an event."""

    allowed = {
        "targets",
        "runner_pid",
        "command_path",
        "target_path",
        "output_path",
        "stdout_path",
        "stderr_path",
        "result_path",
        "source_path",
        "status",
        "provider_status",
        "ui_status",
        "stage",
        "progress",
        "stats_payload",
        "result_message",
        "error",
        "findings_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "report_path",
        "ciso_status",
        "ciso_payload",
        "finalization_attempts",
        "started_at",
        "last_provider_sync_at",
        "completed_at",
    }
    fields = {key: value for key, value in changes.items() if key in allowed}
    if not fields:
        return get_nuclei_job(job_id)

    json_fields = {"targets", "stats_payload", "ciso_payload"}
    assignments: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        assignments.append(f"{key} = %s")
        values.append(Json(value) if key in json_fields else value)
    assignments.append("updated_at = NOW()")
    values.append(int(job_id))

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                f"""
                UPDATE securescope_nuclei_jobs
                SET {', '.join(assignments)}
                WHERE id = %s
                RETURNING *;
                """,
                tuple(values),
            )
            job = _row_dict(cursor.fetchone())
            if not job:
                raise NucleiDatabaseError(f"Nuclei job not found: {job_id}")
            if event_type:
                _record_event_with_cursor(
                    cursor,
                    job=job,
                    event_type=event_type,
                    message=message,
                    error=str(job.get("error") or ""),
                )
            return job


def update_nuclei_batch_counters(batch_id: int) -> dict[str, Any]:
    """Recalculate one batch from current attempts."""

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE ui_status = 'Completed') AS completed,
                    COUNT(*) FILTER (
                        WHERE ui_status IN (
                            'Failed', 'Interrupted', 'Stopped', 'Abandoned'
                        )
                    ) AS failed,
                    COUNT(*) FILTER (WHERE ui_status = ANY(%s)) AS active
                FROM securescope_nuclei_jobs
                WHERE batch_id = %s
                  AND is_current_attempt = TRUE;
                """,
                (list(ACTIVE_UI_STATUSES), int(batch_id)),
            )
            counters = _row_dict(cursor.fetchone())
            total = int(counters.get("total") or 0)
            completed = int(counters.get("completed") or 0)
            failed = int(counters.get("failed") or 0)
            active = int(counters.get("active") or 0)

            if total and completed + failed >= total:
                status = "Completed" if failed == 0 else "Completed with attention"
                completed_at = utc_now()
            elif active:
                status = "Running"
                completed_at = None
            else:
                status = "Queued"
                completed_at = None

            cursor.execute(
                """
                UPDATE securescope_nuclei_batches
                SET status = %s,
                    completed_count = %s,
                    failed_count = %s,
                    completed_at = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *;
                """,
                (status, completed, failed, completed_at, int(batch_id)),
            )
            return _row_dict(cursor.fetchone())


def update_worker_heartbeat(
    *,
    worker_name: str,
    pid: int,
    status: str,
    message: str,
) -> None:
    """Upsert standalone Nuclei worker health."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO securescope_nuclei_worker_state (
                    worker_name,
                    pid,
                    hostname,
                    status,
                    message,
                    heartbeat_at,
                    started_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), NOW())
                ON CONFLICT (worker_name)
                DO UPDATE SET
                    pid = EXCLUDED.pid,
                    hostname = EXCLUDED.hostname,
                    status = EXCLUDED.status,
                    message = EXCLUDED.message,
                    heartbeat_at = NOW(),
                    started_at = CASE
                        WHEN securescope_nuclei_worker_state.pid
                             IS DISTINCT FROM EXCLUDED.pid
                          OR securescope_nuclei_worker_state.hostname
                             IS DISTINCT FROM EXCLUDED.hostname
                        THEN NOW()
                        ELSE securescope_nuclei_worker_state.started_at
                    END,
                    updated_at = NOW();
                """,
                (worker_name, int(pid), socket.gethostname(), status, message),
            )


def get_worker_state(worker_name: str | None = None) -> dict[str, Any]:
    """Return Nuclei worker state with calculated heartbeat age."""

    init_nuclei_tables()
    resolved_name = worker_name or os.getenv(
        "NUCLEI_WORKER_NAME",
        "nuclei-monitor",
    )
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT *,
                       EXTRACT(EPOCH FROM (NOW() - heartbeat_at))::INTEGER
                           AS heartbeat_age_seconds
                FROM securescope_nuclei_worker_state
                WHERE worker_name = %s;
                """,
                (resolved_name,),
            )
            return _row_dict(cursor.fetchone())


def reset_job_to_queue(job_id: int, reason: str) -> dict[str, Any]:
    """Return one recoverable attempt to the Nuclei worker queue."""

    job = get_nuclei_job(job_id)
    if not job:
        raise NucleiDatabaseError(f"Nuclei job not found: {job_id}")
    return update_nuclei_job(
        job_id,
        runner_pid=None,
        status="Queued",
        provider_status="Not started",
        ui_status="Queued",
        stage="Queued for Nuclei worker",
        error="",
        result_message=reason,
        event_type="job_requeued",
        message=reason,
    )


def retry_nuclei_job(job_id: int, reason: str) -> dict[str, Any]:
    """Create a new exact attempt for one terminal Nuclei job."""

    init_nuclei_tables()
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM securescope_nuclei_jobs WHERE id = %s FOR UPDATE;",
                (int(job_id),),
            )
            source = _row_dict(cursor.fetchone())
            if not source:
                raise NucleiDatabaseError(f"Nuclei job not found: {job_id}")

            cursor.execute(
                """
                UPDATE securescope_nuclei_jobs
                SET is_current_attempt = FALSE,
                    updated_at = NOW()
                WHERE logical_job_id = %s
                  AND is_current_attempt = TRUE;
                """,
                (source["logical_job_id"],),
            )

            new_job_uuid = str(uuid.uuid4())
            attempt_number = int(source.get("attempt_number") or 1) + 1
            batch = get_nuclei_batch(int(source["batch_id"]))
            scan_name = deterministic_scan_name(
                client_id=int(source["client_id"]),
                batch_uuid=str(batch.get("batch_uuid") or "batch"),
                job_uuid=new_job_uuid,
                asset_ip=str(source["asset_ip"]),
                attempt_number=attempt_number,
            )
            cursor.execute(
                """
                INSERT INTO securescope_nuclei_jobs (
                    batch_id,
                    client_id,
                    logical_job_id,
                    job_uuid,
                    attempt_number,
                    retry_of_job_id,
                    is_current_attempt,
                    asset_ip,
                    asset_tag,
                    asset_payload,
                    scan_name,
                    status,
                    provider_status,
                    ui_status,
                    stage,
                    result_message,
                    sync_to_ciso,
                    submitted_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, TRUE,
                    %s, %s, %s, %s,
                    'Queued', 'Not started', 'Queued',
                    'Queued retry for Nuclei worker', %s, %s, NOW()
                )
                RETURNING *;
                """,
                (
                    source["batch_id"],
                    source["client_id"],
                    source["logical_job_id"],
                    new_job_uuid,
                    attempt_number,
                    source["id"],
                    source["asset_ip"],
                    source.get("asset_tag") or "",
                    Json(source.get("asset_payload") or {}),
                    scan_name,
                    reason,
                    bool(source.get("sync_to_ciso")),
                ),
            )
            created = _row_dict(cursor.fetchone())
            _record_event_with_cursor(
                cursor,
                job=created,
                event_type="job_retry_created",
                message=reason,
            )
            request_wake_cursor(
                cursor,
                batch_id=int(source["batch_id"]),
                reason=f"Retry requested for job {job_id}.",
            )
            return created
