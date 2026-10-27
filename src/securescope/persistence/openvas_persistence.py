"""Persistent PostgreSQL state for SecureScope OpenVAS batches and jobs.

The module keeps scan execution isolated by client workspace while preserving
exact batch, job, task, report, attempt, event, and worker identities.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import connect, init_database

TERMINAL_JOB_STATUSES = {
    "Completed",
    "Recovered report",
    "Failed",
    "Stopped",
    "Interrupted",
    "Submission failed",
    "Submission blocked",
    "Abandoned",
    "Cancelled",
}

TERMINAL_BATCH_STATUSES = {
    "Completed",
    "Completed with errors",
    "Failed",
    "Cancelled",
}

ACTIVE_PROVIDER_STATUSES = {
    "Start submitted",
    "Start confirmation pending",
    "Requested",
    "Queued",
    "Running",
    "Processing",
    "Stop Requested",
    "Resume Requested",
}

_INITIALIZED = False
_INITIALIZE_LOCK = threading.Lock()


ACTIVE_UI_STATUSES = {
    "Creating",
    "Starting",
    "Waiting for scanner",
    "Running",
    "Processing results",
    "Stop requested",
    "Resume requested",
}


def utc_now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _row_id(row: Any) -> int:
    """Return an integer identifier from a cursor result row.

    Args:
        row: Tuple or mapping returned by PostgreSQL.

    Returns:
        Database identifier.

    Raises:
        RuntimeError: If PostgreSQL returned no row.
    """
    if row is None:
        raise RuntimeError("PostgreSQL did not return an id.")
    if isinstance(row, dict):
        return int(row["id"])
    return int(row[0])


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve an existing workspace; stale jobs cannot recreate a deleted client."""
    from securescope.persistence.db_service import _get_client_id

    return _get_client_id(cursor, client_name, create=False)


def init_openvas_tables() -> None:
    """Create and migrate all OpenVAS persistence tables once per process."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    with _INITIALIZE_LOCK:
        if _INITIALIZED:
            return

        init_database()
        with connect() as conn:
            with conn.cursor() as cur:
                # Prevent concurrent Streamlit processes from running the same
                # OpenVAS DDL migration and deadlocking on catalog locks.
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (74109002,))
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_openvas_batches (
                        id BIGSERIAL PRIMARY KEY,
                        batch_uuid TEXT NOT NULL UNIQUE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        label TEXT NOT NULL,
                        scan_mode TEXT NOT NULL,
                        profile_name TEXT,
                        port_list_name TEXT,
                        status TEXT NOT NULL DEFAULT 'Created',
                        sync_to_ciso BOOLEAN NOT NULL DEFAULT TRUE,
                        dispatch_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                        dispatch_requested_at TIMESTAMPTZ,
                        dispatch_completed_at TIMESTAMPTZ,
                        dispatch_note TEXT,
                        submitted_count INTEGER NOT NULL DEFAULT 0,
                        completed_count INTEGER NOT NULL DEFAULT 0,
                        failed_count INTEGER NOT NULL DEFAULT 0,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        started_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    ALTER TABLE securescope_openvas_batches
                        ADD COLUMN IF NOT EXISTS dispatch_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                        ADD COLUMN IF NOT EXISTS dispatch_requested_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS dispatch_completed_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS dispatch_note TEXT;
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_openvas_jobs (
                        id BIGSERIAL PRIMARY KEY,
                        batch_id BIGINT NOT NULL
                            REFERENCES securescope_openvas_batches(id) ON DELETE CASCADE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        asset_ip TEXT NOT NULL,
                        asset_tag TEXT,
                        asset_payload JSONB NOT NULL,
                        target_id TEXT,
                        task_id TEXT,
                        report_id TEXT,
                        scanner_id TEXT,
                        status TEXT NOT NULL DEFAULT 'Created',
                        provider_status TEXT,
                        provider_task_status TEXT,
                        provider_report_status TEXT,
                        provider_progress_source TEXT,
                        provider_scan_start TEXT,
                        provider_scan_end TEXT,
                        ui_status TEXT,
                        stage TEXT NOT NULL DEFAULT 'Waiting',
                        progress INTEGER NOT NULL DEFAULT 0,
                        queue_position INTEGER,
                        result_message TEXT,
                        error TEXT,
                        findings_count INTEGER NOT NULL DEFAULT 0,
                        critical_count INTEGER NOT NULL DEFAULT 0,
                        high_count INTEGER NOT NULL DEFAULT 0,
                        medium_count INTEGER NOT NULL DEFAULT 0,
                        pdf_path TEXT,
                        ciso_status TEXT NOT NULL DEFAULT 'Not requested',
                        ciso_payload JSONB,
                        sync_to_ciso BOOLEAN NOT NULL DEFAULT TRUE,
                        finalization_status TEXT NOT NULL DEFAULT 'pending',
                        finalization_attempts INTEGER NOT NULL DEFAULT 0,
                        logical_job_id TEXT,
                        attempt_number INTEGER NOT NULL DEFAULT 1,
                        retry_of_job_id BIGINT,
                        retry_reason TEXT,
                        is_current_attempt BOOLEAN NOT NULL DEFAULT TRUE,
                        job_uuid TEXT,
                        launch_report_id TEXT,
                        submission_attempts INTEGER NOT NULL DEFAULT 0,
                        action_requested TEXT,
                        action_reason TEXT,
                        action_requested_at TIMESTAMPTZ,
                        action_completed_at TIMESTAMPTZ,
                        submitted_at TIMESTAMPTZ,
                        started_at TIMESTAMPTZ,
                        last_synced_at TIMESTAMPTZ,
                        last_provider_sync_at TIMESTAMPTZ,
                        status_changed_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (batch_id, asset_ip)
                    );
                    """
                )

                # Safe migrations for installations created by earlier versions.
                cur.execute(
                    """
                    ALTER TABLE securescope_openvas_jobs
                        ADD COLUMN IF NOT EXISTS provider_status TEXT,
                        ADD COLUMN IF NOT EXISTS provider_task_status TEXT,
                        ADD COLUMN IF NOT EXISTS provider_report_status TEXT,
                        ADD COLUMN IF NOT EXISTS provider_progress_source TEXT,
                        ADD COLUMN IF NOT EXISTS provider_scan_start TEXT,
                        ADD COLUMN IF NOT EXISTS provider_scan_end TEXT,
                        ADD COLUMN IF NOT EXISTS ui_status TEXT,
                        ADD COLUMN IF NOT EXISTS queue_position INTEGER,
                        ADD COLUMN IF NOT EXISTS logical_job_id TEXT,
                        ADD COLUMN IF NOT EXISTS attempt_number INTEGER NOT NULL DEFAULT 1,
                        ADD COLUMN IF NOT EXISTS retry_of_job_id BIGINT,
                        ADD COLUMN IF NOT EXISTS retry_reason TEXT,
                        ADD COLUMN IF NOT EXISTS is_current_attempt BOOLEAN NOT NULL DEFAULT TRUE,
                        ADD COLUMN IF NOT EXISTS job_uuid TEXT,
                        ADD COLUMN IF NOT EXISTS launch_report_id TEXT,
                        ADD COLUMN IF NOT EXISTS submission_attempts INTEGER NOT NULL DEFAULT 0,
                        ADD COLUMN IF NOT EXISTS action_requested TEXT,
                        ADD COLUMN IF NOT EXISTS action_reason TEXT,
                        ADD COLUMN IF NOT EXISTS action_requested_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS action_completed_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS last_provider_sync_at TIMESTAMPTZ,
                        ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
                    """
                )
                cur.execute(
                    """
                    UPDATE securescope_openvas_jobs
                    SET
                        logical_job_id = COALESCE(
                            NULLIF(logical_job_id, ''),
                            'legacy-' || id::text
                        ),
                        job_uuid = COALESCE(
                            NULLIF(job_uuid, ''),
                            'legacy-job-' || id::text
                        ),
                        launch_report_id = COALESCE(
                            NULLIF(launch_report_id, ''),
                            report_id
                        ),
                        ui_status = COALESCE(NULLIF(ui_status, ''), status),
                        provider_status = COALESCE(
                            NULLIF(provider_status, ''),
                            CASE
                                WHEN task_id IS NULL OR task_id = '' THEN 'Not started'
                                ELSE status
                            END
                        ),
                        provider_task_status = COALESCE(
                            NULLIF(provider_task_status, ''),
                            NULLIF(provider_status, ''),
                            CASE
                                WHEN task_id IS NULL OR task_id = '' THEN 'Not started'
                                ELSE status
                            END
                        ),
                        provider_progress_source = COALESCE(
                            NULLIF(provider_progress_source, ''),
                            'legacy local state'
                        ),
                        status_changed_at = COALESCE(status_changed_at, updated_at),
                        queue_position = COALESCE(queue_position, id::integer)
                    WHERE
                        logical_job_id IS NULL OR logical_job_id = ''
                        OR job_uuid IS NULL OR job_uuid = ''
                        OR ui_status IS NULL OR ui_status = ''
                        OR provider_status IS NULL OR provider_status = ''
                        OR provider_task_status IS NULL OR provider_task_status = ''
                        OR provider_progress_source IS NULL OR provider_progress_source = ''
                        OR status_changed_at IS NULL
                        OR queue_position IS NULL
                        OR (
                            (launch_report_id IS NULL OR launch_report_id = '')
                            AND report_id IS NOT NULL
                            AND report_id <> ''
                        );
                    """
                )
                cur.execute(
                    """
                    ALTER TABLE securescope_openvas_jobs
                        ALTER COLUMN logical_job_id SET NOT NULL,
                        ALTER COLUMN job_uuid SET NOT NULL;
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_openvas_job_events (
                        id BIGSERIAL PRIMARY KEY,
                        job_id BIGINT NOT NULL
                            REFERENCES securescope_openvas_jobs(id) ON DELETE CASCADE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        batch_id BIGINT NOT NULL
                            REFERENCES securescope_openvas_batches(id) ON DELETE CASCADE,
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
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_openvas_worker_state (
                        worker_name TEXT PRIMARY KEY,
                        pid INTEGER,
                        hostname TEXT,
                        status TEXT NOT NULL,
                        message TEXT,
                        heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )

                indexes = [
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_securescope_openvas_jobs_task_id
                    ON securescope_openvas_jobs(task_id)
                    WHERE task_id IS NOT NULL AND task_id <> '';
                    """,
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_securescope_openvas_jobs_report_id
                    ON securescope_openvas_jobs(report_id)
                    WHERE report_id IS NOT NULL AND report_id <> '';
                    """,
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_securescope_openvas_jobs_job_uuid
                    ON securescope_openvas_jobs(job_uuid);
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_securescope_openvas_batches_client_created
                    ON securescope_openvas_batches(client_id, created_at DESC);
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS idx_securescope_openvas_jobs_status
                    ON securescope_openvas_jobs(status, finalization_status);
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS idx_openvas_jobs_logical_attempt
                    ON securescope_openvas_jobs(logical_job_id, attempt_number DESC);
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS idx_openvas_jobs_pending_action
                    ON securescope_openvas_jobs(action_requested, action_requested_at)
                    WHERE action_requested IS NOT NULL;
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS idx_openvas_jobs_queue
                    ON securescope_openvas_jobs(status, queue_position, created_at)
                    WHERE status = 'Queued';
                    """,
                    """
                    CREATE INDEX IF NOT EXISTS idx_openvas_job_events_job_created
                    ON securescope_openvas_job_events(job_id, created_at DESC);
                    """,
                ]
                for statement in indexes:
                    cur.execute(statement)

        _INITIALIZED = True


def create_openvas_batch(
    client_name: str,
    *,
    label: str,
    scan_mode: str,
    profile_name: str,
    port_list_name: str,
    sync_to_ciso: bool,
    status: str = "Submitting",
    dispatch_enabled: bool = False,
) -> dict[str, Any]:
    """Create one workspace-scoped OpenVAS batch."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                INSERT INTO securescope_openvas_batches (
                    batch_uuid, client_id, label, scan_mode,
                    profile_name, port_list_name, status,
                    sync_to_ciso, dispatch_enabled, dispatch_requested_at,
                    started_at, updated_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    CASE WHEN %s THEN NOW() ELSE NULL END,
                    NOW(), NOW()
                )
                RETURNING *;
                """,
                (
                    str(uuid.uuid4()),
                    client_id,
                    label,
                    scan_mode,
                    profile_name,
                    port_list_name,
                    status,
                    bool(sync_to_ciso),
                    bool(dispatch_enabled),
                    bool(dispatch_enabled),
                ),
            )
            return dict(cur.fetchone())


def activate_openvas_batch_dispatch(
    batch_id: int,
    *,
    exclusive: bool = True,
    note: str = "Explicit SecureScope batch launch",
) -> dict[str, Any] | None:
    """Allow only the explicitly launched batch to create/start more tasks.

    Historical queued batches remain stored for audit but cannot silently
    create additional Greenbone tasks. Existing running tasks are not stopped.
    """
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if exclusive:
                cur.execute(
                    """
                    UPDATE securescope_openvas_batches
                    SET
                        dispatch_enabled = FALSE,
                        dispatch_completed_at = COALESCE(
                            dispatch_completed_at, NOW()
                        ),
                        dispatch_note = CASE
                            WHEN id = %s THEN dispatch_note
                            ELSE 'Automatic dispatch superseded by a newer explicit batch'
                        END,
                        updated_at = NOW()
                    WHERE dispatch_enabled = TRUE
                      AND id <> %s;
                    """,
                    (int(batch_id), int(batch_id)),
                )
            cur.execute(
                """
                UPDATE securescope_openvas_batches
                SET
                    dispatch_enabled = TRUE,
                    dispatch_requested_at = NOW(),
                    dispatch_completed_at = NULL,
                    dispatch_note = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *;
                """,
                (str(note or "Explicit SecureScope batch launch"), int(batch_id)),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def complete_openvas_batch_dispatch(
    batch_id: int,
    *,
    note: str = "All tasks in this batch received a start decision",
) -> dict[str, Any] | None:
    """Disable automatic dispatch after the exact batch is fully submitted."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE securescope_openvas_batches
                SET
                    dispatch_enabled = FALSE,
                    dispatch_completed_at = NOW(),
                    dispatch_note = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *;
                """,
                (str(note), int(batch_id)),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def count_pending_openvas_dispatch_jobs(batch_id: int) -> int:
    """Count jobs that still need create_task/start_task for one batch."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM securescope_openvas_jobs
                WHERE batch_id = %s
                  AND is_current_attempt = TRUE
                  AND COALESCE(provider_status, '') <> 'Missing'
                  AND (
                        (
                            status = 'Queued'
                            AND (task_id IS NULL OR task_id = '')
                        )
                        OR (
                            task_id IS NOT NULL
                            AND task_id <> ''
                            AND status IN ('Queued', 'Submission failed')
                            AND COALESCE(provider_status, '') IN (
                                '', 'Not started', 'New', 'Created',
                                'Provider retry', 'Start retry pending',
                                'Start confirmation pending', 'Start failed'
                            )
                        )
                  );
                """,
                (int(batch_id),),
            )
            row = cur.fetchone()
            return int(row[0] if row else 0)


def get_latest_dispatchable_openvas_batch_id() -> int | None:
    """Return only an explicitly activated batch with pending dispatch work."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT b.id
                FROM securescope_openvas_batches b
                WHERE b.dispatch_enabled = TRUE
                  AND b.status NOT IN ('Cancelled', 'Failed', 'Completed', 'Completed with errors')
                  AND EXISTS (
                        SELECT 1
                        FROM securescope_openvas_jobs j
                        WHERE j.batch_id = b.id
                          AND j.is_current_attempt = TRUE
                          AND COALESCE(j.provider_status, '') <> 'Missing'
                          AND (
                                (j.status = 'Queued' AND (j.task_id IS NULL OR j.task_id = ''))
                                OR (
                                    j.task_id IS NOT NULL
                                    AND j.task_id <> ''
                                    AND j.status IN ('Queued', 'Submission failed')
                                    AND COALESCE(j.provider_status, '') IN (
                                        '', 'Not started', 'New', 'Created',
                                        'Provider retry', 'Start retry pending',
                                        'Start confirmation pending', 'Start failed'
                                    )
                                )
                          )
                  )
                ORDER BY b.dispatch_requested_at DESC NULLS LAST, b.id DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            return int(row[0]) if row else None


_ALLOWED_JOB_FIELDS = {
    "target_id",
    "task_id",
    "report_id",
    "scanner_id",
    "status",
    "provider_status",
    "provider_task_status",
    "provider_report_status",
    "provider_progress_source",
    "provider_scan_start",
    "provider_scan_end",
    "ui_status",
    "stage",
    "progress",
    "queue_position",
    "result_message",
    "error",
    "findings_count",
    "critical_count",
    "high_count",
    "medium_count",
    "pdf_path",
    "ciso_status",
    "ciso_payload",
    "sync_to_ciso",
    "finalization_status",
    "finalization_attempts",
    "logical_job_id",
    "attempt_number",
    "retry_of_job_id",
    "retry_reason",
    "is_current_attempt",
    "launch_report_id",
    "submission_attempts",
    "action_requested",
    "action_reason",
    "action_requested_at",
    "action_completed_at",
    "submitted_at",
    "started_at",
    "last_synced_at",
    "last_provider_sync_at",
    "status_changed_at",
    "completed_at",
    "asset_payload",
    "asset_tag",
}


def create_or_update_openvas_job(
    client_name: str,
    *,
    batch_id: int,
    asset: dict[str, Any],
    target_id: str = "",
    task_id: str = "",
    report_id: str = "",
    scanner_id: str = "",
    status: str = "Queued",
    provider_status: str = "Not started",
    ui_status: str = "Queued",
    stage: str = "Waiting for SecureScope scan slot",
    progress: int = 0,
    queue_position: int | None = None,
    result_message: str = "",
    error: str = "",
    sync_to_ciso: bool = True,
    logical_job_id: str = "",
    attempt_number: int = 1,
    retry_of_job_id: int | None = None,
    retry_reason: str = "",
    is_current_attempt: bool = True,
    job_uuid: str = "",
    launch_report_id: str = "",
    submission_attempts: int = 0,
) -> dict[str, Any]:
    """Create or update one exact scan attempt within a workspace batch."""
    init_openvas_tables()
    payload = dict(asset)
    asset_ip = str(payload.get("ip") or "").strip()
    if not asset_ip:
        raise ValueError("OpenVAS job asset requires an IP address.")

    normalized_status = str(status or ui_status or "Queued")
    normalized_ui = str(ui_status or normalized_status)
    normalized_provider = str(provider_status or "Not started")
    logical_id = str(logical_job_id or "").strip() or str(uuid.uuid4())
    immutable_job_uuid = str(job_uuid or "").strip() or str(uuid.uuid4())
    immutable_launch_report = str(launch_report_id or report_id or "").strip()

    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                (
                    "\n                INSERT INTO securescope_openvas_jobs (\n    "
                    "                batch_id, client_id, asset_ip, asset_tag, "
                    "asset_payload,\n                    target_id, task_id, "
                    "report_id, scanner_id,\n                    status, "
                    "provider_status, ui_status, stage, progress,\n               "
                    "     queue_position, result_message, error, sync_to_ciso,\n  "
                    "                  logical_job_id, attempt_number, "
                    "retry_of_job_id,\n                    retry_reason, "
                    "is_current_attempt, job_uuid,\n                    "
                    "launch_report_id, submission_attempts,\n                    "
                    "submitted_at, last_synced_at, status_changed_at, "
                    "updated_at\n                ) VALUES (\n                    "
                    "%s, %s, %s, %s, %s,\n                    NULLIF(%s, ''), "
                    "NULLIF(%s, ''), NULLIF(%s, ''), NULLIF(%s, ''),\n            "
                    "        %s, %s, %s, %s, %s,\n                    %s, %s, %s, "
                    "%s,\n                    %s, %s, %s,\n                    %s, "
                    "%s, %s,\n                    NULLIF(%s, ''), %s,\n            "
                    "        NULL, NOW(), NOW(), NOW()\n                )\n        "
                    "        ON CONFLICT (batch_id, asset_ip)\n                DO "
                    "UPDATE SET\n                    asset_tag = "
                    "EXCLUDED.asset_tag,\n                    asset_payload = "
                    "EXCLUDED.asset_payload,\n                    target_id = "
                    "COALESCE(EXCLUDED.target_id, "
                    "securescope_openvas_jobs.target_id),\n                    "
                    "task_id = COALESCE(EXCLUDED.task_id, "
                    "securescope_openvas_jobs.task_id),\n                    "
                    "report_id = COALESCE(EXCLUDED.report_id, "
                    "securescope_openvas_jobs.report_id),\n                    "
                    "scanner_id = COALESCE(EXCLUDED.scanner_id, "
                    "securescope_openvas_jobs.scanner_id),\n                    "
                    "status = EXCLUDED.status,\n                    "
                    "provider_status = EXCLUDED.provider_status,\n                "
                    "    ui_status = EXCLUDED.ui_status,\n                    "
                    "stage = EXCLUDED.stage,\n                    progress = "
                    "EXCLUDED.progress,\n                    queue_position = "
                    "COALESCE(EXCLUDED.queue_position, "
                    "securescope_openvas_jobs.queue_position),\n                  "
                    "  result_message = EXCLUDED.result_message,\n                "
                    "    error = EXCLUDED.error,\n                    "
                    "sync_to_ciso = EXCLUDED.sync_to_ciso,\n                    "
                    "logical_job_id = EXCLUDED.logical_job_id,\n                  "
                    "  attempt_number = EXCLUDED.attempt_number,\n                "
                    "    retry_of_job_id = EXCLUDED.retry_of_job_id,\n            "
                    "        retry_reason = EXCLUDED.retry_reason,\n              "
                    "      is_current_attempt = EXCLUDED.is_current_attempt,\n    "
                    "                job_uuid = "
                    "securescope_openvas_jobs.job_uuid,\n                    "
                    "launch_report_id = COALESCE(\n                        "
                    "securescope_openvas_jobs.launch_report_id,\n                 "
                    "       EXCLUDED.launch_report_id\n                    ),\n    "
                    "                submission_attempts = "
                    "EXCLUDED.submission_attempts,\n                    "
                    "status_changed_at = CASE\n                        WHEN "
                    "securescope_openvas_jobs.status IS DISTINCT FROM "
                    "EXCLUDED.status\n                        THEN NOW()\n         "
                    "               ELSE securescope_openvas_jobs.status_changed_"
                    "at\n                    END,\n                    "
                    "last_synced_at = NOW(),\n                    updated_at = "
                    "NOW()\n                RETURNING *;\n                "
                ),
                (
                    int(batch_id),
                    client_id,
                    asset_ip,
                    str(payload.get("asset_tag") or ""),
                    Json(payload),
                    target_id,
                    task_id,
                    report_id,
                    scanner_id,
                    normalized_status,
                    normalized_provider,
                    normalized_ui,
                    stage,
                    max(0, min(100, int(progress or 0))),
                    queue_position,
                    result_message,
                    error,
                    bool(sync_to_ciso),
                    logical_id,
                    max(1, int(attempt_number or 1)),
                    retry_of_job_id,
                    retry_reason,
                    bool(is_current_attempt),
                    immutable_job_uuid,
                    immutable_launch_report,
                    max(0, int(submission_attempts or 0)),
                ),
            )
            row = dict(cur.fetchone())

    record_openvas_job_event(
        int(row["id"]),
        "job_saved",
        provider_status=normalized_provider,
        ui_status=normalized_ui,
        stage=stage,
        progress=max(0, min(100, int(progress or 0))),
        message=result_message,
        error=error,
    )
    return row


def _prepare_update_fields(fields: dict[str, Any]) -> tuple[list[str], list[Any]]:
    """Build safe SQL assignments for an OpenVAS job update."""
    clean = {key: value for key, value in fields.items() if key in _ALLOWED_JOB_FIELDS}
    assignments: list[str] = []
    params: list[Any] = []
    for key, value in clean.items():
        assignments.append(f"{key} = %s")
        if key in {"ciso_payload", "asset_payload"} and value is not None:
            params.append(Json(value))
        else:
            params.append(value)
    if "status" in clean:
        assignments.append(
            "status_changed_at = CASE WHEN status IS DISTINCT FROM %s "
            "THEN NOW() ELSE status_changed_at END"
        )
        params.append(clean["status"])
    assignments.extend(["last_synced_at = NOW()", "updated_at = NOW()"])
    return assignments, params


def update_openvas_job(task_id: str, **fields: Any) -> dict[str, Any] | None:
    """Update one job by exact Greenbone task ID."""
    if not task_id:
        return None
    assignments, params = _prepare_update_fields(fields)
    if not assignments:
        return get_openvas_job_by_task(task_id)
    params.append(task_id)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                UPDATE securescope_openvas_jobs
                SET {', '.join(assignments)}
                WHERE task_id = %s
                RETURNING *;
                """,
                tuple(params),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def update_openvas_job_by_id(job_id: int, **fields: Any) -> dict[str, Any] | None:
    """Update one job by database identifier."""
    assignments, params = _prepare_update_fields(fields)
    if not assignments:
        return get_openvas_job_by_id(job_id)
    params.append(int(job_id))
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                UPDATE securescope_openvas_jobs
                SET {', '.join(assignments)}
                WHERE id = %s
                RETURNING *;
                """,
                tuple(params),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def get_openvas_job_by_task(task_id: str) -> dict[str, Any] | None:
    """Load one job and workspace metadata by exact task ID."""
    if not task_id:
        return None
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       b.profile_name, b.port_list_name,
                       b.status AS batch_status, c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.task_id = %s;
                """,
                (task_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def get_openvas_job_by_id(job_id: int) -> dict[str, Any] | None:
    """Load one job and workspace metadata by database identifier."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       b.profile_name, b.port_list_name,
                       b.status AS batch_status, c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.id = %s;
                """,
                (int(job_id),),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def openvas_task_exists(task_id: str) -> bool:
    """Return whether a task ID is already tracked in PostgreSQL."""
    return bool(task_id and get_openvas_job_by_task(task_id))


def get_openvas_batch(batch_id: int) -> dict[str, Any] | None:
    """Load one batch with its workspace name."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT b.*, c.name AS client_name
                FROM securescope_openvas_batches b
                JOIN securescope_clients c ON c.id = b.client_id
                WHERE b.id = %s;
                """,
                (int(batch_id),),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def load_openvas_batch_jobs(batch_id: int) -> list[dict[str, Any]]:
    """Load every job belonging to one exact batch."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.batch_id = %s
                ORDER BY j.queue_position NULLS LAST, j.id;
                """,
                (int(batch_id),),
            )
            return [dict(row) for row in cur.fetchall()]


def list_openvas_batches(client_name: str, *, limit: int = 30) -> list[dict[str, Any]]:
    """List recent OpenVAS batches for one client workspace only."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT b.*, c.name AS client_name
                FROM securescope_openvas_batches b
                JOIN securescope_clients c ON c.id = b.client_id
                WHERE b.client_id = %s
                ORDER BY b.created_at DESC, b.id DESC
                LIMIT %s;
                """,
                (client_id, max(1, int(limit))),
            )
            return [dict(row) for row in cur.fetchall()]


def get_active_openvas_batch(client_name: str) -> dict[str, Any] | None:
    """Return the latest unfinished batch for one workspace."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT b.*, c.name AS client_name
                FROM securescope_openvas_batches b
                JOIN securescope_clients c ON c.id = b.client_id
                WHERE b.client_id = %s
                  AND b.status NOT IN (
                      'Completed', 'Completed with errors', 'Failed', 'Cancelled'
                  )
                ORDER BY b.created_at DESC, b.id DESC
                LIMIT 1;
                """,
                (client_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def record_openvas_job_event(
    job_id: int,
    event_type: str,
    *,
    provider_status: str = "",
    ui_status: str = "",
    stage: str = "",
    progress: int | None = None,
    message: str = "",
    error: str = "",
) -> None:
    """Append one immutable event to a workspace-scoped job timeline."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO securescope_openvas_job_events (
                    job_id, client_id, batch_id, event_type,
                    provider_status, ui_status, stage, progress, message, error
                )
                SELECT j.id, j.client_id, j.batch_id, %s,
                       NULLIF(%s, ''), NULLIF(%s, ''), NULLIF(%s, ''),
                       %s, NULLIF(%s, ''), NULLIF(%s, '')
                FROM securescope_openvas_jobs j
                WHERE j.id = %s;
                """,
                (
                    event_type,
                    provider_status,
                    ui_status,
                    stage,
                    progress,
                    message,
                    error,
                    int(job_id),
                ),
            )


def list_openvas_job_events(
    job_id: int,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Load timeline events for one job."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM securescope_openvas_job_events
                WHERE job_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s;
                """,
                (int(job_id), max(1, int(limit))),
            )
            return [dict(row) for row in cur.fetchall()]


def _active_slot_sql() -> str:
    """Return SQL that counts only genuinely active scanner reservations."""
    return """
        status IN ('Creating', 'Starting')
        OR (
            task_id IS NOT NULL
            AND task_id <> ''
            AND (
                COALESCE(provider_status, '') IN (
                    'Requested', 'Queued', 'Running', 'Processing',
                    'Stop Requested', 'Resume Requested'
                )
                OR status IN (
                    'Waiting for scanner', 'Running', 'Processing results',
                    'Stop requested', 'Resume requested'
                )
            )
        )
    """


def count_active_openvas_scans(
    *,
    batch_id: int | None = None,
    exclude_batch_id: int | None = None,
    fresh_seconds: int | None = None,
) -> int:
    """Count scanner reservations with optional batch and freshness filters.

    A historical PostgreSQL row must not reserve scanner capacity forever.
    Callers that pass ``fresh_seconds`` count only jobs whose provider state
    was synchronized recently. The selected batch can still be counted without
    this filter so its already-started tasks remain part of the batch limit.
    """
    init_openvas_tables()
    clauses = [f"({_active_slot_sql()})"]
    params: list[Any] = []
    if batch_id is not None:
        clauses.append("batch_id = %s")
        params.append(int(batch_id))
    if exclude_batch_id is not None:
        clauses.append("batch_id <> %s")
        params.append(int(exclude_batch_id))
    if fresh_seconds is not None:
        clauses.append(
            "COALESCE(last_provider_sync_at, status_changed_at, updated_at, created_at) "
            ">= NOW() - (%s * INTERVAL '1 second')"
        )
        params.append(max(30, int(fresh_seconds)))

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT COUNT(*)
                FROM securescope_openvas_jobs
                WHERE {' AND '.join(clauses)};
                """,
                tuple(params),
            )
            row = cur.fetchone()
            return int(row[0] if row else 0)


def get_latest_prepared_openvas_batch_id() -> int | None:
    """Return the newest batch that still owns a prepared task in status New.

    The dedicated starter uses this to continue the latest visible batch after
    the SSH tunnel reconnects, instead of spending cycles on old orphan rows.
    """
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT j.batch_id
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                WHERE j.status = 'Queued'
                  AND j.task_id IS NOT NULL
                  AND j.task_id <> ''
                  AND COALESCE(j.provider_status, '') IN (
                      'New', 'Created', 'Provider retry',
                      'Start retry pending', 'Start failed'
                  )
                  AND b.status NOT IN (
                      'Cancelled', 'Failed', 'Completed',
                      'Completed with errors'
                  )
                  AND b.dispatch_requested_at IS NOT NULL
                  AND b.dispatch_requested_at >= NOW() - INTERVAL '24 hours'
                ORDER BY b.dispatch_requested_at DESC NULLS LAST,
                         b.created_at DESC, j.created_at DESC, j.id DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            return int(row[0]) if row else None


def get_openvas_queue_snapshot(
    batch_id: int,
    *,
    active_stale_seconds: int = 180,
) -> dict[str, int]:
    """Return current scanner pressure without exposing another workspace's data.

    Args:
        batch_id: Selected workspace batch.

    Returns:
        Counts for global active/queued work, activity in the selected batch,
        and queued jobs that are older than the selected batch's first queued
        job. Only counts are returned so one workspace cannot see another
        workspace's asset identifiers.
    """
    init_openvas_tables()
    freshness = max(30, int(active_stale_seconds))
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) FILTER (
                        WHERE ({_active_slot_sql()})
                          AND COALESCE(
                                last_provider_sync_at, status_changed_at,
                                updated_at, created_at
                              ) >= NOW() - (%s * INTERVAL '1 second')
                    ) AS global_active,
                    COUNT(*) FILTER (
                        WHERE status = 'Queued'
                          AND COALESCE(provider_status, '') <> 'Missing'
                    ) AS global_queued,
                    COUNT(*) FILTER (
                        WHERE batch_id = %s AND ({_active_slot_sql()})
                    ) AS batch_active,
                    COUNT(*) FILTER (
                        WHERE batch_id = %s
                          AND status = 'Queued'
                          AND COALESCE(provider_status, '') <> 'Missing'
                    ) AS batch_queued
                FROM securescope_openvas_jobs;
                """,
                (freshness, int(batch_id), int(batch_id)),
            )
            counts = dict(cur.fetchone() or {})

            cur.execute(
                """
                WITH first_selected AS (
                    SELECT MIN(created_at) AS created_at
                    FROM securescope_openvas_jobs
                    WHERE batch_id = %s AND status = 'Queued'
                )
                SELECT COUNT(*) AS queued_ahead
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                CROSS JOIN first_selected f
                WHERE j.status = 'Queued'
                  AND COALESCE(j.provider_status, '') <> 'Missing'
                  AND b.status NOT IN ('Cancelled', 'Failed')
                  AND f.created_at IS NOT NULL
                  AND j.batch_id <> %s
                  AND j.created_at < f.created_at;
                """,
                (int(batch_id), int(batch_id)),
            )
            ahead = cur.fetchone()

    return {
        "global_active": int(counts.get("global_active") or 0),
        "global_queued": int(counts.get("global_queued") or 0),
        "batch_active": int(counts.get("batch_active") or 0),
        "batch_queued": int(counts.get("batch_queued") or 0),
        "queued_ahead": int((ahead or {}).get("queued_ahead") or 0),
    }


def requeue_stale_openvas_submissions(
    *,
    stale_seconds: int = 45,
    batch_id: int | None = None,
) -> int:
    """Return taskless jobs abandoned during creation to the local queue."""
    init_openvas_tables()
    params: list[Any] = [max(15, int(stale_seconds))]
    batch_clause = ""
    if batch_id is not None:
        batch_clause = "AND batch_id = %s"
        params.append(int(batch_id))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE securescope_openvas_jobs
                SET
                    status = 'Queued',
                    ui_status = 'Queued',
                    provider_status = 'Not started',
                    stage = 'Recovered stale queue claim',
                    result_message = (
                        'Previous worker stopped before task creation; '
                        'job returned to queue.'
                    ),
                    status_changed_at = NOW(),
                    updated_at = NOW()
                WHERE (task_id IS NULL OR task_id = '')
                  AND status IN ('Creating', 'Starting', 'Waiting for scanner')
                  AND updated_at < NOW() - (%s * INTERVAL '1 second')
                  {batch_clause};
                """,
                tuple(params),
            )
            return int(cur.rowcount or 0)


def requeue_ambiguous_openvas_start_failures(
    *,
    batch_id: int | None = None,
) -> list[dict[str, Any]]:
    """Requeue task-bearing starts that failed only because transport timed out.

    These rows already own an exact Greenbone task UUID. Requeueing them causes
    SecureScope to inspect that same task before retrying start_task, so no
    duplicate target or task is created.
    """
    init_openvas_tables()
    params: list[Any] = []
    batch_clause = ""
    if batch_id is not None:
        batch_clause = "AND batch_id = %s"
        params.append(int(batch_id))

    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                UPDATE securescope_openvas_jobs
                SET
                    status = 'Queued',
                    ui_status = 'Queued',
                    provider_status = 'Start confirmation pending',
                    stage = 'Retrying preserved task after transport timeout',
                    result_message = (
                        'The previous start_task response timed out. The exact '
                        'task UUID will be verified before retrying.'
                    ),
                    error = '',
                    completed_at = NULL,
                    status_changed_at = NOW(),
                    updated_at = NOW()
                WHERE status = 'Submission failed'
                  AND task_id IS NOT NULL
                  AND task_id <> ''
                  AND COALESCE(provider_status, '') <> 'Missing'
                  AND COALESCE(error, '') NOT ILIKE '%%failed to find task%%'
                  AND COALESCE(error, '') NOT ILIKE '%%response error 404%%'
                  AND (
                      COALESCE(error, '') ILIKE '%%timed out%%'
                      OR COALESCE(error, '') ILIKE '%%TimeoutError%%'
                      OR COALESCE(error, '') ILIKE '%%connection reset%%'
                      OR COALESCE(error, '') ILIKE '%%forcibly closed%%'
                  )
                  {batch_clause}
                RETURNING *;
                """,
                tuple(params),
            )
            return [dict(row) for row in cur.fetchall()]


def claim_next_queued_openvas_job(
    *,
    max_concurrent_scans: int = 1,
    active_stale_seconds: int = 180,
    batch_id: int | None = None,
) -> dict[str, Any] | None:
    """Atomically reserve one scanner slot and claim the newest prepared job.

    Only recently synchronized reservations count against the slot limit. This
    prevents deleted historical tasks from blocking a new batch forever.
    """
    init_openvas_tables()
    limit = max(1, int(max_concurrent_scans))
    freshness = max(30, int(active_stale_seconds))
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_try_advisory_xact_lock(%s) AS locked;",
                (74109017,),
            )
            lock_row = cur.fetchone()
            if not lock_row or not bool(lock_row["locked"]):
                return None

            cur.execute(
                f"""
                SELECT COUNT(*) AS active_count
                FROM securescope_openvas_jobs
                WHERE ({_active_slot_sql()})
                  AND COALESCE(
                        last_provider_sync_at, status_changed_at, updated_at, created_at
                      ) >= NOW() - (%s * INTERVAL '1 second');
                """,
                (freshness,),
            )
            active_row = cur.fetchone()
            if int(active_row["active_count"] if active_row else 0) >= limit:
                return None

            batch_clause = ""
            select_params: list[Any] = []
            if batch_id is not None:
                batch_clause = "AND j.batch_id = %s"
                select_params.append(int(batch_id))

            cur.execute(
                f"""
                SELECT j.id
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                WHERE j.status = 'Queued'
                  AND COALESCE(j.provider_status, '') <> 'Missing'
                  AND (
                      COALESCE(j.provider_status, '') NOT IN (
                          'Provider retry', 'Start retry pending'
                      )
                      OR j.updated_at <= NOW() - (15 * INTERVAL '1 second')
                  )
                  AND b.status NOT IN ('Cancelled', 'Failed')
                  AND b.dispatch_enabled = TRUE
                  {batch_clause}
                ORDER BY
                    CASE
                        WHEN j.task_id IS NOT NULL AND j.task_id <> '' THEN 0
                        ELSE 1
                    END,
                    b.created_at DESC,
                    j.created_at DESC,
                    j.queue_position NULLS LAST,
                    j.id DESC
                FOR UPDATE SKIP LOCKED
                LIMIT 1;
                """,
                tuple(select_params),
            )
            selected = cur.fetchone()
            if not selected:
                return None

            job_id = int(selected["id"])
            cur.execute(
                """
                UPDATE securescope_openvas_jobs
                SET
                    status = 'Creating',
                    ui_status = 'Creating',
                    provider_status = CASE
                        WHEN task_id IS NOT NULL AND task_id <> ''
                            THEN COALESCE(NULLIF(provider_status, ''), 'New')
                        ELSE 'Not started'
                    END,
                    stage = CASE
                        WHEN task_id IS NOT NULL AND task_id <> ''
                            THEN 'Starting pre-created Greenbone task'
                        ELSE 'Preparing OpenVAS task'
                    END,
                    submission_attempts = submission_attempts + 1,
                    started_at = COALESCE(started_at, NOW()),
                    status_changed_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *;
                """,
                (job_id,),
            )
            return dict(cur.fetchone())


def list_queued_openvas_jobs(*, limit: int = 500) -> list[dict[str, Any]]:
    """List queued jobs globally while retaining workspace metadata."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       b.profile_name, b.port_list_name,
                       c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.status = 'Queued'
                ORDER BY j.created_at, j.queue_position NULLS LAST, j.id
                LIMIT %s;
                """,
                (max(1, int(limit)),),
            )
            return [dict(row) for row in cur.fetchall()]


def list_worker_jobs(
    *,
    limit: int = 250,
    max_finalization_attempts: int = 3,
    batch_id: int | None = None,
) -> list[dict[str, Any]]:
    """Load task-bearing jobs requiring provider reconciliation or actions.

    Recent batches are intentionally prioritized. Historical unfinished rows
    must not starve the current batch from live provider status and progress.
    """
    init_openvas_tables()
    batch_clause = ""
    params: list[Any] = [max(1, int(max_finalization_attempts))]
    if batch_id is not None:
        batch_clause = "AND j.batch_id = %s"
        params.append(int(batch_id))
    params.append(max(1, int(limit)))

    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       b.profile_name, b.port_list_name,
                       b.status AS batch_status,
                       c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.task_id IS NOT NULL
                  AND j.task_id <> ''
                  AND (
                      j.action_requested IS NOT NULL
                      OR j.status NOT IN (
                          'Completed', 'Recovered report', 'Done', 'Failed',
                          'Stopped', 'Interrupted',
                          'Submission blocked', 'Abandoned', 'Cancelled'
                      )
                      OR (
                          j.status = 'Done'
                          AND j.finalization_status <> 'complete'
                          AND j.finalization_attempts < %s
                      )
                  )
                  {batch_clause}
                ORDER BY
                    CASE
                        WHEN j.action_requested IS NOT NULL THEN 0
                        WHEN j.status IN (
                            'Starting', 'Waiting for scanner', 'Running',
                            'Processing results', 'Finalizing', 'Queued',
                            'Stop requested', 'Resume requested'
                        ) THEN 1
                        WHEN j.status = 'Done' THEN 2
                        ELSE 3
                    END,
                    b.created_at DESC,
                    j.created_at DESC,
                    COALESCE(j.last_provider_sync_at, j.updated_at) ASC,
                    j.id DESC
                LIMIT %s;
                """,
                tuple(params),
            )
            return [dict(row) for row in cur.fetchall()]


def update_batch_counters(batch_id: int) -> dict[str, Any] | None:
    """Recalculate one batch summary from its exact job rows."""
    jobs = load_openvas_batch_jobs(batch_id)
    completed = sum(
        1 for job in jobs if str(job.get("status") or "") in {"Completed", "Recovered report"}
    )
    failed = sum(
        1
        for job in jobs
        if str(job.get("status") or "") in TERMINAL_JOB_STATUSES
        and str(job.get("status") or "") not in {"Completed", "Recovered report"}
    )
    active = len(jobs) - completed - failed

    if not jobs:
        status = "Failed"
        completed_at: str | None = utc_now()
    elif active > 0:
        status = (
            "Queued" if all(str(job.get("status") or "") == "Queued" for job in jobs) else "Running"
        )
        completed_at = None
    else:
        status = "Completed" if failed == 0 else "Completed with errors"
        completed_at = utc_now()

    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE securescope_openvas_batches
                SET
                    submitted_count = %s,
                    completed_count = %s,
                    failed_count = %s,
                    status = %s,
                    completed_at = CASE
                        WHEN %s IS NULL THEN completed_at
                        ELSE %s::timestamptz
                    END,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *;
                """,
                (
                    len(jobs),
                    completed,
                    failed,
                    status,
                    completed_at,
                    completed_at,
                    int(batch_id),
                ),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def list_openvas_attempts(logical_job_id: str) -> list[dict[str, Any]]:
    """List every attempt for one logical asset scan."""
    if not logical_job_id:
        return []
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.logical_job_id = %s
                ORDER BY j.attempt_number DESC, j.id DESC;
                """,
                (logical_job_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def get_active_openvas_attempt(
    logical_job_id: str,
    *,
    exclude_job_id: int | None = None,
) -> dict[str, Any] | None:
    """Return another current nonterminal attempt for a logical scan."""
    if not logical_job_id:
        return None
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            params: list[Any] = [logical_job_id, list(TERMINAL_JOB_STATUSES)]
            exclude_sql = ""
            if exclude_job_id is not None:
                exclude_sql = "AND j.id <> %s"
                params.append(int(exclude_job_id))
            cur.execute(
                f"""
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.logical_job_id = %s
                  AND j.is_current_attempt = TRUE
                  AND NOT (j.status = ANY(%s))
                  {exclude_sql}
                ORDER BY j.attempt_number DESC, j.id DESC
                LIMIT 1;
                """,
                tuple(params),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def set_current_openvas_attempt(logical_job_id: str, job_id: int) -> None:
    """Mark exactly one attempt as current for a logical scan."""
    if not logical_job_id:
        return
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE securescope_openvas_jobs
                SET is_current_attempt = (id = %s), updated_at = NOW()
                WHERE logical_job_id = %s;
                """,
                (int(job_id), logical_job_id),
            )


def list_retryable_openvas_jobs(client_name: str) -> list[dict[str, Any]]:
    """List retryable attempts for one workspace."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT j.*, b.batch_uuid, b.label AS batch_label,
                       c.name AS client_name
                FROM securescope_openvas_jobs j
                JOIN securescope_openvas_batches b ON b.id = j.batch_id
                JOIN securescope_clients c ON c.id = j.client_id
                WHERE j.client_id = %s
                  AND j.status IN (
                      'Failed', 'Stopped', 'Interrupted',
                      'Submission failed', 'Submission blocked',
                      'Abandoned', 'Cancelled'
                  )
                ORDER BY j.updated_at DESC, j.id DESC;
                """,
                (client_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def request_openvas_job_action(
    job_id: int,
    action: str,
    reason: str = "",
) -> dict[str, Any]:
    """Queue an analyst action for the background worker."""
    normalized = str(action or "").strip().lower()
    if normalized not in {"refresh", "stop", "resume", "recover"}:
        raise ValueError(f"Unsupported OpenVAS action: {action}")
    row = update_openvas_job_by_id(
        int(job_id),
        action_requested=normalized,
        action_reason=reason.strip(),
        action_requested_at=utc_now(),
        action_completed_at=None,
    )
    if not row:
        raise RuntimeError("OpenVAS job was not found.")
    record_openvas_job_event(
        int(job_id),
        "action_requested",
        provider_status=str(row.get("provider_status") or ""),
        ui_status=str(row.get("ui_status") or row.get("status") or ""),
        stage=str(row.get("stage") or ""),
        progress=int(row.get("progress") or 0),
        message=f"Action queued: {normalized}. {reason}".strip(),
    )
    return row


def complete_openvas_job_action(
    job_id: int,
    *,
    error: str = "",
) -> dict[str, Any] | None:
    """Clear a queued action after worker processing."""
    current = get_openvas_job_by_id(job_id)
    if not current:
        return None
    action = str(current.get("action_requested") or "")
    row = update_openvas_job_by_id(
        int(job_id),
        action_requested=None,
        action_reason=None,
        action_completed_at=utc_now(),
        error=error or str(current.get("error") or ""),
    )
    if row:
        record_openvas_job_event(
            int(job_id),
            "action_failed" if error else "action_completed",
            provider_status=str(row.get("provider_status") or ""),
            ui_status=str(row.get("ui_status") or row.get("status") or ""),
            stage=str(row.get("stage") or ""),
            progress=int(row.get("progress") or 0),
            message=f"Action completed: {action}" if action else "Action completed.",
            error=error,
        )
    return row


def cancel_queued_openvas_job(
    job_id: int,
    *,
    reason: str = "",
) -> dict[str, Any]:
    """Cancel a local queued job before Greenbone task creation."""
    job = get_openvas_job_by_id(job_id)
    if not job:
        raise RuntimeError("OpenVAS job was not found.")
    if str(job.get("status") or "") != "Queued" or job.get("task_id"):
        raise ValueError("Only a queued job without a task ID can be cancelled.")
    row = update_openvas_job_by_id(
        int(job_id),
        status="Cancelled",
        ui_status="Cancelled",
        provider_status="Not started",
        stage="Cancelled before OpenVAS submission",
        result_message="The queued scan was cancelled before task creation.",
        error=reason.strip(),
        completed_at=utc_now(),
        finalization_status="complete",
        action_requested=None,
    )
    record_openvas_job_event(
        int(job_id),
        "queue_cancelled",
        provider_status="Not started",
        ui_status="Cancelled",
        stage="Cancelled before OpenVAS submission",
        message=reason.strip() or "Cancelled by analyst.",
    )
    update_batch_counters(int(job["batch_id"]))
    if not row:
        raise RuntimeError("Could not cancel the queued OpenVAS job.")
    return row


def abandon_openvas_job(job_id: int, *, reason: str = "") -> dict[str, Any]:
    """Mark a failed or interrupted attempt as intentionally abandoned."""
    job = get_openvas_job_by_id(job_id)
    if not job:
        raise RuntimeError("OpenVAS job was not found.")
    row = update_openvas_job_by_id(
        int(job_id),
        status="Abandoned",
        ui_status="Abandoned",
        stage="Attempt abandoned by analyst",
        result_message=reason.strip() or "Attempt abandoned by analyst.",
        completed_at=utc_now(),
        finalization_status="complete",
        action_requested=None,
    )
    record_openvas_job_event(
        int(job_id),
        "attempt_abandoned",
        provider_status=str(job.get("provider_status") or ""),
        ui_status="Abandoned",
        stage="Attempt abandoned by analyst",
        message=reason.strip() or "Attempt abandoned by analyst.",
    )
    update_batch_counters(int(job["batch_id"]))
    if not row:
        raise RuntimeError("Could not abandon the OpenVAS job.")
    return row


def update_worker_heartbeat(
    *,
    worker_name: str,
    pid: int,
    hostname: str,
    status: str,
    message: str = "",
) -> None:
    """Insert or refresh the background worker heartbeat."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO securescope_openvas_worker_state (
                    worker_name, pid, hostname, status, message,
                    heartbeat_at, started_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), NOW())
                ON CONFLICT (worker_name)
                DO UPDATE SET
                    pid = EXCLUDED.pid,
                    hostname = EXCLUDED.hostname,
                    status = EXCLUDED.status,
                    message = EXCLUDED.message,
                    heartbeat_at = NOW(),
                    updated_at = NOW();
                """,
                (worker_name, int(pid), hostname, status, message),
            )


def get_worker_state(worker_name: str = "openvas-monitor") -> dict[str, Any] | None:
    """Return one worker heartbeat and its age in seconds."""
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *,
                       GREATEST(
                           0,
                           FLOOR(EXTRACT(EPOCH FROM (NOW() - heartbeat_at)))
                       )::integer AS heartbeat_age_seconds
                FROM securescope_openvas_worker_state
                WHERE worker_name = %s;
                """,
                (worker_name,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def save_scan_record_direct(client_name: str, record: dict[str, Any]) -> None:
    """Upsert one completed report into the client scan history."""
    init_database(client_name)
    payload = dict(record)
    payload["client_name"] = client_name
    report_id = str(payload.get("report_id") or "").strip()
    if not report_id:
        raise ValueError("Completed scan record requires a report ID.")
    with connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                INSERT INTO securescope_scan_history (
                    client_id, report_id, asset_ip, scanned_at, payload
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (client_id, report_id)
                DO UPDATE SET
                    asset_ip = EXCLUDED.asset_ip,
                    scanned_at = EXCLUDED.scanned_at,
                    payload = EXCLUDED.payload,
                    updated_at = NOW();
                """,
                (
                    client_id,
                    report_id,
                    str(payload.get("asset_ip") or ""),
                    payload.get("scanned_at") or None,
                    Json(payload),
                ),
            )


def mark_asset_scanned_direct(
    client_name: str,
    asset_ip: str,
    scanned_at: str,
) -> None:
    """Update one workspace asset with its latest completed scan timestamp."""
    init_database(client_name)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT payload
                FROM securescope_assets
                WHERE client_id = %s AND ip = %s;
                """,
                (client_id, asset_ip),
            )
            row = cur.fetchone()
            if not row:
                return
            payload = dict(row["payload"] or {})
            payload["last_scan"] = scanned_at
            payload["last_scanned_at"] = scanned_at
            payload["last_openvas_scan"] = scanned_at
            cur.execute(
                """
                UPDATE securescope_assets
                SET payload = %s, updated_at = NOW()
                WHERE client_id = %s AND ip = %s;
                """,
                (Json(payload), client_id, asset_ip),
            )
