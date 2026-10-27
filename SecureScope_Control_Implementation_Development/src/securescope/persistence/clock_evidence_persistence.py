"""PostgreSQL persistence for Wazuh endpoint clock evidence."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Iterator

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import init_database

_INITIALIZED = False
_INIT_LOCK = threading.Lock()
_DDL_LOCK_KEY = 74109011


class ClockEvidenceDatabaseError(RuntimeError):
    """Raised when clock evidence cannot be stored or loaded."""


def _safe_timestamp(value: Any) -> str | None:
    """Return a PostgreSQL-safe timestamp or ``None``.

    Endpoint clocks are the subject of the assessment, so malformed or
    far-future endpoint timestamps must not break evidence persistence.  The
    original value remains available inside the JSON payload.
    """
    if value in {None, ""}:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        year = int(text[:4])
        if year < 1970 or year >= 2099:
            return None
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return text


def _database_url() -> str:
    url = os.getenv("SECURESCOPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise ClockEvidenceDatabaseError("Missing SECURESCOPE_DATABASE_URL or DATABASE_URL in .env")
    return url.strip()


@contextmanager
def _connect() -> Iterator[Any]:
    conn = None
    try:
        conn = psycopg2.connect(_database_url())
        yield conn
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        raise ClockEvidenceDatabaseError(str(exc)) from exc
    finally:
        if conn is not None:
            conn.close()


def init_clock_evidence_tables() -> None:
    """Create the clock-evidence table once with DDL locking."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    with _INIT_LOCK:
        if _INITIALIZED:
            return
        init_database()
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (_DDL_LOCK_KEY,))
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_clock_evidence (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        asset_ip TEXT,
                        asset_hostname TEXT,
                        wazuh_agent_id TEXT,
                        status TEXT NOT NULL,
                        source TEXT,
                        offset_ms DOUBLE PRECISION,
                        manager_agent_delta_ms DOUBLE PRECISION,
                        payload JSONB NOT NULL,
                        observed_at TIMESTAMPTZ,
                        collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_clock_evidence_client_asset
                    ON securescope_clock_evidence (
                        client_id,
                        asset_ip,
                        collected_at DESC
                    );
                    """
                )
        _INITIALIZED = True


def _client_id(cur: Any, client_name: str) -> int:
    name = (client_name or "Default Client").strip() or "Default Client"
    cur.execute(
        """
        INSERT INTO securescope_clients (name)
        VALUES (%s)
        ON CONFLICT (name) DO UPDATE SET updated_at = NOW()
        RETURNING id;
        """,
        (name,),
    )
    row = cur.fetchone()
    if not row:
        raise ClockEvidenceDatabaseError("Could not resolve client workspace.")
    return int(row[0])


def save_clock_evidence(
    client_name: str,
    rows: Iterable[dict[str, Any]],
) -> int:
    """Persist one collection cycle and return the number of rows saved."""
    values = [dict(row) for row in rows]
    if not values:
        return 0

    init_clock_evidence_tables()
    with _connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            for row in values:
                cur.execute(
                    """
                    INSERT INTO securescope_clock_evidence (
                        client_id,
                        asset_ip,
                        asset_hostname,
                        wazuh_agent_id,
                        status,
                        source,
                        offset_ms,
                        manager_agent_delta_ms,
                        payload,
                        observed_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        row.get("asset_ip") or row.get("ip"),
                        row.get("asset_hostname") or row.get("hostname"),
                        row.get("wazuh_agent_id"),
                        row.get("clock_sync_status") or row.get("status") or "Unknown",
                        row.get("clock_source"),
                        row.get("clock_offset_ms"),
                        row.get("manager_agent_delta_ms"),
                        Json(row),
                        _safe_timestamp(row.get("clock_last_checked")),
                    ),
                )
    return len(values)


def load_latest_clock_evidence(
    client_name: str,
) -> list[dict[str, Any]]:
    """Load the latest evidence record for each client asset."""
    init_clock_evidence_tables()
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT DISTINCT ON (
                    COALESCE(NULLIF(asset_ip, ''), NULLIF(asset_hostname, ''), wazuh_agent_id)
                )
                    payload
                FROM securescope_clock_evidence
                WHERE client_id = %s
                ORDER BY
                    COALESCE(NULLIF(asset_ip, ''), NULLIF(asset_hostname, ''), wazuh_agent_id),
                    collected_at DESC,
                    id DESC;
                """,
                (client_id,),
            )
            return [dict(row["payload"] or {}) for row in cur.fetchall()]
