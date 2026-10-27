"""PostgreSQL persistence layer for SecureScope.

The Streamlit app stores client workspaces, asset inventory, OpenVAS scan
history, CISO synchronization metadata and ISO mapping evidence in PostgreSQL.

Environment variable required:
    SECURESCOPE_DATABASE_URL=postgresql://user:password@host:5432/securescope

DATABASE_URL is accepted as a fallback to ease deployment on platforms that use
that conventional variable name.
"""

from __future__ import annotations

import atexit
import os
import re
import threading
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg2
from psycopg2.extras import Json, RealDictCursor
from psycopg2.pool import PoolError, ThreadedConnectionPool

_INITIALIZED = False
_INITIALIZE_LOCK = threading.Lock()
_POOL: ThreadedConnectionPool | None = None
_POOL_URL = ""
_POOL_LOCK = threading.Lock()


class DatabaseConfigurationError(RuntimeError):
    """Raised when the PostgreSQL connection string is missing."""


class DatabaseError(RuntimeError):
    """Raised when a PostgreSQL operation fails."""


def get_database_url() -> str:
    """Return the PostgreSQL connection URL from environment variables."""
    url = os.getenv("SECURESCOPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise DatabaseConfigurationError(
            "Missing SECURESCOPE_DATABASE_URL in .env. Example: "
            "postgresql://securescope:password@localhost:5432/securescope"
        )
    return url.strip()


def _pool_limits() -> tuple[int, int]:
    """Return validated PostgreSQL pool bounds from environment settings.

    Returns:
        Minimum and maximum pooled connection counts.
    """

    try:
        minimum = max(1, int(os.getenv("SECURESCOPE_DB_POOL_MIN", "1")))
    except ValueError:
        minimum = 1
    try:
        maximum = max(minimum, int(os.getenv("SECURESCOPE_DB_POOL_MAX", "12")))
    except ValueError:
        maximum = max(minimum, 12)
    return minimum, maximum


def _get_connection_pool() -> ThreadedConnectionPool:
    """Return the process-wide thread-safe PostgreSQL connection pool.

    Returns:
        Lazily initialized ``ThreadedConnectionPool`` for the active database URL.

    Raises:
        DatabaseError: If PostgreSQL cannot initialize the pool.
    """

    global _POOL, _POOL_URL
    database_url = get_database_url()
    if _POOL is not None and _POOL_URL == database_url:
        return _POOL

    with _POOL_LOCK:
        if _POOL is not None and _POOL_URL == database_url:
            return _POOL
        if _POOL is not None:
            try:
                _POOL.closeall()
            except psycopg2.Error:
                # A stale pool is replaced below; failure to close an already
                # broken connection must not block reconnection.
                pass
            _POOL = None
        minimum, maximum = _pool_limits()
        try:
            _POOL = ThreadedConnectionPool(minimum, maximum, database_url)
        except psycopg2.Error as exc:
            raise DatabaseError(f"Could not initialize PostgreSQL connection pool: {exc}") from exc
        _POOL_URL = database_url
        return _POOL


def close_connection_pool() -> None:
    """Close all pooled PostgreSQL connections during process shutdown."""

    global _POOL, _POOL_URL
    with _POOL_LOCK:
        if _POOL is not None:
            try:
                _POOL.closeall()
            except psycopg2.Error:
                # Interpreter shutdown may race with PostgreSQL teardown.
                pass
            finally:
                _POOL = None
                _POOL_URL = ""


atexit.register(close_connection_pool)


@contextmanager
def connect() -> Iterator[Any]:
    """Borrow one pooled PostgreSQL connection and commit or rollback safely.

    Returns:
        Context manager yielding a psycopg2 connection.

    Raises:
        DatabaseError: If the pool is exhausted or a database operation fails.
    """

    conn = None
    pool = None
    discard = False
    try:
        pool = _get_connection_pool()
        conn = pool.getconn()
        if conn.closed:
            discard = True
            raise DatabaseError("PostgreSQL returned a closed pooled connection.")
        yield conn
        conn.commit()
    except PoolError as exc:
        raise DatabaseError(
            "PostgreSQL connection pool is exhausted. Increase "
            "SECURESCOPE_DB_POOL_MAX if concurrent dashboard queries require it."
        ) from exc
    except DatabaseError:
        if conn is not None and not conn.closed:
            conn.rollback()
        raise
    except psycopg2.Error as exc:
        if conn is not None and not conn.closed:
            conn.rollback()
        if conn is not None and conn.closed:
            discard = True
        raise DatabaseError(str(exc)) from exc
    except (RuntimeError, ValueError, TypeError, KeyError):
        # Domain/programming exceptions raised inside the transaction should keep
        # their original type while still rolling back database work.
        if conn is not None and not conn.closed:
            conn.rollback()
        raise
    finally:
        if conn is not None and pool is not None:
            try:
                pool.putconn(conn, close=discard or bool(conn.closed))
            except PoolError:
                # Pool shutdown can race with interpreter/application teardown.
                pass


def init_database(default_client_name: str = "Default Client") -> None:
    """Create SecureScope tables once using process and PostgreSQL locks."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    with _INITIALIZE_LOCK:
        if _INITIALIZED:
            return

        with connect() as conn:
            with conn.cursor() as cur:
                # Prevent concurrent Streamlit processes from running the same
                # DDL migration and deadlocking on PostgreSQL catalog locks.
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (74109001,))
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_clients (
                        id BIGSERIAL PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_assets (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        asset_tag TEXT,
                        ip TEXT NOT NULL,
                        payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (client_id, ip)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_scan_history (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        report_id TEXT NOT NULL,
                        asset_ip TEXT,
                        scanned_at TIMESTAMPTZ,
                        payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (client_id, report_id)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_securescope_assets_client_ip
                    ON securescope_assets (client_id, ip);
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_securescope_scan_history_client
                    ON securescope_scan_history (
                        client_id,
                        scanned_at DESC NULLS LAST
                    );
                    """
                )
                cur.execute("SELECT to_regclass('securescope_admin_audit_events');")
                has_audit_table = bool(cur.fetchone()[0])
                deleted_before = False
                if has_audit_table:
                    cur.execute(
                        (
                            "SELECT EXISTS(SELECT 1 FROM securescope_admin_audit_events WHERE "
                            "event_type='workspace.deleted');"
                        )
                    )
                    deleted_before = bool(cur.fetchone()[0])
                if not deleted_before:
                    cur.execute(
                        (
                            "INSERT INTO securescope_clients(name) SELECT %s WHERE NOT "
                            "EXISTS(SELECT 1 FROM securescope_clients) ON CONFLICT(name) DO "
                            "NOTHING"
                        ),
                        (default_client_name,),
                    )

        _INITIALIZED = True


def _row_id(row: Any) -> int:
    """Return an integer id from either a normal cursor row or RealDictCursor row."""
    if row is None:
        raise DatabaseError("PostgreSQL did not return an id.")
    if isinstance(row, dict):
        return int(row["id"])
    return int(row[0])


def _get_client_id(cur: Any, client_name: str, create: bool = True) -> int:
    """Return the PostgreSQL ID for a client workspace."""
    name = (client_name or "Default Client").strip() or "Default Client"

    if create:
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
        return _row_id(row)

    cur.execute("SELECT id FROM securescope_clients WHERE name = %s;", (name,))
    row = cur.fetchone()
    if not row:
        raise DatabaseError(f"Client workspace not found: {name}")
    return _row_id(row)


def ensure_client(client_name: str) -> str:
    """Create a client workspace when missing and return its name."""
    name = (client_name or "Default Client").strip() or "Default Client"
    init_database(name)
    with connect() as conn:
        with conn.cursor() as cur:
            _get_client_id(cur, name, create=True)
    return name


def get_client_id(client_name: str, *, create: bool = False) -> int:
    """Return the PostgreSQL identifier for one named client workspace.

    Args:
        client_name: Exact client workspace name.
        create: Whether to create the workspace when it does not exist.

    Returns:
        Positive PostgreSQL client identifier.

    Raises:
        DatabaseConfigurationError: If the database URL is missing.
        DatabaseError: If the workspace does not exist or PostgreSQL fails.
    """

    name = str(client_name or "").strip()
    if not name:
        raise DatabaseError("Client workspace name cannot be empty.")
    init_database(name if create else "Default Client")
    with connect() as conn:
        with conn.cursor() as cur:
            return _get_client_id(cur, name, create=create)


def list_client_names(default_client_name: str = "Default Client") -> list[str]:
    """Return all client workspace names stored in PostgreSQL."""
    init_database(default_client_name)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT name
                FROM securescope_clients
                ORDER BY lower(name);
                """
            )
            return [str(row[0]) for row in cur.fetchall()]


def load_assets_for_client(client_name: str) -> list[dict[str, Any]]:
    """Load asset records for one client workspace."""
    init_database(client_name)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _get_client_id(cur, client_name, create=False)
            cur.execute(
                """
                SELECT payload
                FROM securescope_assets
                WHERE client_id = %s
                ORDER BY ip;
                """,
                (client_id,),
            )
            return [dict(row["payload"]) for row in cur.fetchall()]


def load_all_assets() -> list[dict[str, Any]]:
    """Load all asset records across every client workspace."""
    init_database()
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT payload
                FROM securescope_assets
                ORDER BY client_id, ip;
                """
            )
            return [dict(row["payload"]) for row in cur.fetchall()]


def save_assets_for_client(client_name: str, assets: list[dict[str, Any]]) -> None:
    """Replace one client's asset inventory with the supplied records."""
    init_database(client_name)
    with connect() as conn:
        with conn.cursor() as cur:
            client_id = _get_client_id(cur, client_name, create=False)
            cur.execute("DELETE FROM securescope_assets WHERE client_id = %s;", (client_id,))
            for asset in assets:
                payload = dict(asset)
                payload["client_name"] = client_name
                ip = str(payload.get("ip") or "Unknown")
                report_tag = str(payload.get("asset_tag") or "")
                cur.execute(
                    """
                    INSERT INTO securescope_assets (client_id, asset_tag, ip, payload)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (client_id, ip)
                    DO UPDATE SET
                        asset_tag = EXCLUDED.asset_tag,
                        payload = EXCLUDED.payload,
                        updated_at = NOW();
                    """,
                    (client_id, report_tag, ip, Json(payload)),
                )


def load_scan_history_for_client(client_name: str, max_records: int = 30) -> list[dict[str, Any]]:
    """Load saved OpenVAS scan records for one client workspace."""
    init_database(client_name)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _get_client_id(cur, client_name, create=False)
            cur.execute(
                """
                SELECT payload
                FROM securescope_scan_history
                WHERE client_id = %s
                ORDER BY scanned_at DESC NULLS LAST, id DESC
                LIMIT %s;
                """,
                (client_id, max_records),
            )
            return [dict(row["payload"]) for row in cur.fetchall()]


def load_all_scan_history(max_records: int | None = None) -> list[dict[str, Any]]:
    """Load scan history across all clients."""
    init_database()
    limit_clause = ""
    params: tuple[Any, ...] = ()
    if max_records is not None:
        limit_clause = "LIMIT %s"
        params = (max_records,)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT payload
                FROM securescope_scan_history
                ORDER BY scanned_at DESC NULLS LAST, id DESC
                {limit_clause};
                """,
                params,
            )
            return [dict(row["payload"]) for row in cur.fetchall()]


def save_scan_history_for_client(
    client_name: str,
    history: list[dict[str, Any]],
    max_records: int = 30,
) -> None:
    """Replace one client's saved scan history with the supplied records."""
    init_database(client_name)
    with connect() as conn:
        with conn.cursor() as cur:
            client_id = _get_client_id(cur, client_name, create=False)
            cur.execute("DELETE FROM securescope_scan_history WHERE client_id = %s;", (client_id,))
            for index, record in enumerate(history[:max_records]):
                payload = dict(record)
                payload["client_name"] = client_name
                report_id = str(payload.get("report_id") or f"manual-{index}")
                asset_ip = str(payload.get("asset_ip") or "")
                scanned_at = payload.get("scanned_at") or None
                cur.execute(
                    """
                    INSERT INTO securescope_scan_history (
                        client_id,
                        report_id,
                        asset_ip,
                        scanned_at,
                        payload
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (client_id, report_id)
                    DO UPDATE SET
                        asset_ip = EXCLUDED.asset_ip,
                        scanned_at = EXCLUDED.scanned_at,
                        payload = EXCLUDED.payload,
                        updated_at = NOW();
                    """,
                    (client_id, report_id, asset_ip, scanned_at, Json(payload)),
                )


def get_client_name_by_id(client_id: int) -> str:
    """Return the client workspace name for a database ID.

    Args:
        client_id: PostgreSQL client identifier.

    Returns:
        Client workspace name.

    Raises:
        DatabaseError: If the client does not exist.
    """
    init_database()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM securescope_clients WHERE id = %s;",
                (int(client_id),),
            )
            row = cur.fetchone()
            if not row:
                raise DatabaseError(f"Client workspace not found: {client_id}")
            return str(row[0])


def upsert_scan_record_for_client(
    client_name: str,
    record: dict[str, Any],
) -> None:
    """Insert or update one scan-history record without replacing others.

    Args:
        client_name: Target client workspace.
        record: Scan record containing at least ``report_id``.

    Raises:
        DatabaseError: If ``report_id`` is missing or PostgreSQL fails.
    """
    payload = dict(record)
    report_id = str(payload.get("report_id") or "").strip()
    if not report_id:
        raise DatabaseError("A scan history record requires report_id.")

    payload["client_name"] = client_name
    asset_ip = str(payload.get("asset_ip") or "")
    scanned_at = payload.get("scanned_at") or None

    init_database(client_name)
    with connect() as conn:
        with conn.cursor() as cur:
            client_id = _get_client_id(cur, client_name, create=False)
            cur.execute(
                """
                INSERT INTO securescope_scan_history (
                    client_id,
                    report_id,
                    asset_ip,
                    scanned_at,
                    payload
                )
                VALUES (%s, %s, %s, %s, %s)
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
                    asset_ip,
                    scanned_at,
                    Json(payload),
                ),
            )


def mark_asset_scanned_for_engine(
    client_name: str,
    asset_ip: str,
    scanned_at: str,
    scanner_engine: str,
) -> None:
    """Update one asset with generic and provider-specific scan timestamps.

    Args:
        client_name: Client workspace name.
        asset_ip: Asset IP address.
        scanned_at: Completion timestamp.
        scanner_engine: Canonical scanner name used to build the payload key.

    Raises:
        DatabaseError: If PostgreSQL persistence fails.
    """

    engine_key = (
        re.sub(
            r"[^a-z0-9]+",
            "_",
            str(scanner_engine or "scanner").strip().lower(),
        ).strip("_")
        or "scanner"
    )
    init_database(client_name)
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _get_client_id(cur, client_name, create=False)
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
            payload[f"last_{engine_key}_scan"] = scanned_at
            cur.execute(
                """
                UPDATE securescope_assets
                SET payload = %s, updated_at = NOW()
                WHERE client_id = %s AND ip = %s;
                """,
                (Json(payload), client_id, asset_ip),
            )
