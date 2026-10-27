"""Transactional working registers and drafts; approvals remain in GRC services."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.grc_repository import GrcRepositoryError, _client_id
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


def load_register(client_name: str, register_key: str) -> dict[str, Any]:
    """Load an editable register without creating records on a read.

    Args:
        client_name: Exact workspace name.
        register_key: Application-owned register identifier.
    Returns:
        Saved rows, revision and recorder; an empty revision-zero draft if absent.
    Raises:
        GrcRepositoryError: On unknown workspace or database failure.
    """
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT rows, revision, updated_by, updated_at "
                    "FROM securescope_working_registers WHERE client_id = %s AND register_key = %s",
                    (client_id, register_key),
                )
                row = cursor.fetchone()
                return dict(row) if row else {"rows": [], "revision": 0, "updated_by": ""}
    except DatabaseError as exc:
        LOGGER.error("Register read failed for %s/%s", client_name, register_key)
        raise GrcRepositoryError("The register could not be loaded. Check PostgreSQL.") from exc


def save_register(
    client_name: str,
    register_key: str,
    rows: list[dict[str, Any]],
    *,
    actor: str,
    expected_revision: int,
) -> int:
    """Save one complete register and its immutable version atomically.

    Args:
        client_name: Exact workspace name.
        register_key: Application-owned identifier.
        rows: JSON-safe working records; never used to grant permissions.
        actor: Identified recorder.
        expected_revision: Revision read before editing, including zero.
    Returns:
        New register revision.
    Raises:
        ValueError: If key, recorder, rows or revision are invalid.
        GrcRepositoryError: If another user saved first or persistence fails.
    """
    if not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,120}", register_key):
        raise ValueError("Invalid working register.")
    if not actor.strip() or len(actor) > 250:
        raise ValueError("Recorded by is required (maximum 250 characters).")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Invalid revision. Reload the register.")
    if not isinstance(rows, list) or len(rows) > 5000:
        raise ValueError("A register supports up to 5,000 records.")
    encoded = json.dumps(rows, allow_nan=False, default=str)
    if len(encoded.encode("utf-8")) > 8_000_000:
        raise ValueError("This register is too large. Keep attachments in Evidence.")
    clean = json.loads(encoded)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE id = %s FOR UPDATE", (client_id,)
                )
                cursor.execute(
                    "SELECT revision FROM securescope_working_registers "
                    "WHERE client_id = %s AND register_key = %s FOR UPDATE",
                    (client_id, register_key),
                )
                previous = cursor.fetchone()
                actual = int(previous["revision"]) if previous else 0
                if actual != expected_revision:
                    raise GrcRepositoryError(
                        "Someone saved a newer version. Reload before saving your changes."
                    )
                revision = actual + 1
                cursor.execute(
                    "INSERT INTO securescope_working_registers "
                    "(client_id, register_key, rows, revision, updated_by) VALUES (%s,"
                    " %s, %s, %s, %s) "
                    "ON CONFLICT (client_id, register_key) DO UPDATE SET rows = EXCLUDED.rows, "
                    "revision = EXCLUDED.revision, updated_by = EXCLUDED.updated_by, "
                    "updated_at = NOW()",
                    (client_id, register_key, Json(clean), revision, actor.strip()),
                )
                cursor.execute(
                    "INSERT INTO securescope_working_register_versions "
                    "(client_id, register_key, revision, rows, recorded_by) VALUES "
                    "(%s, %s, %s, %s, %s)",
                    (client_id, register_key, revision, Json(clean), actor.strip()),
                )
                return revision
    except DatabaseError as exc:
        LOGGER.error("Register write failed for %s/%s", client_name, register_key)
        raise GrcRepositoryError("The register was not saved. Check PostgreSQL.") from exc


def register_history(client_name: str, register_key: str) -> list[dict[str, Any]]:
    """Return recent saved versions with their recorder and timestamp.

    Args:
        client_name: Active workspace.
        register_key: Application-owned identifier.
    Returns:
        Latest twenty version records, newest first.
    Raises:
        GrcRepositoryError: On database or workspace failure.
    """
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT revision, recorded_by, created_at, rows "
                    "FROM securescope_working_register_versions "
                    "WHERE client_id = %s AND register_key = %s ORDER BY revision DESC LIMIT 20",
                    (client_id, register_key),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcRepositoryError("Version history is unavailable.") from exc
