"""
SecureScope Wazuh PostgreSQL persistence.

Fixes included:
- Wazuh manager agent 000 can return lastKeepAlive = 9999-12-31T23:59:59+00:00.
  On Windows/Python this may become "year 10000 is out of range" after timezone conversion.
  We now store that sentinel value as NULL.
- Reads timestamp columns as text to avoid psycopg2 datetime conversion problems.
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.db_service import init_database

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)

_WAZUH_INITIALIZED = False
_WAZUH_INIT_LOCK = threading.Lock()
_WAZUH_DDL_LOCK_KEY = 74109003


class WazuhDatabaseError(RuntimeError):
    pass


def database_url() -> str:
    url = os.getenv("SECURESCOPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise WazuhDatabaseError("Missing SECURESCOPE_DATABASE_URL or DATABASE_URL in .env")
    return url


@contextmanager
def connect():
    conn = None
    try:
        conn = psycopg2.connect(database_url())
        yield conn
        conn.commit()
    except Exception as exc:
        if conn:
            conn.rollback()
        raise WazuhDatabaseError(str(exc)) from exc
    finally:
        if conn:
            conn.close()


def init_wazuh_tables() -> None:
    """Create Wazuh evidence tables once with cross-process DDL locking."""
    global _WAZUH_INITIALIZED
    if _WAZUH_INITIALIZED:
        return

    with _WAZUH_INIT_LOCK:
        if _WAZUH_INITIALIZED:
            return

        init_database()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(%s);",
                    (_WAZUH_DDL_LOCK_KEY,),
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_wazuh_agents (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        wazuh_agent_id TEXT NOT NULL,
                        agent_name TEXT,
                        agent_ip TEXT,
                        status TEXT,
                        last_keep_alive TIMESTAMPTZ NULL,
                        os_label TEXT,
                        version TEXT,
                        agent_group TEXT,
                        raw JSONB NOT NULL DEFAULT '{}'::jsonb,
                        collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE(client_id, wazuh_agent_id)
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_asset_wazuh_status (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        asset_ip TEXT,
                        asset_hostname TEXT,
                        asset_tag TEXT,
                        match_type TEXT,
                        monitoring_status TEXT,
                        wazuh_agent_id TEXT,
                        wazuh_agent_name TEXT,
                        wazuh_agent_ip TEXT,
                        wazuh_status TEXT,
                        wazuh_last_keep_alive TIMESTAMPTZ NULL,
                        wazuh_os TEXT,
                        wazuh_version TEXT,
                        wazuh_group TEXT,
                        last_rule_id TEXT,
                        last_rule_level INTEGER NULL,
                        last_rule_description TEXT,
                        last_alert_time TIMESTAMPTZ NULL,
                        last_action TEXT,
                        raw JSONB NOT NULL DEFAULT '{}'::jsonb,
                        collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_securescope_asset_wazuh_status_client
                    ON securescope_asset_wazuh_status(client_id, collected_at DESC);
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_securescope_asset_wazuh_status_asset_ip
                    ON securescope_asset_wazuh_status(asset_ip);
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_iso_evidence (
                        id BIGSERIAL PRIMARY KEY,
                        client_id BIGINT REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        control_id TEXT NOT NULL,
                        control_name TEXT,
                        status TEXT,
                        evidence TEXT,
                        source TEXT,
                        metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
                        collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_securescope_iso_evidence_client_control
                    ON securescope_iso_evidence(client_id, control_id, collected_at DESC);
                    """
                )

        _WAZUH_INITIALIZED = True


def get_client_id(conn, client_name: str) -> int:
    name = (client_name or "Default Client").strip() or "Default Client"
    with conn.cursor() as cur:
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
        return int(row[0])


def safe_timestamp(value: Any) -> Optional[str]:
    """
    Convert Wazuh timestamps to values safe for PostgreSQL/Python.

    Wazuh manager agent 000 can use:
        9999-12-31T23:59:59+00:00

    This can break Python timezone conversion with:
        year 10000 is out of range

    We treat far-future sentinel values as NULL.
    """
    if not value:
        return None

    text = str(value).strip()
    if not text:
        return None

    # Common Wazuh sentinel for the manager agent.
    if text.startswith("9999-") or text.startswith("10000-"):
        return None

    # Defensive rule: any timestamp year >= 2099 is considered a sentinel.
    try:
        year = int(text[:4])
        if year >= 2099:
            return None
    except Exception:
        pass

    return text


def cleanup_future_wazuh_dates() -> None:
    """
    Clean existing bad rows created before this fix.
    """
    init_wazuh_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE securescope_wazuh_agents
                SET last_keep_alive = NULL
                WHERE last_keep_alive >= TIMESTAMPTZ '2099-01-01 00:00:00+00';
                """
            )
            cur.execute(
                """
                UPDATE securescope_asset_wazuh_status
                SET wazuh_last_keep_alive = NULL
                WHERE wazuh_last_keep_alive >= TIMESTAMPTZ '2099-01-01 00:00:00+00';
                """
            )
            cur.execute(
                """
                UPDATE securescope_asset_wazuh_status
                SET last_alert_time = NULL
                WHERE last_alert_time >= TIMESTAMPTZ '2099-01-01 00:00:00+00';
                """
            )


def save_wazuh_snapshot(
    client_name: str,
    agents: Iterable[Dict[str, Any]],
    monitoring_rows: Iterable[Dict[str, Any]],
    iso_evidence: Optional[Dict[str, Any]] = None,
) -> None:
    init_wazuh_tables()
    with connect() as conn:
        client_id = get_client_id(conn, client_name)

        with conn.cursor() as cur:
            for agent in agents:
                cur.execute(
                    """
                    INSERT INTO securescope_wazuh_agents (
                        client_id, wazuh_agent_id, agent_name, agent_ip, status,
                        last_keep_alive, os_label, version, agent_group, raw, collected_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW())
                    ON CONFLICT (client_id, wazuh_agent_id)
                    DO UPDATE SET
                        agent_name = EXCLUDED.agent_name,
                        agent_ip = EXCLUDED.agent_ip,
                        status = EXCLUDED.status,
                        last_keep_alive = EXCLUDED.last_keep_alive,
                        os_label = EXCLUDED.os_label,
                        version = EXCLUDED.version,
                        agent_group = EXCLUDED.agent_group,
                        raw = EXCLUDED.raw,
                        collected_at = NOW();
                    """,
                    (
                        client_id,
                        agent.get("agent_id"),
                        agent.get("agent_name"),
                        agent.get("agent_ip"),
                        agent.get("status"),
                        safe_timestamp(agent.get("last_keep_alive")),
                        agent.get("os_label") or agent.get("wazuh_os"),
                        agent.get("version"),
                        agent.get("group") or agent.get("agent_group"),
                        json.dumps(agent.get("raw") or agent, default=str),
                    ),
                )

            # Legacy callers append history; canonical M1 collection uses durable observations.
            for row in monitoring_rows:
                last_alert = row.get("last_alert") or {}
                last_rule_level = last_alert.get("rule_level")
                try:
                    last_rule_level = int(last_rule_level) if last_rule_level is not None else None
                except (TypeError, ValueError):
                    last_rule_level = None

                cur.execute(
                    """
                    INSERT INTO securescope_asset_wazuh_status (
                        client_id, asset_ip, asset_hostname, asset_tag, match_type,
                        monitoring_status, wazuh_agent_id, wazuh_agent_name, wazuh_agent_ip,
                        wazuh_status, wazuh_last_keep_alive, wazuh_os, wazuh_version, wazuh_group,
                        last_rule_id, last_rule_level, last_rule_description,
                        last_alert_time, last_action, raw, collected_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s::jsonb, NOW()
                    );
                    """,
                    (
                        client_id,
                        row.get("asset_ip"),
                        row.get("asset_hostname"),
                        row.get("asset_tag"),
                        row.get("match_type"),
                        row.get("monitoring_status"),
                        row.get("wazuh_agent_id"),
                        row.get("wazuh_agent_name"),
                        row.get("wazuh_agent_ip"),
                        row.get("wazuh_status"),
                        safe_timestamp(row.get("wazuh_last_keep_alive")),
                        row.get("wazuh_os"),
                        row.get("wazuh_version"),
                        row.get("wazuh_group"),
                        last_alert.get("rule_id"),
                        last_rule_level,
                        last_alert.get("rule_description"),
                        safe_timestamp(last_alert.get("timestamp")),
                        last_alert.get("rule_description"),
                        json.dumps(row, default=str),
                    ),
                )

            if iso_evidence:
                cur.execute(
                    (
                        "\n                    INSERT INTO securescope_iso_evidence "
                        "(\n                        client_id, control_id, "
                        "control_name, status, evidence, source, metrics, "
                        "collected_at\n                    )\n                    "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, NOW());\n         "
                        "           "
                    ),
                    (
                        client_id,
                        iso_evidence.get("control_id"),
                        iso_evidence.get("control_name"),
                        iso_evidence.get("status"),
                        iso_evidence.get("evidence"),
                        "Wazuh",
                        json.dumps(iso_evidence, default=str),
                    ),
                )

        # Clean any older sentinel rows after saving.
        cleanup_future_wazuh_dates()


def load_legacy_wazuh_status(client_name: str) -> List[Dict[str, Any]]:
    init_wazuh_tables()
    cleanup_future_wazuh_dates()

    with connect() as conn:
        client_id = get_client_id(conn, client_name)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Cast timestamptz columns to text to avoid Python datetime issues.
            cur.execute(
                """
                SELECT
                    id,
                    client_id,
                    asset_ip,
                    asset_hostname,
                    asset_tag,
                    match_type,
                    monitoring_status,
                    wazuh_agent_id,
                    wazuh_agent_name,
                    wazuh_agent_ip,
                    wazuh_status,
                    wazuh_last_keep_alive::text AS wazuh_last_keep_alive,
                    wazuh_os,
                    wazuh_version,
                    wazuh_group,
                    last_rule_id,
                    last_rule_level,
                    last_rule_description,
                    last_alert_time::text AS last_alert_time,
                    last_action,
                    raw,
                    collected_at::text AS collected_at
                FROM securescope_asset_wazuh_status
                WHERE client_id = %s
                ORDER BY
                    CASE monitoring_status
                        WHEN 'Monitored' THEN 1
                        WHEN 'Agent not active' THEN 2
                        WHEN 'Not monitored' THEN 3
                        ELSE 4
                    END,
                    asset_ip NULLS LAST,
                    wazuh_agent_id NULLS LAST;
                """,
                (client_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def load_latest_iso_evidence(
    client_name: str, control_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    init_wazuh_tables()

    with connect() as conn:
        client_id = get_client_id(conn, client_name)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if control_id:
                cur.execute(
                    """
                    SELECT
                        id,
                        client_id,
                        control_id,
                        control_name,
                        status,
                        evidence,
                        source,
                        metrics,
                        collected_at::text AS collected_at
                    FROM securescope_iso_evidence
                    WHERE client_id = %s AND control_id = %s
                    ORDER BY collected_at DESC
                    LIMIT 20;
                    """,
                    (client_id, control_id),
                )
            else:
                cur.execute(
                    """
                    SELECT
                        id,
                        client_id,
                        control_id,
                        control_name,
                        status,
                        evidence,
                        source,
                        metrics,
                        collected_at::text AS collected_at
                    FROM securescope_iso_evidence
                    WHERE client_id = %s
                    ORDER BY collected_at DESC
                    LIMIT 50;
                    """,
                    (client_id,),
                )
            return [dict(row) for row in cur.fetchall()]


# M1 stores immutable facts separately from the legacy compatibility tables.
def existing_client_id(conn: Any, client_name: str) -> int:
    """Resolve an existing workspace without creating or updating it.

    Raises:
        WazuhDatabaseError: If the explicit workspace does not exist.
    """
    if not client_name or not client_name.strip():
        raise WazuhDatabaseError("An existing workspace is required.")
    with conn.cursor() as cursor:
        cursor.execute("SELECT id FROM securescope_clients WHERE name=%s", (client_name.strip(),))
        row = cursor.fetchone()
        if not row:
            raise WazuhDatabaseError("Workspace was not found.")
        return int(row[0])


def _monitoring_schema() -> None:
    """Apply additive migrations before accessing monitoring records.

    Returns:
        None.
    Raises:
        MigrationError: If the migration ledger or schema cannot be updated.
    """
    from securescope.persistence.migration_service import run_pending_migrations

    run_pending_migrations()


def _monitoring_actor(cursor: Any, client_id: int, actor: str, *, admin: bool = False) -> None:
    """Authorize a monitoring mutation against current workspace membership.

    Args:
        cursor: Transaction cursor; client_id: tenant; actor: server identity.
        admin: Require Administrator for identity changes.
    Returns:
        None.
    Raises:
        WazuhDatabaseError: If membership is absent or insufficient.
    """
    from securescope.persistence.foundation_repository import member_role

    allowed = {"Administrator"} if admin else {"Administrator", "Consultant"}
    if member_role(cursor, client_id, actor) not in allowed:
        raise WazuhDatabaseError("Current workspace authorization is required.")


def list_monitoring_bindings(client_name: str, connector_id: str) -> list[dict]:
    """Load only active bindings owned by a workspace and connector.

    Args:
        client_name: Existing workspace; connector_id: non-secret endpoint identity.
    Returns:
        Active approved binding rows.
    Raises:
        WazuhDatabaseError: On database failure.
    """
    _monitoring_schema()
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            cur.execute(
                "SELECT * FROM securescope_wazuh_bindings WHERE client_id=%s "
                "AND connector_id=%s AND revoked_at IS NULL ORDER BY asset_id",
                (client_id, connector_id),
            )
            return [dict(row) for row in cur.fetchall()]


def approve_monitoring_binding(
    client_name: str,
    actor: str,
    *,
    asset_id: int,
    connector_id: str,
    manager_name: str,
    agent_id: str,
    heartbeat_max_age_seconds: int,
    telemetry_max_age_seconds: int,
    rationale: str,
) -> int:
    """Record an explicit, auditable agent/asset association; never infer scope.

    Args:
        client_name: Workspace; actor: authorized host/workspace administrator.
        asset_id: Canonical inventory ID; connector_id: current endpoint identity.
        manager_name: Exact Wazuh manager name; agent_id: exact endpoint ID.
        heartbeat_max_age_seconds: Chosen heartbeat/collection freshness window.
        telemetry_max_age_seconds: Chosen telemetry freshness window.
        rationale: Human explanation confirming ownership and identity.
    Returns:
        New binding ID.
    Raises:
        WazuhDatabaseError: On invalid, conflicting or cross-tenant association.
        WazuhError: If host connector administration is not authorized.
    """
    import re

    from securescope.integrations.wazuh_service import WazuhClient, require_connector_admin
    from securescope.persistence.evidence_repository import _append_audit_event

    require_connector_admin(client_name, actor)
    if connector_id != WazuhClient().connector_id:
        raise WazuhDatabaseError("Connector configuration changed; reload before approving.")
    if (
        not re.fullmatch(r"[0-9]{3,}", agent_id)
        or agent_id == "000"
        or not manager_name.strip()
        or not rationale.strip()
        or not 1 <= heartbeat_max_age_seconds <= 604800
        or not 1 <= telemetry_max_age_seconds <= 31536000
    ):
        raise WazuhDatabaseError(
            "An exact endpoint identity, rationale and valid policy are required."
        )
    _monitoring_schema()
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            _monitoring_actor(cur, client_id, actor, admin=True)
            cur.execute(
                "SELECT id FROM securescope_assets WHERE client_id=%s AND id=%s FOR SHARE",
                (client_id, asset_id),
            )
            if not cur.fetchone():
                raise WazuhDatabaseError("Asset does not belong to this workspace.")
            cur.execute(
                "INSERT INTO securescope_wazuh_bindings "
                "(client_id,asset_id,connector_id,manager_name,agent_id,"
                "heartbeat_max_age_seconds,telemetry_max_age_seconds,approved_by,rationale) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id",
                (
                    client_id,
                    asset_id,
                    connector_id,
                    manager_name.strip(),
                    agent_id,
                    heartbeat_max_age_seconds,
                    telemetry_max_age_seconds,
                    actor,
                    rationale,
                ),
            )
            result = cur.fetchone()
            if not result:
                raise WazuhDatabaseError(
                    "Asset or agent already has an active binding; review it first."
                )
            _append_audit_event(
                cur,
                client_id,
                event_type="Wazuh binding approved",
                entity_type="Wazuh binding",
                entity_id=str(result["id"]),
                actor=actor,
                summary=rationale,
                payload={"asset_id": asset_id},
            )
            return int(result["id"])


def revoke_monitoring_binding(
    client_name: str, actor: str, binding_id: int, rationale: str
) -> None:
    """Revoke a binding while preserving observations and approval history.

    Args:
        client_name: Workspace; actor: administrator; binding_id: owned binding.
        rationale: Required human reason.
    Returns:
        None.
    Raises:
        WazuhDatabaseError: If authorization or binding validation fails.
    """
    from securescope.integrations.wazuh_service import require_connector_admin
    from securescope.persistence.evidence_repository import _append_audit_event

    require_connector_admin(client_name, actor)
    if not rationale.strip():
        raise WazuhDatabaseError("Record a revocation reason.")
    _monitoring_schema()
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            _monitoring_actor(cur, client_id, actor, admin=True)
            cur.execute(
                "UPDATE securescope_wazuh_bindings SET revoked_at=NOW(),revoked_by=%s "
                "WHERE client_id=%s AND id=%s AND revoked_at IS NULL RETURNING id",
                (actor, client_id, binding_id),
            )
            if not cur.fetchone():
                raise WazuhDatabaseError("Active binding was not found in this workspace.")
            _append_audit_event(
                cur,
                client_id,
                event_type="Wazuh binding revoked",
                entity_type="Wazuh binding",
                entity_id=str(binding_id),
                actor=actor,
                summary=rationale,
            )


def start_monitoring_collection(client_name: str, actor: str, connector_id: str) -> int:
    """Persist a collection attempt before making any external calls.

    Args:
        client_name: Workspace; actor: authorized member; connector_id: source identity.
    Returns:
        Collection run ID.
    Raises:
        WazuhDatabaseError: On authorization or persistence failure.
    """
    _monitoring_schema()
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            _monitoring_actor(cur, client_id, actor)
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"wazuh-collection-boundary:{client_id}:{connector_id}",),
            )
            cur.execute("SELECT to_regclass('securescope_evidence_schedules') AS name")
            if cur.fetchone()["name"]:
                cur.execute(
                    "SELECT id FROM securescope_evidence_schedules WHERE client_id=%s "
                    "AND connector_id=%s LIMIT 1",
                    (client_id, connector_id),
                )
                if cur.fetchone():
                    raise WazuhDatabaseError(
                        "This connector uses approved scheduled collection. Use its Run now control."
                    )
            cur.execute(
                "INSERT INTO securescope_wazuh_collection_runs "
                "(client_id,connector_id,requested_by) VALUES (%s,%s,%s) RETURNING id",
                (client_id, connector_id, actor),
            )
            return int(cur.fetchone()["id"])


def finish_monitoring_collection(
    client_name: str, actor: str, run_id: int, rows: list[dict], outcome: str, error_code: str = ""
) -> None:
    """Atomically persist source facts, stable hashes and the run outcome.

    Args:
        client_name: Workspace; actor: member; run_id: owned pending run.
        rows: Connector-produced minimal snapshots; outcome: succeeded/partial/failed.
        error_code: Safe diagnostic category, never a raw response or credential.
    Returns:
        None. Repeating a completed run has no effect.
    Raises:
        WazuhDatabaseError: For unauthorized/cross-tenant or malformed persistence.
    """
    import hashlib

    from securescope.persistence.evidence_repository import _append_audit_event

    if outcome not in {"succeeded", "partial", "failed"}:
        raise WazuhDatabaseError("Invalid collection outcome.")
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            _monitoring_actor(cur, client_id, actor)
            cur.execute(
                "SELECT * FROM securescope_wazuh_collection_runs "
                "WHERE client_id=%s AND id=%s AND requested_by=%s FOR UPDATE",
                (client_id, run_id, actor),
            )
            run = cur.fetchone()
            if not run:
                raise WazuhDatabaseError("Collection run does not belong to this actor/workspace.")
            if run["outcome"] != "running":
                return
            for row in rows:
                if not row.get("binding_id"):
                    continue
                cur.execute(
                    "SELECT b.* FROM securescope_wazuh_bindings b "
                    "JOIN securescope_assets a ON a.client_id=b.client_id AND a.id=b.asset_id "
                    "WHERE b.client_id=%s AND b.id=%s AND b.asset_id=%s "
                    "AND b.connector_id=%s AND b.revoked_at IS NULL FOR SHARE OF b",
                    (client_id, row["binding_id"], row["asset_id"], run["connector_id"]),
                )
                binding = cur.fetchone()
                if not binding or any(
                    row.get(key) != binding[key]
                    for key in (
                        "manager_name",
                        "heartbeat_max_age_seconds",
                        "telemetry_max_age_seconds",
                    )
                ):
                    raise WazuhDatabaseError(
                        "Monitoring source binding changed or is unauthorized."
                    )
                if row.get("wazuh_agent_id") != binding["agent_id"]:
                    raise WazuhDatabaseError("Source agent does not match the approved binding.")
                payload = {
                    k: v
                    for k, v in row.items()
                    if k
                    not in {
                        "collected_at",
                        "monitoring_state",
                        "monitoring_status",
                        "monitoring_reason",
                        "last_verified_at",
                        "verified_until",
                    }
                }
                serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
                digest = hashlib.sha256(serialized.encode()).hexdigest()
                source_key = f"v2:{binding['id']}:{digest}"
                cur.execute(
                    "INSERT INTO securescope_wazuh_observations "
                    "(client_id,binding_id,asset_id,source_key,payload_sha256,payload) "
                    "VALUES (%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING",
                    (client_id, binding["id"], binding["asset_id"], source_key, digest, serialized),
                )
                cur.execute(
                    "SELECT id FROM securescope_wazuh_observations "
                    "WHERE client_id=%s AND source_key=%s",
                    (client_id, source_key),
                )
                observation_id = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO securescope_wazuh_run_assets "
                    "(client_id,run_id,observation_id,asset_id) VALUES (%s,%s,%s,%s) "
                    "ON CONFLICT DO NOTHING",
                    (client_id, run_id, observation_id, row["asset_id"]),
                )
            cur.execute(
                "UPDATE securescope_wazuh_collection_runs SET outcome=%s,error_code=%s,"
                "completed_at=NOW() WHERE client_id=%s AND id=%s",
                (outcome, error_code, client_id, run_id),
            )
            _append_audit_event(
                cur,
                client_id,
                event_type="Wazuh monitoring collection",
                entity_type="Wazuh collection",
                entity_id=str(run_id),
                actor=actor,
                summary=f"Collection {outcome}",
                payload={"error_code": error_code},
            )


def load_monitoring_rows(cursor: Any, client_id: int) -> list[dict]:
    """Read current asset facts and source health without renewing observation dates.

    Args:
        cursor: Tenant transaction cursor; client_id: canonical workspace.
    Returns:
        Latest snapshot for each bound asset; revoked sources become unverified.
    Raises:
        psycopg2.Error: If PostgreSQL cannot read monitoring data.
    """
    from securescope.integrations.wazuh_monitoring import evaluate_monitoring

    cursor.execute(
        "SELECT DISTINCT ON (x.asset_id) o.id,o.source_key,o.payload_sha256,o.payload,"
        "r.started_at AS collected_at,b.revoked_at,a.ip AS "
        "asset_ip,a.payload->>'hostname' AS asset_hostname,"
        "a.asset_tag FROM securescope_wazuh_run_assets x "
        "JOIN securescope_wazuh_observations o ON o.client_id=x.client_id "
        "AND o.id=x.observation_id "
        "JOIN securescope_wazuh_collection_runs r ON r.client_id=x.client_id AND r.id=x.run_id "
        "JOIN securescope_wazuh_bindings b ON b.client_id=o.client_id AND b.id=o.binding_id "
        "JOIN securescope_assets a ON a.client_id=x.client_id AND a.id=x.asset_id "
        "WHERE x.client_id=%s ORDER BY x.asset_id,r.started_at DESC,r.id DESC",
        (client_id,),
    )
    from securescope.integrations.wazuh_service import configured_connector_id

    connector_id = configured_connector_id()
    rows = []
    for record in cursor.fetchall():
        row = dict(record["payload"], **{k: v for k, v in record.items() if k != "payload"})
        if record["revoked_at"] or row.get("connector_id") != connector_id:
            row["identity_verified"] = False
        row.update(evaluate_monitoring(row))
        rows.append(row)
    return rows


def load_latest_wazuh_status(client_name: str) -> List[Dict[str, Any]]:
    """Return every inventory asset with current factual verification status.

    Args:
        client_name: Existing workspace name.
    Returns:
        Workspace-owned rows, including unbound assets as not verified.
    Raises:
        WazuhDatabaseError: On database failure.
    """
    from securescope.integrations.wazuh_monitoring import evaluate_monitoring

    _monitoring_schema()
    with connect() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            client_id = existing_client_id(conn, client_name)
            rows = load_monitoring_rows(cur, client_id)
            known = {r["asset_id"] for r in rows}
            cur.execute(
                "SELECT id AS asset_id,ip AS asset_ip,payload->>'hostname' AS "
                "asset_hostname,asset_tag "
                "FROM securescope_assets WHERE client_id=%s ORDER BY id",
                (client_id,),
            )
            for asset in cur.fetchall():
                if asset["asset_id"] not in known:
                    row = dict(asset, schema_version=2, identity_verified=False, match_type="none")
                    row.update(evaluate_monitoring(row))
                    rows.append(row)
            return rows
