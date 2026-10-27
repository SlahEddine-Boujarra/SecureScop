"""Bounded on-demand Wazuh collection using existing services and evidence bridge."""

import logging
from datetime import datetime, timezone

from securescope.integrations.wazuh_monitoring import evaluate_monitoring
from securescope.integrations.wazuh_service import (
    WazuhClient,
    WazuhError,
    WazuhTelemetryNotConfigured,
    match_agents_to_assets,
)
from securescope.persistence.db_wazuh_service import (
    connect,
    existing_client_id,
    finish_monitoring_collection,
    list_monitoring_bindings,
    load_latest_wazuh_status,
    start_monitoring_collection,
)

LOGGER = logging.getLogger(__name__)


def collect_monitoring(
    client_name: str, actor: str, collection_context: dict | None = None
) -> dict:
    """Collect only bound workspace agents and persist failures without false success.

    Args:
        client_name: Existing workspace; actor: authorized server-side identity.
        collection_context: Optional originating requirement context for canonical evidence.
    Returns:
        Run ID, outcome, count of evidence and explainable monitoring rows.
    Raises:
        WazuhError: If connector configuration is invalid.
        WazuhDatabaseError: On authorization, identity or persistence failure.
        EvidenceRepositoryError: If canonical ingestion fails after source persistence.
    """
    import os

    from psycopg2.extras import RealDictCursor

    from securescope.evidence.wazuh_bridge import ingest_wazuh_evidence

    if os.getenv("SECURESCOPE_RECURRING_EVIDENCE_ENABLED", "").lower() == "true":
        from securescope.persistence.evidence_schedule_repository import queue_manual_context

        return queue_manual_context(client_name, actor, collection_context)

    if collection_context and collection_context.get("client") != client_name:
        raise WazuhError("Collection origin belongs to another workspace.")
    client = WazuhClient()
    run_id = start_monitoring_collection(client_name, actor, client.connector_id)
    bindings = list_monitoring_bindings(client_name, client.connector_id)
    with connect() as connection:
        client_id = existing_client_id(connection, client_name)
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id,ip,asset_tag,payload->>'hostname' AS hostname "
                "FROM securescope_assets WHERE client_id=%s",
                (client_id,),
            )
            assets = [dict(a) for a in cursor.fetchall()]
    previous = {r["asset_id"]: r for r in load_latest_wazuh_status(client_name)}
    collected_at = datetime.now(timezone.utc)
    error = ""
    try:
        agents = client.list_agents(agent_ids=[b["agent_id"] for b in bindings])
    except WazuhError:
        LOGGER.warning("Wazuh agent collection failed for run %s", run_id)
        agents, error = [], "Agent API unavailable or incomplete"
    rows = match_agents_to_assets(assets, agents, bindings=bindings)
    for row in rows:
        row.update(
            schema_version=2,
            collected_at=collected_at,
            api_verified=not bool(error) and client.verify_tls is True,
            source_health="unavailable" if error else "healthy",
            source_error=error,
            telemetry={},
        )
        if not error and client.verify_tls is not True:
            row["source_error"] = (
                "API TLS verification is disabled; source identity is not verified."
            )
            row["source_health"] = "unavailable"
        old = previous.get(row["asset_id"], {})
        same_binding = old.get("binding_id") == row.get("binding_id")
        if error and same_binding and row.get("binding_id"):
            for key in ("identity_verified", "wazuh_status", "wazuh_last_keep_alive", "telemetry"):
                row[key] = old.get(key)
        if row["identity_verified"] and not error:
            try:
                row["telemetry"] = client.search_last_alert_for_agent(
                    agent_id=row["wazuh_agent_id"], manager_name=row["manager_name"]
                )
            except WazuhTelemetryNotConfigured:
                row["source_health"] = "api_only"
                row["source_error"] = (
                    "Indexer not configured; API heartbeat alone is not telemetry."
                )
            except WazuhError as exc:
                row["source_health"] = "unavailable"
                row["source_error"] = str(exc)
                if same_binding:
                    row["telemetry"] = old.get("telemetry") or {}
        row.update(evaluate_monitoring(row, now=collected_at))
    bound_rows = [r for r in rows if r.get("binding_id")]
    outcome = (
        "failed"
        if error
        else (
            "partial"
            if (
                not bound_rows
                or any(
                    r["source_health"] != "healthy" or not r["identity_verified"]
                    for r in bound_rows
                )
            )
            else "succeeded"
        )
    )
    finish_monitoring_collection(client_name, actor, run_id, bound_rows, outcome, error)
    evidence_ids = ingest_wazuh_evidence(client_name, actor, collection_context)
    return dict(run_id=run_id, outcome=outcome, evidence_ids=evidence_ids, rows=rows)
