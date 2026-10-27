"""Bridge existing persisted Wazuh facts; no additional connector or raw source model."""

import hashlib
import json
from datetime import timedelta

from psycopg2.extras import RealDictCursor

from securescope.evidence.automated_checks import AutomatedCheck
from securescope.integrations.wazuh_monitoring import evaluate_monitoring, observation_time
from securescope.persistence.db_service import connect
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    _client_id,
    create_evidence_record,
    get_workspace_role,
)

CHECKS = {
    "logging": AutomatedCheck(
        "wazuh.logging.coverage",
        "Wazuh Log Source Coverage",
        "supports",
        ("A.8.15",),
        ("Log source coverage",),
        "A timestamped security event was received from this exact inventory asset.",
        provider="wazuh",
    ),
    "monitoring": AutomatedCheck(
        "wazuh.monitoring.coverage",
        "Wazuh Monitoring Coverage",
        "supports",
        ("A.8.16",),
        ("Monitoring coverage",),
        "The bound asset has recent authenticated telemetry and a current agent heartbeat.",
        provider="wazuh",
    ),
    "clock": AutomatedCheck(
        "wazuh.clock.synchronization",
        "Wazuh Clock Synchronization",
        "supports",
        ("A.8.17",),
        ("Clock synchronization",),
        "An explicit clock observation reports synchronization; agent presence "
        "alone is insufficient.",
        provider="wazuh",
    ),
}


def load_source(cursor, client_id, kind, record_id):
    """Read one tenant-owned, exact-IP-matched persisted source under a row lock.

    Args:
        cursor: Active transaction cursor.
        client_id: Tenant identifier.
        kind: logging, monitoring or clock.
        record_id: Existing source row ID.
    Returns:
        Canonical source row or None for absent/ambiguous data.
    Raises:
        EvidenceRepositoryError: For an unsupported check.
    """
    if kind not in CHECKS:
        raise EvidenceRepositoryError("Unsupported Wazuh check.")
    if kind == "clock":
        cursor.execute(
            "SELECT s.*,a.id AS asset_id,a.asset_tag,a.ip FROM securescope_clock_evidence s "
            "JOIN securescope_assets a ON a.client_id=s.client_id AND a.ip=s.asset_ip "
            "WHERE s.client_id=%s AND s.id=%s FOR SHARE OF s",
            (client_id, record_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    from securescope.persistence.db_wazuh_service import load_monitoring_rows

    row = next((r for r in load_monitoring_rows(cursor, client_id) if r["id"] == record_id), None)
    if not row or row.get("m2_collection") or row.get("monitoring_state") != "verified":
        return None
    cursor.execute(
        "SELECT payload FROM securescope_wazuh_observations "
        "WHERE client_id=%s AND id=%s FOR SHARE",
        (client_id, record_id),
    )
    stored = cursor.fetchone()
    if not stored:
        return None
    digest = hashlib.sha256(
        json.dumps(stored["payload"], sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    if digest != row["payload_sha256"]:
        raise EvidenceRepositoryError("Wazuh source snapshot integrity check failed.")
    row["ip"] = row["asset_ip"]
    return row


def normalized_source(row, kind, *, now=None):
    """Normalize independent factual checks without inferring other control results.

    Args:
        row: Canonical persisted API/clock source with numeric asset ID.
        kind: Allowlisted check name.
    Returns:
        (Normalized payload, observation timestamp), or None for unknown facts.
    Raises:
        KeyError: For malformed internal source data.
    """
    asset_id = int(row["asset_id"])
    if kind == "clock":
        payload = row.get("payload") or {}
        if payload.get("clock_evidence_source") != "Wazuh endpoint command" or not row.get(
            "wazuh_agent_id"
        ):
            return None
        if row.get("status") not in {"Synchronized", "Not synchronized", "Out of tolerance"}:
            return None
        positive = row["status"] == "Synchronized"
        timestamp = row.get("observed_at")
    else:
        status = evaluate_monitoring(row, now=now)
        if status["monitoring_state"] != "verified":
            return None
        if kind == "logging" and (row.get("telemetry") or {}).get("kind") != "security_event":
            return None
        positive = True
        timestamp = observation_time(row["telemetry"]["observed_at"])
    if not timestamp:
        return None
    check = CHECKS[kind].to_dict()
    check["effect"] = "supports" if positive else "gap"
    if kind != "clock":
        check["check_version"] = 2
    return {
        "tool_id": "wazuh",
        "format_name": "persisted-api-facts",
        "observations": [],
        "metadata": {
            "automated_checks": [check],
            **(
                {
                    "monitoring_snapshot": json.loads(
                        json.dumps(
                            {
                                k: v
                                for k, v in row.items()
                                if k
                                not in {
                                    "payload",
                                    "raw",
                                    "id",
                                    "source_key",
                                    "payload_sha256",
                                    "artifact_id",
                                }
                            },
                            default=str,
                        )
                    ),
                    "monitoring_contract_version": 2,
                }
                if kind != "clock"
                else {}
            ),
            "assurance": {
                kind: {
                    "evaluated_asset_ids": [asset_id],
                    "satisfied_asset_ids": [asset_id] if positive else [],
                }
            },
            "provenance": {
                "asset_id": asset_id,
                "asset_tag": row.get("asset_tag"),
                "source_record_id": row["id"],
                "check": kind,
                "payload_sha256": row.get("payload_sha256"),
                "binding_id": row.get("binding_id"),
                "source_event_id": (row.get("telemetry") or {}).get("source_event_id"),
            },
        },
    }, timestamp


def ingest_wazuh_evidence(client_name, actor, collection_context=None):
    """Create canonical evidence from existing connector snapshots for an authorized member.

    Args:
        client_name: Workspace receiving its own matched asset evidence.
        actor: Authenticated member requesting collection.
        collection_context: Optional originating requirement in this workspace.
    Returns:
        List of existing or newly created canonical evidence IDs.
    Raises:
        EvidenceRepositoryError: For unauthorized access or invalid persistence.
    """
    if get_workspace_role(client_name, actor) not in {"Administrator", "Consultant"}:
        raise EvidenceRepositoryError("Wazuh collection requires a Consultant or Administrator.")
    context = dict(collection_context or {})
    if context and context.get("client") != client_name:
        raise EvidenceRepositoryError("Collection origin belongs to another workspace.")
    ids = []
    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            client_id = _client_id(cursor, client_name)
            for kind in CHECKS:
                if kind == "clock":
                    cursor.execute("SELECT to_regclass('securescope_clock_evidence') AS name")
                    if not cursor.fetchone()["name"]:
                        continue
                    cursor.execute(
                        "SELECT DISTINCT ON (asset_ip) id FROM securescope_clock_evidence "
                        "WHERE client_id=%s ORDER BY asset_ip,collected_at DESC,id DESC",
                        (client_id,),
                    )
                    record_ids = [r["id"] for r in cursor.fetchall()]
                else:
                    from securescope.persistence.db_wazuh_service import load_monitoring_rows

                    record_ids = [
                        r["id"]
                        for r in load_monitoring_rows(cursor, client_id)
                        if r["monitoring_state"] == "verified"
                    ]
                for record_id in record_ids:
                    row = load_source(cursor, client_id, kind, record_id)
                    if (
                        context.get("asset_ids")
                        and row
                        and row["asset_id"] not in context["asset_ids"]
                    ):
                        continue
                    normalized = normalized_source(row, kind) if row else None
                    if not normalized:
                        continue
                    payload, timestamp = normalized
                    check = payload["metadata"]["automated_checks"][0]
                    ids.append(
                        create_evidence_record(
                            client_name,
                            tool_id="wazuh",
                            collection_method="Authenticated API",
                            evidence_type="Automated technical evidence",
                            title=check["display_name"],
                            summary=check["explanation"],
                            scope_description="Canonical asset scope membership",
                            source_asset_or_system=row["ip"],
                            owner=actor,
                            submitted_by="system:wazuh-connector",
                            collected_at=timestamp,
                            expires_at=(
                                timestamp + timedelta(days=90)
                                if kind == "clock"
                                else evaluate_monitoring(row)["verified_until"]
                            ),
                            confidence="Medium",
                            normalized=payload,
                            suggested_controls=check["mapped_controls"],
                            system_source={
                                "provider": "wazuh",
                                "kind": kind,
                                "record_id": record_id,
                                "requested_by": actor,
                                "collection_context": context,
                            },
                        )
                    )
    return ids
