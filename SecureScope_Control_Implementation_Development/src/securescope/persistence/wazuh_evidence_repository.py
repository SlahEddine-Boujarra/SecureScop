"""Fenced M2 source history and exact-context canonical evidence associations."""

import hashlib
import json

from psycopg2.extras import Json, RealDictCursor

from securescope.evidence.storage import read_artifact, store_protected_artifact
from securescope.integrations.wazuh_collection_health import CollectionFailure, policy_hash
from securescope.integrations.wazuh_monitoring import evaluate_monitoring
from securescope.persistence import evidence_schedule_repository as schedules
from securescope.persistence.db_service import connect


def canonical_bytes(value):
    """Return deterministic UTF-8 JSON bytes; raise TypeError for unsupported JSON keys."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def target_context(cursor, job, target_id):
    """Return a fenced current target/binding; raise ScheduleError for foreign or obsolete IDs."""
    schedules.fence(cursor, job)
    cursor.execute(
        "SELECT * FROM securescope_evidence_schedule_targets "
        "WHERE client_id=%s AND schedule_id=%s AND id=%s",
        (job["client_id"], job["schedule_id"], target_id),
    )
    row = cursor.fetchone()
    if not row:
        raise schedules.ScheduleError("Target does not belong to this job.")
    target = dict(row)
    return target, schedules.validate_target(cursor, job["client_id"], target, job["connector_id"])


def status(job, target_id, *, acquisition, ingestion, error_code="", observation_id=None):
    """Persist current target outcomes under a live fence; raise LeaseLost on stale ownership."""
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        schedules.fence(cur, job, authorize=False)
        cur.execute(
            "INSERT INTO securescope_evidence_target_attempts "
            "(client_id,attempt_id,target_id,acquisition,ingestion,error_code,observation_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(client_id,attempt_id,target_id) "
            "DO UPDATE SET acquisition=EXCLUDED.acquisition,ingestion=EXCLUDED.ingestion,"
            "error_code=EXCLUDED.error_code,observation_id=EXCLUDED.observation_id",
            (
                job["client_id"],
                job["attempt_id"],
                target_id,
                acquisition,
                ingestion,
                error_code,
                observation_id,
            ),
        )


def load_source(cursor, client_id, source):
    """Load exact persisted M2 facts and verify protected bytes in the publication transaction.

    Args:
        cursor: Canonical write transaction; client_id: Tenant; source: Internal job identity.
    Returns:
        Historical observation with original collection time and trusted artifact ID, or None.
    Raises:
        ScheduleError: On invalid context; EvidenceStorageError: On missing/tampered bytes.
    """
    job = source["scheduled_job"]
    if job["client_id"] != client_id or source["kind"] not in {"logging", "monitoring"}:
        raise schedules.ScheduleError("Invalid scheduled source identity.")
    target, binding = target_context(cursor, job, source["target_id"])
    if source["kind"] != ("logging" if target["control_id"] == "A.8.15" else "monitoring"):
        raise schedules.ScheduleError("Check does not match the pinned control.")
    cursor.execute(
        "SELECT x.*,o.payload,o.payload_sha256,o.source_key,a.storage_reference,"
        "a.sha256,a.encrypted FROM securescope_wazuh_job_sources x "
        "JOIN securescope_wazuh_observations o ON o.client_id=x.client_id AND o.id=x.observation_id "
        "JOIN securescope_evidence_artifacts a ON a.client_id=x.client_id AND a.id=x.artifact_id "
        "WHERE x.client_id=%s AND x.job_id=%s AND x.target_id=%s",
        (client_id, job["id"], target["id"]),
    )
    stored = cursor.fetchone()
    if not stored:
        return None
    if hashlib.sha256(canonical_bytes(stored["payload"])).hexdigest() != stored["payload_sha256"]:
        raise schedules.ScheduleError("Observation integrity mismatch.")
    if not stored["encrypted"] or stored["policy_sha256"].strip() != policy_hash(
        target["health_policy"]
    ):
        raise schedules.ScheduleError("Protected policy provenance is required.")
    read_artifact(client_id, stored["storage_reference"], expected_sha256=stored["sha256"])
    row = dict(
        stored["payload"],
        id=stored["observation_id"],
        source_key=stored["source_key"],
        payload_sha256=stored["payload_sha256"],
        collected_at=stored["collected_at"],
        artifact_id=stored["artifact_id"],
    )
    if (
        row["asset_id"] != target["asset_id"]
        or row["binding_id"] != target["binding_id"]
        or row["connector_id"] != job["connector_id"]
        or row["manager_name"] != binding["manager_name"]
        or row["wazuh_agent_id"] != binding["agent_id"]
    ):
        raise schedules.ScheduleError("Persisted source identity changed.")
    if row.get("telemetry", {}).get("kind") == "collection_health" and not target["accept_health"]:
        raise schedules.ScheduleError("Health proof is not approved for this target.")
    return row


def existing_source(job, target):
    """Return the exact recoverable source for this job/target; never select a newer observation."""
    source = dict(
        scheduled_job=job,
        target_id=target["id"],
        kind="logging" if target["control_id"] == "A.8.15" else "monitoring",
    )
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        return load_source(cur, job["client_id"], source)


def save_source(job, target, row, *, error_code=""):
    """Append observations, runs and protected source provenance in one fenced transaction.

    Args:
        job: Claimed lease; target: Frozen target; row: Allowlisted authenticated facts.
        error_code: Safe acquisition failure category; failures retain history without a resume source.
    Returns:
        Observation ID. Publication is a separate recoverable stage.
    Raises:
        LeaseLost, ScheduleError: On stale authorization; CollectionFailure: On replay.
        EvidenceStorageError: If required protection fails; DatabaseError: On rollback.
    """
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
            "id",
            "source_key",
            "payload_sha256",
            "artifact_id",
        }
    }
    payload = json.loads(canonical_bytes(payload))
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        current, binding = target_context(cur, job, target["id"])
        if any(
            payload.get(k) != value
            for k, value in {
                "asset_id": current["asset_id"],
                "binding_id": binding["id"],
                "wazuh_agent_id": binding["agent_id"],
                "manager_name": binding["manager_name"],
                "connector_id": binding["connector_id"],
            }.items()
        ):
            raise schedules.ScheduleError("Collected source is not the approved binding.")
        telemetry = payload.get("telemetry") or {}
        if telemetry.get("kind") == "collection_health":
            if not current["accept_health"] or telemetry.get("policy_sha256") != policy_hash(
                current["health_policy"]
            ):
                raise schedules.ScheduleError("Unapproved health policy.")
            if telemetry.get("mode") == "canary":
                cur.execute(
                    "SELECT payload->'telemetry' AS telemetry FROM securescope_wazuh_observations "
                    "WHERE client_id=%s AND binding_id=%s AND payload->'telemetry'->>'policy_sha256'=%s "
                    "AND payload->'telemetry'->>'source_event_id'=%s LIMIT 1",
                    (
                        job["client_id"],
                        binding["id"],
                        telemetry["policy_sha256"],
                        telemetry["source_event_id"],
                    ),
                )
                same_event = cur.fetchone()
                if same_event and any(
                    telemetry.get(k) != same_event["telemetry"].get(k)
                    for k in ("sequence", "observed_at")
                ):
                    raise CollectionFailure("canary_replay")
                cur.execute(
                    "SELECT payload->'telemetry' AS telemetry FROM securescope_wazuh_observations "
                    "WHERE client_id=%s AND binding_id=%s AND payload->'telemetry'->>'policy_sha256'=%s "
                    "AND payload->'telemetry'->>'mode'='canary' ORDER BY id DESC LIMIT 1",
                    (job["client_id"], binding["id"], telemetry["policy_sha256"]),
                )
                previous = cur.fetchone()
                old = previous["telemetry"] if previous else {}
                if old and (
                    telemetry["sequence"] < old["sequence"]
                    or (
                        telemetry["sequence"] == old["sequence"]
                        and any(
                            telemetry.get(k) != old.get(k)
                            for k in ("source_event_id", "observed_at")
                        )
                    )
                ):
                    raise CollectionFailure("canary_replay")
        cur.execute(
            "INSERT INTO securescope_wazuh_observations "
            "(client_id,binding_id,asset_id,source_key,payload_sha256,payload) "
            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                job["client_id"],
                binding["id"],
                binding["asset_id"],
                f'm2:{binding["id"]}:{digest}',
                digest,
                Json(payload),
            ),
        )
        cur.execute(
            "SELECT id FROM securescope_wazuh_observations WHERE client_id=%s AND source_key=%s",
            (job["client_id"], f'm2:{binding["id"]}:{digest}'),
        )
        observation_id = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO securescope_wazuh_collection_runs "
            "(client_id,connector_id,requested_by,started_at,completed_at,outcome,error_code) "
            "VALUES (%s,%s,%s,%s,NOW(),%s,%s) RETURNING id",
            (
                job["client_id"],
                job["connector_id"],
                job["requested_by"],
                row["collected_at"],
                "failed" if error_code else "succeeded",
                error_code,
            ),
        )
        run_id = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO securescope_wazuh_run_assets VALUES (%s,%s,%s,%s)",
            (job["client_id"], run_id, observation_id, binding["asset_id"]),
        )
        cur.execute(
            "INSERT INTO securescope_wazuh_attempt_runs VALUES (%s,%s,%s)",
            (job["client_id"], job["attempt_id"], run_id),
        )
        if not error_code:
            package = dict(
                format="securescope-wazuh-source-subset-v1",
                facts=payload,
                provenance=dict(
                    client_id=job["client_id"],
                    connector_id=job["connector_id"],
                    job_id=job["id"],
                    attempt_id=job["attempt_id"],
                    run_id=run_id,
                    target_id=current["id"],
                    collected_at=row["collected_at"],
                    observation_sha256=digest,
                    health_policy=current["health_policy"],
                    redaction="Allowlisted normalized source facts; no credentials or full log capture.",
                ),
            )
            artifact = store_protected_artifact(
                job["client_id"], "wazuh-source.json", canonical_bytes(package)
            )
            # A transaction failure leaves only an inaccessible orphan; never a dangling canonical record.
            cur.execute(
                "INSERT INTO securescope_evidence_artifacts "
                "(client_id,artifact_uuid,original_filename,storage_reference,media_type,byte_size,sha256,encrypted,created_by) "
                "VALUES (%s,%s,%s,%s,'application/json',%s,%s,TRUE,%s) RETURNING id",
                (
                    job["client_id"],
                    artifact.artifact_uuid,
                    artifact.original_filename,
                    artifact.storage_reference,
                    artifact.byte_size,
                    artifact.sha256,
                    job["worker_name"],
                ),
            )
            artifact_id = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO securescope_wazuh_job_sources "
                "(client_id,job_id,target_id,observation_id,run_id,collected_at,artifact_id,policy_sha256) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    job["client_id"],
                    job["id"],
                    current["id"],
                    observation_id,
                    run_id,
                    row["collected_at"],
                    artifact_id,
                    policy_hash(current["health_policy"]),
                ),
            )
        schedules._audit(
            cur,
            job["client_id"],
            job["worker_name"],
            "Wazuh source retained",
            job["schedule_id"],
            dict(job_id=job["id"], observation_id=observation_id, error_code=error_code),
        )
        schedules.fence(cur, job)
        return observation_id


def link_source(cursor, client_id, evidence_id, source):
    """Associate only the explicitly approved target; raise ScheduleError on a mid-run change."""
    from securescope.persistence.evidence_repository import _insert_evidence_scope_link

    job = source["scheduled_job"]
    target, _ = target_context(cursor, job, source["target_id"])
    cursor.execute(
        "INSERT INTO securescope_evidence_control_mappings "
        "(client_id,evidence_id,control_id,mapping_origin,evidence_dimension,rationale) "
        "SELECT %s,%s,%s,'Automated check','Implementation','Pinned scheduled requirement' "
        "WHERE NOT EXISTS (SELECT 1 FROM securescope_evidence_control_mappings "
        "WHERE client_id=%s AND evidence_id=%s AND control_id=%s AND mapping_origin='Automated check') "
        "ON CONFLICT DO NOTHING",
        (
            client_id,
            evidence_id,
            target["control_id"],
            client_id,
            evidence_id,
            target["control_id"],
        ),
    )
    _insert_evidence_scope_link(
        cursor,
        client_id,
        target["engagement_id"],
        target["scope_id"],
        evidence_id,
        job["requested_by"],
        "Approved recurring collection target",
        origin="Automated collection",
    )
    cursor.execute(
        "SELECT id FROM securescope_engagement_record_links WHERE client_id=%s "
        "AND engagement_id=%s AND link_key=%s",
        (
            client_id,
            target["engagement_id"],
            f'assurance-evidence:{target["scope_id"]}:{evidence_id}',
        ),
    )
    link_id = cursor.fetchone()["id"]
    cursor.execute(
        "INSERT INTO securescope_evidence_association_provenance "
        "(client_id,evidence_id,target_id,job_id,scope_link_id) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
        (client_id, evidence_id, target["id"], job["id"], link_id),
    )
    cursor.execute(
        "INSERT INTO securescope_evidence_job_results VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
        (client_id, job["id"], target["id"], evidence_id),
    )


def annotate_currency(cursor, client_id, row, engagement_id, scope_id):
    """Set exact current requirement eligibility without rewriting historical evidence.

    Args:
        cursor: Read cursor; client_id: Tenant; row: Canonical evidence; engagement_id, scope_id: View.
    Returns:
        None; updates computed source status and eligible_requirement_ids.
    Raises:
        DatabaseError: On failed provenance lookup.
    """
    from securescope.integrations.wazuh_service import configured_connector_id

    metadata = row["normalized_payload"]["metadata"]
    snapshot = metadata["monitoring_snapshot"]
    eligible = []
    cursor.execute(
        "SELECT t.*,s.connector_id FROM securescope_evidence_association_provenance p "
        "JOIN securescope_evidence_schedule_targets t ON t.client_id=p.client_id AND t.id=p.target_id "
        "JOIN securescope_evidence_schedules s ON s.client_id=t.client_id AND s.id=t.schedule_id "
        "WHERE p.client_id=%s AND p.evidence_id=%s AND NOT EXISTS "
        "(SELECT 1 FROM securescope_evidence_schedules newer WHERE newer.client_id=s.client_id "
        "AND newer.schedule_uuid=s.schedule_uuid AND newer.revision>s.revision)",
        (client_id, row["id"]),
    )
    targets = [dict(t) for t in cursor.fetchall()]
    for target in targets:
        if (
            (scope_id and scope_id != target["scope_id"])
            or (engagement_id and engagement_id != target["engagement_id"])
            or target["connector_id"] != configured_connector_id()
        ):
            continue
        try:
            schedules.validate_target(cursor, client_id, target, target["connector_id"])
        except schedules.ScheduleError:
            continue
        cursor.execute(
            "SELECT x.observation_id FROM securescope_wazuh_job_sources x "
            "WHERE x.client_id=%s AND x.target_id=%s ORDER BY x.collected_at DESC,x.job_id DESC LIMIT 1",
            (client_id, target["id"]),
        )
        latest = cursor.fetchone()
        if not latest or latest["observation_id"] != metadata["provenance"]["source_record_id"]:
            continue
        cursor.execute(
            "SELECT a.acquisition,a.ingestion FROM securescope_evidence_target_attempts a "
            "JOIN securescope_evidence_job_attempts j ON j.client_id=a.client_id AND j.id=a.attempt_id "
            "WHERE a.client_id=%s AND a.target_id=%s ORDER BY j.started_at DESC,a.id DESC LIMIT 1",
            (client_id, target["id"]),
        )
        last_attempt = cursor.fetchone()
        if last_attempt and (
            last_attempt["acquisition"] == "failed" or last_attempt["ingestion"] == "failed"
        ):
            continue
        if evaluate_monitoring(snapshot)["monitoring_state"] == "verified":
            eligible.append(target["requirement_id"])
    row["eligible_requirement_ids"] = sorted(set(eligible))
    row["source_verification_current"] = bool(eligible)
    if not eligible:
        row["source_review_reason"] = (
            "Pinned source or approved requirement context is no longer current."
        )
