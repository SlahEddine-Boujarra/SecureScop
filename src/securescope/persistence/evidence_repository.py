"""Workspace-aware PostgreSQL repository for the ISO Evidence Hub."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence

from psycopg2.extras import Json, RealDictCursor

from securescope.evidence.models import NormalizedEvidence, ReviewDecision
from securescope.evidence.storage import StoredArtifact
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


class EvidenceRepositoryError(RuntimeError):
    """Raised when workspace evidence cannot be persisted safely."""


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve an existing workspace inside the active transaction."""

    cursor.execute(
        "SELECT id FROM securescope_clients WHERE name = %s;",
        (str(client_name).strip(),),
    )
    row = cursor.fetchone()
    if not row:
        raise EvidenceRepositoryError(f"Client workspace not found: {client_name}")
    return int(row["id"] if isinstance(row, dict) else row[0])


def _append_audit_event(
    cursor: Any,
    client_id: int,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor: str,
    summary: str,
    payload: Mapping[str, Any] | None = None,
) -> None:
    """Append one hash-chained event; this repository exposes no update operation."""

    cursor.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"evidence-audit:{client_id}",)
    )
    cursor.execute(
        """
        SELECT event_hash
        FROM securescope_evidence_audit_events
        WHERE client_id = %s
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE;
        """,
        (client_id,),
    )
    previous = cursor.fetchone()
    previous_hash = (
        str(previous["event_hash"] if isinstance(previous, dict) else previous[0])
        if previous
        else ""
    )
    event_payload = dict(payload or {})
    canonical = json.dumps(
        {
            "previous": previous_hash,
            "event_type": event_type,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "actor": actor,
            "summary": summary,
            "payload": event_payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    cursor.execute(
        """
        INSERT INTO securescope_evidence_audit_events (
            client_id, event_uuid, event_type, entity_type, entity_id,
            actor, summary, event_payload, previous_event_hash, event_hash
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (
            client_id,
            str(uuid.uuid4()),
            event_type,
            entity_type,
            entity_id,
            actor,
            summary,
            Json(event_payload),
            previous_hash or None,
            event_hash,
        ),
    )


def _insert_evidence_scope_link(
    cursor: Any,
    client_id: int,
    engagement_id: int,
    scope_id: int,
    evidence_id: int,
    actor: str,
    rationale: str,
    *,
    origin: str = "Manual association",
) -> None:
    """Insert an explicit scope association in the caller's validated transaction.

    Args:
        cursor: Transaction cursor after membership and ownership validation.
        client_id: Client owning the evidence and scope.
        engagement_id: Engagement owning the scope.
        scope_id: Canonical ISMS Scope identifier.
        evidence_id: Canonical evidence identifier.
        actor: Authenticated submitting or associating principal.
        rationale: Submitted scope description or explicit association rationale.
        origin: Existing manual or automated association provenance.
    Returns:
        None.
    Raises:
        DatabaseError: If persistence fails; the caller rolls back the transaction.
    """
    cursor.execute(
        "INSERT INTO securescope_engagement_record_links "
        "(client_id,engagement_id,scope_id,link_key,evidence_id,link_origin,rationale,linked_by) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (client_id,engagement_id,link_key) DO NOTHING",
        (
            client_id,
            engagement_id,
            scope_id,
            f"assurance-evidence:{scope_id}:{evidence_id}",
            evidence_id,
            origin,
            rationale,
            actor,
        ),
    )


def create_evidence_record(
    client_name: str,
    *,
    tool_id: str,
    collection_method: str,
    evidence_type: str,
    title: str,
    summary: str,
    scope_description: str,
    source_asset_or_system: str,
    owner: str,
    submitted_by: str,
    collected_at: datetime,
    expires_at: datetime | None,
    confidence: str,
    normalized: NormalizedEvidence | Mapping[str, Any],
    suggested_controls: Sequence[str],
    artifact: StoredArtifact | None = None,
    engagement_id: int | None = None,
    scope_id: int | None = None,
    system_source: Mapping[str, Any] | None = None,
    artifact_factory: Callable[[int], StoredArtifact] | None = None,
) -> int:
    """Create evidence, mappings and scope associations atomically.

    The optional engagement_id and scope_id must be supplied together and belong
    to the submitting member's client. Omitting both preserves client-wide legacy
    callers without guessing an ISMS Scope. Source text is never treated as an ID.

    system_source is reserved for the Nuclei worker: the repository locks and
    validates its canonical job, attempt and asset before system verification.
    A repeated source identity returns the existing record. Automated mappings
    do not receive human approval; scope links derive from configured assets.
    artifact_factory optionally defers system artifact storage until after the
    locked source-identity lookup, so retries do not create duplicate raw files.

    Returns:
        Canonical evidence record ID after the transaction commits.
    Raises:
        EvidenceRepositoryError: For invalid context, membership, input or storage.
    """

    run_pending_migrations()
    if artifact_factory and (system_source is None or artifact is not None):
        raise EvidenceRepositoryError("Deferred artifacts require a single verified system source.")
    required = (
        tool_id,
        collection_method,
        evidence_type,
        title,
        summary,
        scope_description,
        owner,
        submitted_by,
    )
    if not all(str(value).strip() for value in required):
        raise EvidenceRepositoryError("Evidence identity, scope, owner and submitter are required.")
    payload = (
        normalized.to_dict() if isinstance(normalized, NormalizedEvidence) else dict(normalized)
    )
    observation_count = len(payload.get("observations") or [])
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                source_key = None
                scheduled_artifact_id = None
                if system_source is not None:
                    if tool_id == "wazuh":
                        from securescope.evidence.wazuh_bridge import load_source, normalized_source
                        from securescope.persistence.foundation_repository import member_role

                        if (
                            collection_method != "Authenticated API"
                            or submitted_by != "system:wazuh-connector"
                            or member_role(cursor, client_id, system_source.get("requested_by", ""))
                            not in {"Administrator", "Consultant"}
                        ):
                            raise EvidenceRepositoryError("Unauthorized Wazuh source.")
                        kind = system_source.get("kind")
                        if system_source.get("scheduled_job"):
                            from securescope.persistence.wazuh_evidence_repository import (
                                load_source as load_scheduled,
                            )

                            persisted = load_scheduled(cursor, client_id, system_source)
                            scheduled_artifact_id = persisted["artifact_id"] if persisted else None
                        else:
                            persisted = load_source(
                                cursor, client_id, kind, system_source.get("record_id")
                            )
                        verified = normalized_source(persisted, kind) if persisted else None
                        if not verified or verified[0] != payload or verified[1] != collected_at:
                            raise EvidenceRepositoryError(
                                "Wazuh evidence must match its persisted source."
                            )
                        checks = payload["metadata"]["automated_checks"]
                        suggested_controls = [
                            c for check in checks for c in check["mapped_controls"]
                        ]
                        system_source = dict(
                            system_source,
                            asset_id=persisted["asset_id"],
                            checks=checks,
                            actor=submitted_by,
                        )
                        source_key = (
                            f"wazuh:{kind}:{persisted['id']}:{collected_at.isoformat()}"
                            if kind == "clock"
                            else f"wazuh:{kind}:{persisted['source_key']}"
                        )
                        if kind != "clock":
                            from securescope.integrations.wazuh_monitoring import (
                                evaluate_monitoring,
                            )

                            expires_at = evaluate_monitoring(persisted)["verified_until"]
                    else:
                        if (
                            tool_id != "nuclei"
                            or collection_method != "Existing worker"
                            or submitted_by != "system:nuclei-worker"
                        ):
                            raise EvidenceRepositoryError("Unsupported system evidence source.")
                        cursor.execute(
                            "SELECT j.id,j.asset_payload,j.created_at,a.id AS asset_id FROM "
                            "securescope_nuclei_jobs j "
                            "JOIN securescope_assets a ON a.client_id=j.client_id AND "
                            "a.ip=j.asset_ip "
                            "WHERE j.client_id=%s AND j.job_uuid=%s AND j.attempt_number=%s "
                            "AND j.provider_status='Completed' AND "
                            "j.status IN ('Finalizing','Completed') "
                            "AND a.id=%s FOR UPDATE OF j",
                            (
                                client_id,
                                system_source["job_uuid"],
                                system_source["attempt_number"],
                                system_source["asset_id"],
                            ),
                        )
                        verified_job = cursor.fetchone()
                        if not verified_job:
                            raise EvidenceRepositoryError(
                                "A completed canonical Nuclei job and asset are required."
                            )
                        system_source = dict(system_source)
                        system_source["collection_context"] = (
                            verified_job.get("asset_payload") or {}
                        ).get("evidence_collection_context", {})
                        system_source["target_snapshot"] = (
                            verified_job.get("asset_payload") or {}
                        ).get("m3_requirement_targets")
                        system_source["job_created_at"] = verified_job.get("created_at")
                        source_key = (
                            f"nuclei:{system_source['job_uuid']}:"
                            f"attempt:{system_source['attempt_number']}"
                        )
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                        (f"{client_id}:{source_key}",),
                    )
                    cursor.execute(
                        "SELECT id FROM securescope_evidence_records WHERE "
                        "client_id=%s AND tool_id=%s AND source_key=%s",
                        (client_id, tool_id, source_key),
                    )
                    existing = cursor.fetchone()
                    if existing:
                        if tool_id != "nuclei":
                            _link_system_evidence(
                                cursor,
                                client_id,
                                int(existing["id"]),
                                system_source,
                                suggested_controls,
                            )
                        if system_source.get("scheduled_job"):
                            from securescope.persistence.evidence_schedule_repository import fence

                            fence(cursor, system_source["scheduled_job"])
                        return int(existing["id"])
                if (engagement_id is None) != (scope_id is None):
                    raise EvidenceRepositoryError("Select both an engagement and an ISMS Scope.")
                if scope_id is not None:
                    from securescope.evidence.models import WorkspaceRole, role_can
                    from securescope.persistence.foundation_repository import member_role

                    membership = member_role(cursor, client_id, submitted_by)
                    if not membership or not role_can(WorkspaceRole(membership), "submit"):
                        raise EvidenceRepositoryError(
                            "Evidence submission requires workspace membership."
                        )
                    cursor.execute(
                        "SELECT id FROM securescope_scope_definitions WHERE client_id=%s "
                        "AND engagement_id=%s AND id=%s AND NOT archived FOR SHARE",
                        (client_id, engagement_id, scope_id),
                    )
                    if not cursor.fetchone():
                        raise EvidenceRepositoryError(
                            "Select a current ISMS Scope in this engagement."
                        )
                if system_source is not None:
                    cursor.execute(
                        "SELECT register_key,rows FROM securescope_working_registers "
                        "WHERE client_id=%s AND register_key IN "
                        "('evidence_defaults','tool_settings')",
                        (client_id,),
                    )
                    settings = {r["register_key"]: r["rows"] for r in cursor.fetchall()}
                    defaults = settings.get("evidence_defaults") or [{}]
                    source_settings = next(
                        (
                            r
                            for r in settings.get("tool_settings", [])
                            if r.get("tool_id") == tool_id
                        ),
                        {},
                    )
                    days = int(
                        source_settings.get("Freshness days")
                        or defaults[0].get("freshness_days")
                        or 90
                    )
                    if not 1 <= days <= 3650:
                        raise EvidenceRepositoryError(
                            "Configured freshness must be 1 to 3650 days."
                        )
                    default_expiry = collected_at + timedelta(days=days)
                    expires_at = min(expires_at, default_expiry) if expires_at else default_expiry
                if artifact_factory:
                    artifact = artifact_factory(client_id)
                artifact_id: int | None = scheduled_artifact_id
                if artifact:
                    cursor.execute(
                        """
                        INSERT INTO securescope_evidence_artifacts (
                            client_id, artifact_uuid, original_filename,
                            storage_reference, media_type, byte_size, sha256,
                            encrypted, created_by
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (
                            client_id,
                            artifact.artifact_uuid,
                            artifact.original_filename,
                            artifact.storage_reference,
                            "application/octet-stream",
                            artifact.byte_size,
                            artifact.sha256,
                            artifact.encrypted,
                            submitted_by,
                        ),
                    )
                    artifact_id = int(cursor.fetchone()["id"])
                evidence_uuid = str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO securescope_evidence_records (
                        client_id, evidence_uuid, artifact_id, tool_id,
                        collection_method, evidence_type, title, summary,
                        source_asset_or_system, scope_description,
                        normalized_payload, observation_count, collected_at,
                        expires_at, freshness_status, confidence, owner, submitted_by
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, 'Current', %s, %s, %s
                    ) RETURNING id;
                    """,
                    (
                        client_id,
                        evidence_uuid,
                        artifact_id,
                        tool_id,
                        collection_method,
                        evidence_type,
                        title,
                        summary,
                        source_asset_or_system,
                        scope_description,
                        Json(payload),
                        observation_count,
                        collected_at,
                        expires_at,
                        confidence,
                        owner,
                        submitted_by,
                    ),
                )
                evidence_id = int(cursor.fetchone()["id"])
                if system_source is not None:
                    cursor.execute(
                        "UPDATE securescope_evidence_records SET source_"
                        "key=%s, verification_origin='System collector', "
                        "validation_status='Validated', validator=%s, validated_at=NOW(), "
                        "validation_comment='System collection verified; no hu"
                        "man assurance decision.' WHERE id=%s AND client_id=%s",
                        (source_key, submitted_by, evidence_id, client_id),
                    )
                    if tool_id == "nuclei":
                        from securescope.persistence.requirement_evidence_repository import (
                            capture_source,
                        )

                        capture_source(cursor, client_id, evidence_id, system_source)
                        system_source["m3_attributed"] = True
                    _link_system_evidence(
                        cursor, client_id, evidence_id, system_source, suggested_controls
                    )
                if scope_id is not None:
                    _insert_evidence_scope_link(
                        cursor,
                        client_id,
                        engagement_id,
                        scope_id,
                        evidence_id,
                        submitted_by,
                        scope_description,
                    )
                for control_id in (
                    []
                    if system_source is not None
                    else sorted(
                        set(str(item).strip() for item in suggested_controls if str(item).strip())
                    )
                ):
                    cursor.execute(
                        """
                        INSERT INTO securescope_evidence_control_mappings (
                            client_id, evidence_id, control_id, mapping_origin,
                            evidence_dimension, rationale
                        ) VALUES (%s, %s, %s, 'Catalog suggestion', 'Implementation', %s)
                        ON CONFLICT (client_id, evidence_id, control_id, evidence_dimension)
                        DO NOTHING;
                        """,
                        (
                            client_id,
                            evidence_id,
                            control_id,
                            (
                                f"{tool_id}"
                                " is catalogued as supporting evidence; consultant review is "
                                "required."
                            ),
                        ),
                    )
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Evidence submitted",
                    entity_type="Evidence",
                    entity_id=str(evidence_id),
                    actor=submitted_by,
                    summary=(
                        "System verified technical collection; human assessment remains required."
                        if system_source
                        else f"Evidence submitted from {tool_id}; consultant validation pending."
                    ),
                    payload={
                        "source_key": source_key,
                        "system_source": {
                            k: v
                            for k, v in (system_source or {}).items()
                            if k not in {"scheduled_job", "job_created_at"}
                        },
                        "scheduled_job_id": (system_source or {})
                        .get("scheduled_job", {})
                        .get("id"),
                        "engagement_id": engagement_id,
                        "scope_id": scope_id,
                        "tool_id": tool_id,
                        "collection_method": collection_method,
                        "sha256": artifact.sha256 if artifact else None,
                        "suggested_controls": list(sorted(set(suggested_controls))),
                    },
                )
                if system_source and system_source.get("scheduled_job"):
                    from securescope.persistence.evidence_schedule_repository import fence

                    fence(cursor, system_source["scheduled_job"])
                return evidence_id
    except DatabaseError as exc:
        LOGGER.exception("Evidence submission transaction failed")
        raise EvidenceRepositoryError(str(exc)) from exc


def list_evidence_records(
    client_name: str,
    *,
    validation_status: str | None = None,
    limit: int = 500,
    scope_id: int | None = None,
    engagement_id: int | None = None,
) -> list[dict[str, Any]]:
    """List evidence and its control mappings for one workspace only."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT evidence.id, evidence.evidence_uuid, evidence.client_id,
                           evidence.tool_id, evidence.source_key, evidence.verification_origin,
                           evidence.normalized_payload,
                           evidence.collection_method, evidence.title, evidence.summary,
                           evidence.source_asset_or_system,
                           CASE WHEN evidence.verification_origin='System collector' THEN
                               COALESCE((SELECT string_agg(DISTINCT s.name, ', ')
                                 FROM securescope_engagement_record_links l
                                 JOIN securescope_scope_definitions s
                                   ON s.client_id=l.client_id AND s.id=l.scope_id
                                 WHERE l.client_id=evidence.client_id
                                   AND l.evidence_id=evidence.id), 'Unassigned')
                           ELSE evidence.scope_description END AS scope_description,
                           evidence.collected_at, evidence.expires_at, evidence.freshness_status,
                           evidence.validation_status, evidence.validator, evidence.validated_at,
                           evidence.artifact_id, evidence.observation_count, evidence.owner,
                           evidence.submitted_by, evidence.evidence_type, evidence.confidence,
                           evidence.validation_comment, evidence.created_at, evidence.updated_at,
                           artifact.original_filename, artifact.sha256,
                           artifact.byte_size, artifact.storage_reference,
                           COALESCE(mapping.controls, '[]'::jsonb) AS controls
                    FROM securescope_evidence_records evidence
                    LEFT JOIN securescope_evidence_artifacts artifact
                      ON artifact.client_id = evidence.client_id
                     AND artifact.id = evidence.artifact_id
                    LEFT JOIN LATERAL (
                        SELECT jsonb_agg(jsonb_build_object(
                            'control_id', item.control_id,
                            'dimension', item.evidence_dimension,
                            'approved', item.consultant_approved,
                            'mapping_origin', item.mapping_origin,
                            'rationale', item.rationale
                        ) ORDER BY item.control_id) AS controls
                        FROM securescope_evidence_control_mappings item
                        WHERE item.client_id = evidence.client_id
                          AND item.evidence_id = evidence.id
                    ) mapping ON TRUE
                    WHERE evidence.client_id = %s
                      AND (%s IS NULL OR evidence.validation_status = %s)
                      AND (%s IS NULL OR EXISTS (
                          SELECT 1 FROM securescope_engagement_record_links scope_link
                          WHERE scope_link.client_id=evidence.client_id
                            AND scope_link.evidence_id=evidence.id
                            AND scope_link.scope_id=%s
                            AND scope_link.engagement_id=%s
                            AND scope_link.link_origin <> 'Legacy backfill'
                      ))
                    ORDER BY evidence.collected_at DESC
                    LIMIT %s;
                    """,
                    (
                        client_id,
                        validation_status,
                        validation_status,
                        scope_id,
                        scope_id,
                        engagement_id,
                        max(1, min(limit, 5_000)),
                    ),
                )
                rows = [dict(row) for row in cursor.fetchall()]
                apply_evidence_currency(cursor, client_id, rows, engagement_id, scope_id)
                return rows
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def evidence_hub_summary(client_name: str) -> dict[str, Any]:
    """Return review, freshness, mapping and request metrics for one workspace."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE validation_status = 'Pending') AS pending,
                        COUNT(*) FILTER (WHERE validation_status = 'Validated') AS validated,
                        COUNT(*) FILTER (WHERE validation_status = 'Rejected') AS rejected,
                        COUNT(*) FILTER (WHERE collection_method = 'Manual evidence') AS manual,
                        COUNT(*) FILTER (WHERE collection_method <> 'Manual evidence') AS automated
                    FROM securescope_evidence_records
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                summary = dict(cursor.fetchone())
                cursor.execute(
                    "SELECT "
                    "e.id,e.collected_at,e.expires_at,e.freshness_status,"
                    "e.tool_id,e.verification_origin,"
                    "e.normalized_payload,COALESCE((SELECT jsonb_agg(jsonb_build_object("
                    "'control_id',m.control_id)) FROM securescope_evidence_control_mappings m "
                    "WHERE m.client_id=e.client_id AND m.evidence_id=e.id),"
                    "'[]'::jsonb) AS controls "
                    "FROM securescope_evidence_records e WHERE e.client_id=%s",
                    (client_id,),
                )
                currency_rows = [dict(row) for row in cursor.fetchall()]
                apply_evidence_currency(cursor, client_id, currency_rows)
                summary["expired"] = sum(
                    row["freshness_status"] == "Stale" for row in currency_rows
                )
                cursor.execute(
                    """
                    SELECT COUNT(DISTINCT control_id) AS mapped_controls
                    FROM securescope_evidence_control_mappings
                    WHERE client_id = %s AND consultant_approved = TRUE;
                    """,
                    (client_id,),
                )
                summary.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT COUNT(*) AS open_requests
                    FROM securescope_evidence_requests
                    WHERE client_id = %s AND status IN ('Open', 'Submitted');
                    """,
                    (client_id,),
                )
                summary.update(dict(cursor.fetchone()))
                return summary
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def review_evidence_record(
    client_name: str,
    evidence_id: int,
    *,
    decision: ReviewDecision | str,
    validator: str,
    comment: str,
    approved_controls: Sequence[str],
) -> None:
    """Record an explicit consultant decision and approved control mappings."""

    run_pending_migrations()
    try:
        resolved = (
            decision if isinstance(decision, ReviewDecision) else ReviewDecision(str(decision))
        )
    except ValueError as exc:
        raise EvidenceRepositoryError(f"Unsupported review decision: {decision}") from exc
    if not validator.strip() or not comment.strip():
        raise EvidenceRepositoryError("Consultant name and review comment are required.")
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT id, validation_status
                    FROM securescope_evidence_records
                    WHERE client_id = %s AND id = %s
                    FOR UPDATE;
                    """,
                    (client_id, int(evidence_id)),
                )
                row = cursor.fetchone()
                if not row:
                    raise EvidenceRepositoryError("Evidence is not part of the active workspace.")
                cursor.execute(
                    """
                    UPDATE securescope_evidence_records
                    SET validation_status = %s, validator = %s,
                        validation_comment = %s, validated_at = NOW(), updated_at = NOW()
                    WHERE client_id = %s AND id = %s;
                    """,
                    (
                        resolved.value,
                        validator.strip(),
                        comment.strip(),
                        client_id,
                        int(evidence_id),
                    ),
                )
                cursor.execute(
                    """
                    UPDATE securescope_evidence_control_mappings
                    SET consultant_approved = FALSE, approved_by = NULL, approved_at = NULL
                    WHERE client_id = %s AND evidence_id = %s;
                    """,
                    (client_id, int(evidence_id)),
                )
                if resolved is ReviewDecision.VALIDATED:
                    controls = sorted(
                        set(str(item).strip() for item in approved_controls if str(item).strip())
                    )
                    if not controls:
                        raise EvidenceRepositoryError(
                            "Validated evidence requires at least one approved control mapping."
                        )
                    for control_id in controls:
                        cursor.execute(
                            "INSERT INTO securescope_evidence_control_mappings "
                            "(client_id, evidence_id, control_id, mapping_origin, "
                            "evidence_dimension, rationale) "
                            "VALUES (%s, %s, %s, 'Consultant mapping', 'Implementation', %s) "
                            "ON CONFLICT (client_id, evidence_id, control_id, "
                            "evidence_dimension) DO NOTHING",
                            (client_id, int(evidence_id), control_id, comment.strip()),
                        )
                    cursor.execute(
                        """
                        UPDATE securescope_evidence_control_mappings
                        SET consultant_approved = TRUE, approved_by = %s, approved_at = NOW()
                        WHERE client_id = %s AND evidence_id = %s
                          AND control_id = ANY(%s);
                        """,
                        (validator.strip(), client_id, int(evidence_id), controls),
                    )
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Evidence reviewed",
                    entity_type="Evidence",
                    entity_id=str(evidence_id),
                    actor=validator.strip(),
                    summary=f"Consultant review decision: {resolved.value}.",
                    payload={
                        "comment": comment.strip(),
                        "approved_controls": list(approved_controls),
                    },
                )
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def create_evidence_request(
    client_name: str,
    *,
    control_id: str,
    title: str,
    requested_evidence: str,
    assigned_to: str,
    due_date: date,
    requested_by: str,
) -> int:
    """Create one manual/hybrid evidence request within a workspace."""

    run_pending_migrations()
    required = (control_id, title, requested_evidence, assigned_to, requested_by)
    if not all(str(value).strip() for value in required):
        raise EvidenceRepositoryError("Evidence request fields cannot be empty.")
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    INSERT INTO securescope_evidence_requests (
                        client_id, request_uuid, control_id, title,
                        requested_evidence, assigned_to, due_date, requested_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        control_id,
                        title.strip(),
                        requested_evidence.strip(),
                        assigned_to.strip(),
                        due_date,
                        requested_by.strip(),
                    ),
                )
                request_id = int(cursor.fetchone()["id"])
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Evidence requested",
                    entity_type="Evidence request",
                    entity_id=str(request_id),
                    actor=requested_by.strip(),
                    summary=f"Evidence requested for {control_id}.",
                    payload={"assigned_to": assigned_to.strip(), "due_date": due_date.isoformat()},
                )
                return request_id
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def list_evidence_requests(client_name: str) -> list[dict[str, Any]]:
    """List all manual evidence requests for one workspace."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT * FROM securescope_evidence_requests
                    WHERE client_id = %s
                    ORDER BY (status IN ('Open', 'Submitted')) DESC, due_date, created_at DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def update_evidence_request(
    client_name: str,
    request_id: int,
    *,
    actor: str,
    expected_status: str,
    status: str,
    assigned_to: str,
    due_date: date,
    response_evidence_id: int | None,
) -> None:
    """Update ownership, deadline or response while enforcing workspace roles.

    Args:
        client_name: Exact workspace.
        request_id: Existing request ID.
        actor: Configured member email.
        expected_status: Status read before editing.
        status: Requested workflow state.
        assigned_to: Responsible contributor email.
        due_date: Required delivery date.
        response_evidence_id: Optional evidence from the same workspace.
    Returns:
        None after an atomic update and audit event.
    Raises:
        EvidenceRepositoryError: On invalid permissions, stale state or evidence.
    """
    from securescope.evidence.models import role_can

    role = get_workspace_role(client_name, actor)
    reviewer = bool(role and role_can(role, "review"))
    if not reviewer and not (role and role_can(role, "submit")):
        raise EvidenceRepositoryError("Your workspace membership cannot update requests.")
    if (
        status not in {"Open", "Submitted", "Accepted", "Rejected", "Cancelled"}
        or not assigned_to.strip()
    ):
        raise EvidenceRepositoryError("Choose a valid status and assignee.")
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    (
                        "SELECT * FROM securescope_evidence_requests WHERE client_id = %s "
                        "AND id = %s FOR UPDATE"
                    ),
                    (client_id, request_id),
                )
                previous = cursor.fetchone()
                if not previous or previous["status"] != expected_status:
                    raise EvidenceRepositoryError(
                        "The request changed or is outside this workspace. Reload it."
                    )
                if not reviewer and (
                    previous["assigned_to"].strip().lower() != actor.lower()
                    or status != "Submitted"
                ):
                    raise EvidenceRepositoryError(
                        "Contributors can only submit responses to their assigned requests."
                    )
                if not reviewer:
                    assigned_to, due_date = previous["assigned_to"], previous["due_date"]
                if status in {"Submitted", "Accepted"} and response_evidence_id is None:
                    raise EvidenceRepositoryError("Link the response evidence first.")
                if response_evidence_id is not None:
                    cursor.execute(
                        "SELECT validation_status, expires_at FROM securescope_evidence_records "
                        "WHERE client_id = %s AND id = %s",
                        (client_id, response_evidence_id),
                    )
                    evidence = cursor.fetchone()
                    if not evidence:
                        raise EvidenceRepositoryError(
                            "Response evidence is outside this workspace."
                        )
                    if status == "Accepted" and evidence["validation_status"] != "Validated":
                        raise EvidenceRepositoryError(
                            "Validate the evidence before accepting the response."
                        )
                    if (
                        status == "Accepted"
                        and evidence.get("expires_at")
                        and evidence["expires_at"] <= datetime.now(timezone.utc)
                    ):
                        raise EvidenceRepositoryError("The response evidence has expired.")
                cursor.execute(
                    "UPDATE securescope_evidence_requests SET status = %s, assigned_to = %s, "
                    "due_date = %s, response_evidence_id = %s, closed_by = %s, updated_at = NOW() "
                    "WHERE client_id = %s AND id = %s",
                    (
                        status,
                        assigned_to.strip(),
                        due_date,
                        response_evidence_id,
                        actor if status in {"Accepted", "Rejected", "Cancelled"} else None,
                        client_id,
                        request_id,
                    ),
                )
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Evidence request updated",
                    entity_type="Evidence request",
                    entity_id=str(request_id),
                    actor=actor,
                    summary=f"Request moved to {status}",
                    payload={"status": status, "response_evidence_id": response_evidence_id},
                )
    except DatabaseError as exc:
        raise EvidenceRepositoryError("The request was not saved.") from exc


def list_evidence_audit_events(client_name: str, limit: int = 2_000) -> list[dict[str, Any]]:
    """List hash-chained evidence events for an auditor export."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT * FROM securescope_evidence_audit_events
                    WHERE client_id = %s ORDER BY id LIMIT %s;
                    """,
                    (client_id, max(1, min(limit, 10_000))),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def upsert_workspace_member(
    client_name: str,
    *,
    email: str,
    display_name: str,
    role: str,
    granted_by: str,
) -> int:
    """Create/update one user membership without crossing workspace boundaries."""

    run_pending_migrations()
    normalized_email = email.strip().lower()
    if not all((normalized_email, display_name.strip(), role.strip(), granted_by.strip())):
        raise EvidenceRepositoryError("Membership identity, role and grantor are required.")
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    INSERT INTO securescope_users (user_uuid, email, display_name)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (email) DO UPDATE
                    SET display_name = EXCLUDED.display_name, updated_at = NOW()
                    RETURNING id;
                    """,
                    (str(uuid.uuid4()), normalized_email, display_name.strip()),
                )
                user_id = int(cursor.fetchone()["id"])
                cursor.execute(
                    """
                    INSERT INTO securescope_workspace_memberships (
                        client_id, user_id, role, granted_by
                    ) VALUES (%s, %s, %s, %s)
                    ON CONFLICT (client_id, user_id) DO UPDATE
                    SET role = EXCLUDED.role, active = TRUE,
                        granted_by = EXCLUDED.granted_by, updated_at = NOW()
                    RETURNING id;
                    """,
                    (client_id, user_id, role.strip(), granted_by.strip()),
                )
                membership_id = int(cursor.fetchone()["id"])
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Membership changed",
                    entity_type="Membership",
                    entity_id=str(membership_id),
                    actor=granted_by.strip(),
                    summary=f"Workspace role set to {role.strip()}.",
                    payload={"email": normalized_email, "role": role.strip()},
                )
                return membership_id
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def get_workspace_role(client_name: str, email: str) -> str | None:
    """Resolve an active role using both client_id and normalized email."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT membership.role
                    FROM securescope_workspace_memberships membership
                    JOIN securescope_users app_user ON app_user.id = membership.user_id
                    WHERE membership.client_id = %s
                      AND app_user.email = %s
                      AND membership.active = TRUE AND app_user.active = TRUE;
                    """,
                    (client_id, email.strip().lower()),
                )
                row = cursor.fetchone()
                return str(row["role"]) if row else None
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def enqueue_evidence_job(
    client_name: str,
    *,
    tool_id: str,
    target: str,
    profile: str,
    requested_by: str,
    timeout_seconds: int = 1800,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> str:
    """Add one workspace-owned defensive collector job to the persistent queue."""

    from securescope.evidence.tool_catalog import ExecutionPolicy, get_tool

    run_pending_migrations()
    tool = get_tool(tool_id)
    if tool.execution_policy is not ExecutionPolicy.DEFENSIVE_ONLY:
        raise EvidenceRepositoryError(
            f"{tool.name} cannot be queued in the defensive collector worker."
        )
    if not target.strip() or not requested_by.strip():
        raise EvidenceRepositoryError("Collector target and requester are required.")
    job_uuid = str(uuid.uuid4())
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    INSERT INTO securescope_evidence_jobs (
                        client_id, job_uuid, tool_id, job_type,
                        request_payload, requested_by
                    ) VALUES (%s, %s, %s, 'Collect', %s, %s);
                    """,
                    (
                        client_id,
                        job_uuid,
                        tool_id,
                        Json(
                            {
                                "target": target.strip(),
                                "profile": profile.strip(),
                                "timeout_seconds": int(timeout_seconds),
                                "engagement_id": engagement_id,
                                "scope_id": scope_id,
                            }
                        ),
                        requested_by.strip(),
                    ),
                )
                _append_audit_event(
                    cursor,
                    client_id,
                    event_type="Collector queued",
                    entity_type="Evidence job",
                    entity_id=job_uuid,
                    actor=requested_by.strip(),
                    summary=f"Defensive {tool.name} collection queued.",
                    payload={"tool_id": tool_id},
                )
                return job_uuid
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def claim_evidence_job(
    worker_name: str, *, schema_initialized: bool = False
) -> dict[str, Any] | None:
    """Claim one available job using PostgreSQL SKIP LOCKED semantics.

    Args:
        worker_name: Non-empty worker identity recorded on the claimed job.
        schema_initialized: True only after this worker ran startup migrations.
    Returns:
        Claimed job or None when no eligible job is queued.
    Raises:
        EvidenceRepositoryError: For invalid identity or persistence failure.
    """

    if not schema_initialized:
        run_pending_migrations()
    if not worker_name.strip():
        raise EvidenceRepositoryError("Worker name cannot be empty.")
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT job.*, client.name AS client_name
                    FROM securescope_evidence_jobs job
                    JOIN securescope_clients client ON client.id = job.client_id
                    WHERE job.status = 'Queued' AND job.operation IS NULL
                      AND job.available_at <= NOW()
                      AND job.attempt_count < job.max_attempts
                    ORDER BY job.available_at, job.created_at
                    FOR UPDATE OF job SKIP LOCKED
                    LIMIT 1;
                    """
                )
                row = cursor.fetchone()
                if not row:
                    return None
                cursor.execute(
                    """
                    UPDATE securescope_evidence_jobs
                    SET status = 'Running', worker_name = %s,
                        claimed_at = NOW(), heartbeat_at = NOW(),
                        attempt_count = attempt_count + 1, updated_at = NOW()
                    WHERE client_id = %s AND id = %s
                    RETURNING *;
                    """,
                    (worker_name.strip(), row["client_id"], row["id"]),
                )
                claimed = dict(cursor.fetchone())
                claimed["client_name"] = row["client_name"]
                return claimed
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def complete_evidence_job(
    client_id: int,
    job_id: int,
    *,
    succeeded: bool,
    evidence_id: int | None,
    error: str = "",
) -> None:
    """Finalize one exact client/job identity and retain diagnostic state."""

    run_pending_migrations()
    status_value = "Succeeded" if succeeded else "Failed"
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE securescope_evidence_jobs
                    SET status = %s, result_evidence_id = %s,
                        last_error = %s, completed_at = NOW(),
                        heartbeat_at = NOW(), updated_at = NOW()
                    WHERE client_id = %s AND id = %s AND status = 'Running';
                    """,
                    (
                        status_value,
                        evidence_id,
                        str(error)[-4_000:],
                        int(client_id),
                        int(job_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise EvidenceRepositoryError(
                        "Evidence job identity or state changed before finalization."
                    )
                _append_audit_event(
                    cursor,
                    int(client_id),
                    event_type="Collector completed" if succeeded else "Collector failed",
                    entity_type="Evidence job",
                    entity_id=str(job_id),
                    actor="evidence-worker",
                    summary=(
                        "Defensive collection completed."
                        if succeeded
                        else "Defensive collection failed."
                    ),
                    payload={"evidence_id": evidence_id, "error": str(error)[-1_000:]},
                )
    except DatabaseError as exc:
        raise EvidenceRepositoryError(str(exc)) from exc


def asset_scope_memberships(cursor, client_id, asset_id):
    """Resolve explicit asset membership from current canonical profile configurations.

    Args:
        cursor: Authorized transaction cursor.
        client_id: Canonical tenant ID.
        asset_id: Canonical asset ID in this tenant.
    Returns:
        Set of (engagement_id, scope_id) pairs; empty when membership is unknown.
    Raises:
        DatabaseError: If the canonical configuration query fails.
    """
    cursor.execute(
        "WITH latest AS (SELECT DISTINCT ON (control_id, "
        "assessment_scope->'implementation_requirements'->>'scope_id') * "
        "FROM securescope_control_assessment_profiles WHERE client_id=%s "
        "ORDER BY control_id,assessment_scope->'implementation_requirements'->>'scope_id',"
        "profile_version DESC) "
        "SELECT assessment_scope->'implementation_requirements' AS config FROM latest p "
        "WHERE EXISTS (SELECT 1 FROM securescope_scope_definitions s "
        "JOIN securescope_scope_versions v ON v.client_id=s.client_id AND v.scope_id=s.id "
        "AND v.id=s.current_approved_version_id WHERE s.client_id=p.client_id "
        "AND NOT s.archived AND v.status='Approved' "
        "AND s.id::text=p.assessment_scope->'implementation_requirements'->>'scope_id' "
        "AND "
        "s.engagement_id::text=p.assessment_scope"
        "->'implementation_requirements'->>'engagement_id' "
        "AND v.id::text=p.assessment_scope->'implementation_requirements'->>'scope_version_id') ",
        (client_id,),
    )
    memberships = set()
    for row in cursor.fetchall():
        config = row["config"] or {}
        assets = {a for r in config.get("requirements", []) for a in r.get("asset_ids", [])}
        if asset_id in assets and config.get("engagement_id") and config.get("scope_id"):
            memberships.add((int(config["engagement_id"]), int(config["scope_id"])))
    return memberships


def _link_system_evidence(cursor, client_id, evidence_id, source, controls):
    """Repair or insert deterministic mappings and validated asset-scope links.

    Args:
        cursor: Evidence transaction cursor.
        client_id: Canonical tenant.
        evidence_id: Existing canonical evidence identity.
        source: Verified worker/connector provenance.
        controls: Catalogue-derived references.
    Returns:
        None; shared evidence associations are inserted idempotently.
    Raises:
        DatabaseError: If an association cannot be persisted.
    """
    if source.get("scheduled_job"):
        from securescope.persistence.wazuh_evidence_repository import link_source

        link_source(cursor, client_id, evidence_id, source)
        return
    if source.get("m3_attributed"):
        cursor.execute(
            "SELECT DISTINCT engagement_id,scope_id FROM securescope_requirement_check_attributions "
            "WHERE client_id=%s AND evidence_id=%s",
            (client_id, evidence_id),
        )
        memberships = {(r["engagement_id"], r["scope_id"]) for r in cursor.fetchall()}
    else:
        memberships = asset_scope_memberships(cursor, client_id, source["asset_id"])
    context = source.get("collection_context") or {}
    if context and not source.get("m3_attributed"):
        # A requirement-originated scan never fans out to a different scope.
        memberships &= {(context.get("engagement_id"), context.get("scope_id"))}
    if (
        not source.get("m3_attributed")
        and context.get("scope_id")
        and context.get("engagement_id")
        and context.get("requirement_id")
    ):
        cursor.execute(
            "WITH latest AS (SELECT * FROM securescope_control_assessment_profiles "
            "WHERE client_id=%s AND control_id=%s "
            "AND assessment_scope->'implementation_requirements'->>'scope_id'=%s "
            "ORDER BY profile_version DESC LIMIT 1) "
            "SELECT assessment_scope->'implementation_requirements' AS config FROM latest p "
            "WHERE EXISTS (SELECT 1 FROM securescope_scope_definitions s "
            "JOIN securescope_scope_versions v ON v.client_id=s.client_id AND v.scope_id=s.id "
            "AND v.id=s.current_approved_version_id WHERE s.client_id=p.client_id "
            "AND NOT s.archived AND v.status='Approved' "
            "AND s.id::text=p.assessment_scope->'implementation_requirements'->>'scope_id' "
            "AND "
            "s.engagement_id::text=p.assessment_scope"
            "->'implementation_requirements'->>'engagement_id' "
            "AND "
            "v.id::text=p.assessment_scope->'implementation_requirements'->>'scope_version_id') ",
            (client_id, context.get("control_id"), str(context["scope_id"])),
        )
        row = cursor.fetchone()
        config = row["config"] if row else {}
        requirement = next(
            (
                r
                for r in (config or {}).get("requirements", [])
                if r["id"] == context["requirement_id"]
            ),
            None,
        )
        if (
            requirement
            and config.get("engagement_id") == context["engagement_id"]
            and source["asset_id"] in requirement.get("asset_ids", [])
        ):
            memberships.add((int(context["engagement_id"]), int(context["scope_id"])))
    for control_id in sorted(set(controls)):
        checks = [c for c in source["checks"] if control_id in c["mapped_controls"]]
        rationale = "Automatically linked by: " + "; ".join(
            c["display_name"] + " (" + c["effect"] + "): " + c.get("explanation", "")
            for c in checks
        )
        cursor.execute(
            "INSERT INTO securescope_evidence_control_mappings "
            "(client_id,evidence_id,control_id,mapping_origin,evidence_dimension,rationale) "
            "SELECT %s,%s,%s,'Automated check','Implementation',%s WHERE NOT EXISTS "
            "(SELECT 1 FROM securescope_evidence_control_mappings WHERE client_id=%s "
            "AND evidence_id=%s AND control_id=%s AND mapping_origin='Automated "
            "check') ON CONFLICT DO NOTHING",
            (client_id, evidence_id, control_id, rationale, client_id, evidence_id, control_id),
        )
    for engagement_id, scope_id in sorted(memberships):
        cursor.execute(
            "SELECT s.id FROM securescope_scope_definitions s "
            "JOIN securescope_scope_versions v ON v.client_id=s.client_id "
            "AND v.scope_id=s.id AND v.id=s.current_approved_version_id "
            "WHERE s.client_id=%s AND s.id=%s AND s.engagement_id=%s "
            "AND NOT s.archived AND v.status='Approved'",
            (client_id, scope_id, engagement_id),
        )
        if cursor.fetchone():
            _insert_evidence_scope_link(
                cursor,
                client_id,
                engagement_id,
                scope_id,
                evidence_id,
                source.get("actor", "system:nuclei-worker"),
                "Canonical asset membership or validated originating requirement collection.",
                origin="Automated collection",
            )


def resolve_nuclei_asset(client_name: str, asset_ip: str) -> dict:
    """Resolve an existing tenant-owned inventory asset without creating one.

    Args:
        client_name: Exact workspace name.
        asset_ip: Job's canonical inventory address.
    Returns:
        Canonical database asset ID, tag and IP.
    Raises:
        EvidenceRepositoryError: Asset missing or database unavailable.
    """
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT id,asset_tag,ip FROM securescope_assets WHERE client_id=%s AND ip=%s",
                    (client_id, asset_ip),
                )
                row = cursor.fetchone()
                if not row:
                    raise EvidenceRepositoryError(
                        "Scanned asset no longer exists in this workspace."
                    )
                return dict(row)
    except DatabaseError as exc:
        raise EvidenceRepositoryError("Could not resolve the scanned asset.") from exc


def apply_evidence_currency(cursor, client_id, rows, engagement_id=None, scope_id=None):
    """Annotate evidence using one timestamp rule and the strictest linked criterion age.

    Args:
        cursor: Tenant-bound cursor.
        client_id: Canonical tenant.
        rows: Evidence dictionaries to annotate in place.
        engagement_id: Optional current engagement.
        scope_id: Optional current scope.
    Returns:
        None. Historical persisted evidence is never changed.
    Raises:
        DatabaseError: If criterion context cannot be loaded.
    """
    from securescope.evidence.freshness import evidence_freshness

    if not rows:
        return
    cursor.execute(
        "SELECT DISTINCT ON "
        "(control_id,assessment_scope->'implementation_requirements'->>'scope_id') "
        "p.control_id,p.assessment_scope->'implementation_requirements' AS config, "
        "ARRAY(SELECT l.evidence_id FROM securescope_engagement_record_links l "
        "WHERE l.client_id=p.client_id AND l.link_origin <> 'Legacy backfill' "
        "AND l.scope_id::text=p.assessment_scope->'implementation_requirements'->>'scope_id' "
        "AND "
        "l.engagement_id::text=p.assessment_scope->'implementation_requirements'"
        "->>'engagement_id') AS evidence_ids "
        "FROM securescope_control_assessment_profiles p WHERE p.client_id=%s "
        "AND (%s IS NULL OR assessment_scope->'implementation_requirements'->>'scope_id'=%s) "
        "ORDER BY "
        "control_id,assessment_scope->'implementation_requirements'->>'scope_id',"
        "profile_version DESC",
        (client_id, str(scope_id) if scope_id else None, str(scope_id) if scope_id else None),
    )
    configs = [dict(r) for r in cursor.fetchall()]
    from securescope.persistence.requirement_evidence_repository import annotate_sources

    annotate_sources(cursor, client_id, rows, engagement_id, scope_id)
    now = datetime.now(timezone.utc)
    monitoring = None
    if any(r.get("tool_id") == "wazuh" for r in rows):
        from securescope.persistence.db_wazuh_service import load_monitoring_rows

        monitoring = {r["id"]: r for r in load_monitoring_rows(cursor, client_id)}
    for row in rows:
        metadata = (row.get("normalized_payload") or {}).get("metadata", {})
        provenance = metadata.get("provenance") or {}
        if (
            row.get("tool_id") == "wazuh"
            and row.get("verification_origin") == "System collector"
            and provenance.get("check") in {"monitoring", "logging"}
        ):
            current = (monitoring or {}).get(provenance.get("source_record_id"), {})
            row["source_verification_current"] = bool(
                metadata.get("monitoring_contract_version") == 2
                and current.get("monitoring_state") == "verified"
            )
            if not row["source_verification_current"]:
                row["source_review_reason"] = (
                    "Monitoring proof is legacy, stale or no longer verified."
                )
        if metadata.get("monitoring_snapshot", {}).get("m2_collection"):
            from securescope.persistence.wazuh_evidence_repository import annotate_currency

            annotate_currency(cursor, client_id, row, engagement_id, scope_id)
        controls = {c.get("control_id") for c in row.get("controls", [])}
        if row.get("control_id"):
            controls.add(row["control_id"])
        checks = (
            (row.get("normalized_payload") or {}).get("metadata", {}).get("automated_checks", [])
        )
        rules = {r for check in checks for r in check.get("mapped_requirements", [])}
        ages = []
        for profile in configs:
            config = profile.get("config") or {}
            if scope_id is None and row["id"] not in (profile.get("evidence_ids") or []):
                continue
            if profile.get("control_id") not in controls:
                continue
            if engagement_id and config.get("engagement_id") != engagement_id:
                continue
            for requirement in config.get("requirements", []):
                explicit = any(
                    link.get("evidence_id") == row["id"]
                    for link in requirement.get("evidence_links", [])
                )
                if explicit or requirement.get("rule") in rules:
                    ages.append(int(requirement.get("max_age_days", 90)))
        if ages:
            days = min(ages)
        elif row.get("expires_at") and row.get("collected_at"):
            from securescope.grc.control_implementation import as_datetime

            expires, collected = as_datetime(row["expires_at"]), as_datetime(row["collected_at"])
            days = max(1, (expires - collected).days) if expires and collected else 90
        else:
            days = 90
        row["max_age_days"] = days
        row["freshness_status"] = evidence_freshness(row, days, now)


def repair_nuclei_evidence(client_name, evidence_id):
    """Repair existing trusted Nuclei mappings/scope links from retained canonical observations.

    Args:
        client_name: Exact workspace name.
        evidence_id: Existing system-collected Nuclei record.
    Returns:
        True when an eligible record was revisited, otherwise False.
    Raises:
        EvidenceRepositoryError: For unsupported or invalid source provenance.
        DatabaseError: If transactional repair fails.
    """
    from securescope.evidence.automated_checks import SCAN_COMPLETED, classify_nuclei

    with connect() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            client_id = _client_id(cursor, client_name)
            cursor.execute(
                "SELECT * FROM securescope_evidence_records WHERE client_id=%s AND id=%s "
                "AND tool_id='nuclei' AND verification_origin='System collector' "
                "AND validator='system:nuclei-worker' AND validation_status='Validated' FOR UPDATE",
                (client_id, evidence_id),
            )
            row = cursor.fetchone()
            if not row:
                return False
            cursor.execute(
                "SELECT 1 FROM securescope_nuclei_requirement_sources WHERE client_id=%s AND evidence_id=%s",
                (client_id, evidence_id),
            )
            if cursor.fetchone():
                # M3 associations are immutable. A replay must not target a new profile.
                return True
            payload = dict(row["normalized_payload"] or {})
            metadata = dict(payload.get("metadata") or {})
            source = dict(metadata.get("provenance") or {})
            cursor.execute(
                "SELECT j.asset_payload,a.id AS asset_id FROM securescope_nuclei_jobs j "
                "JOIN securescope_assets a ON a.client_id=j.client_id AND a.ip=j.asset_ip "
                "WHERE j.client_id=%s AND j.job_uuid=%s AND j.attempt_number=%s "
                "AND j.provider_status='Completed' AND j.status IN "
                "('Completed','Finalizing') FOR SHARE OF j",
                (client_id, source.get("job_uuid"), source.get("attempt_number")),
            )
            job = cursor.fetchone()
            if not job or job["asset_id"] != source.get("asset_id"):
                raise EvidenceRepositoryError(
                    "Historical evidence has no matching completed canonical job."
                )
            checks = {SCAN_COMPLETED.check_id: SCAN_COMPLETED.to_dict()}
            # Old tag-based check labels cannot authorize new mappings.
            for observation in payload.get("observations", []):
                attributes = observation.get("attributes") or {}
                for check in classify_nuclei(
                    attributes.get("template_id", ""), attributes.get("tags", [])
                ):
                    checks[check.check_id] = check.to_dict()
            source["checks"] = list(checks.values())
            source["collection_context"] = (job.get("asset_payload") or {}).get(
                "evidence_collection_context", {}
            )
            # Retain old links; repair cannot upgrade history into a new approved context.
            source["m3_attributed"] = True
            _link_system_evidence(
                cursor,
                client_id,
                evidence_id,
                source,
                [c for check in checks.values() for c in check["mapped_controls"]],
            )
            return True
