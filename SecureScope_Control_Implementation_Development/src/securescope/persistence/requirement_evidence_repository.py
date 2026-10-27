"""Immutable Nuclei requirement attribution and current, read-only eligibility."""

from datetime import datetime, timezone

from psycopg2.extras import Json

from securescope.evidence.nuclei_assurance import (
    RULE_VERSION,
    RULES,
    canonical_digest,
    source_facts,
)
from securescope.evidence.storage import EvidenceStorageError, read_artifact


def current_profiles(cursor, client_id, scope_id=None):
    """Return latest scoped, reviewed profiles against their current approved scope.

    Args:
        cursor: Authorized transaction; client_id: Tenant ID; scope_id: Optional exact scope.
    Returns:
        Profile rows with immutable configuration and approved context.
    Raises:
        DatabaseError: On query failure.
    """
    cursor.execute(
        "WITH latest AS (SELECT DISTINCT ON (control_id,assessment_scope->'implementation_requirements'->>'scope_id') * "
        "FROM securescope_control_assessment_profiles WHERE client_id=%s ORDER BY control_id,"
        "assessment_scope->'implementation_requirements'->>'scope_id',profile_version DESC) "
        "SELECT p.id,p.control_id,p.profile_version,p.created_at,p.assessment_scope->'implementation_requirements' AS config,"
        "s.id AS scope_id,s.engagement_id,v.id AS scope_version_id FROM latest p "
        "JOIN securescope_scope_definitions s ON s.client_id=p.client_id "
        "AND s.id::text=p.assessment_scope->'implementation_requirements'->>'scope_id' "
        "JOIN securescope_scope_versions v ON v.client_id=s.client_id AND v.scope_id=s.id "
        "AND v.id=s.current_approved_version_id JOIN securescope_engagements g ON g.client_id=s.client_id AND g.id=s.engagement_id "
        "WHERE NOT s.archived AND v.status='Approved' AND g.status NOT IN ('Completed','Cancelled') "
        "AND s.engagement_id::text=p.assessment_scope->'implementation_requirements'->>'engagement_id' "
        "AND v.id::text=p.assessment_scope->'implementation_requirements'->>'scope_version_id' "
        "AND (%s IS NULL OR s.id=%s)",
        (client_id, scope_id, scope_id),
    )
    return [
        dict(p)
        for p in cursor.fetchall()
        if p["config"].get("reviewed") is True
        and not p["config"].get("baseline_review_pending")
        and p["config"].get("continuous_auto_assurance") is not False
    ]


def freeze_targets(cursor, client_id, asset_ip, context):
    """Snapshot exact approved requirement targets into the existing Nuclei job payload.

    Args:
        cursor: Queue transaction; client_id: Tenant; asset_ip: Exact canonical address.
        context: Optional originating requirement context.
    Returns:
        Immutable-by-use target dictionaries; empty means no automatic attribution.
    Raises:
        ValueError: An explicit origin does not authorize this asset.
        DatabaseError: On read failure.
    """
    cursor.execute("SELECT id FROM securescope_clients WHERE id=%s FOR SHARE", (client_id,))
    cursor.execute(
        "SELECT id FROM securescope_assets WHERE client_id=%s AND ip=%s", (client_id, asset_ip)
    )
    assets = cursor.fetchall()
    if len(assets) != 1:
        raise ValueError("Select one canonical workspace asset.")
    asset_id = assets[0]["id"]
    result = []
    for p in current_profiles(cursor, client_id):
        if context and any(
            context.get(k) != p[k] for k in ("scope_id", "engagement_id", "control_id")
        ):
            continue
        for r in p["config"].get("requirements", []):
            check = RULES.get(r.get("rule"))
            if (
                check
                and p["control_id"] in check.mapped_controls
                and asset_id in r.get("asset_ids", [])
                and r.get("machine_verifiable") is True
                and (not context or context.get("requirement_id") == r["id"])
            ):
                result.append(
                    dict(
                        profile_id=p["id"],
                        requirement_id=r["id"],
                        scope_version_id=p["scope_version_id"],
                        asset_id=asset_id,
                        requirement_sha256=canonical_digest(r),
                    )
                )
    if context and not result:
        raise ValueError(
            "The originating requirement has no reviewed approved target for this asset."
        )
    return result


def capture_source(cursor, client_id, evidence_id, source):
    """Pin exact source and existing approved requirements on first canonical ingestion only.

    Args:
        cursor: Ingestion transaction; client_id, evidence_id: Canonical ownership.
        source: Verified job provenance, including original collection context.
    Returns:
        None. An unassigned source is retained without inventing requirement membership.
    Raises:
        EvidenceStorageError, ValueError: Invalid artifact or source bytes.
        DatabaseError: Invalid ownership or persistence failure.
    """
    cursor.execute("SELECT id FROM securescope_clients WHERE id=%s FOR SHARE", (client_id,))
    cursor.execute(
        "SELECT e.*,a.storage_reference,a.sha256 FROM securescope_evidence_records e "
        "JOIN securescope_evidence_artifacts a ON a.client_id=e.client_id AND a.id=e.artifact_id "
        "WHERE e.client_id=%s AND e.id=%s",
        (client_id, evidence_id),
    )
    row = cursor.fetchone()
    if not row:
        raise ValueError("Canonical Nuclei evidence requires retained source bytes.")
    raw = read_artifact(client_id, row["storage_reference"], expected_sha256=row["sha256"])
    facts = source_facts(
        raw, source["asset_id"], row["source_asset_or_system"], row["collected_at"]
    )
    cursor.execute(
        "INSERT INTO securescope_nuclei_requirement_sources "
        "(client_id,evidence_id,artifact_id,asset_id,source_key,observed_at,artifact_sha256,facts,facts_sha256,rule_version) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            client_id,
            evidence_id,
            row["artifact_id"],
            source["asset_id"],
            row["source_key"],
            row["collected_at"],
            row["sha256"],
            Json(facts),
            canonical_digest(facts),
            RULE_VERSION,
        ),
    )
    context = source.get("collection_context") or {}
    for profile in current_profiles(cursor, client_id):
        if source.get("job_created_at") and profile["created_at"] > source["job_created_at"]:
            continue
        if context and any(
            context.get(k) != profile[k] for k in ("scope_id", "engagement_id", "control_id")
        ):
            continue
        for requirement in profile["config"].get("requirements", []):
            rule = RULES.get(requirement.get("rule"))
            if (
                not rule
                or profile["control_id"] not in rule.mapped_controls
                or source["asset_id"] not in requirement.get("asset_ids", [])
                or requirement.get("machine_verifiable") is not True
                or (context and context.get("requirement_id") != requirement["id"])
            ):
                continue
            snapshot = source.get("target_snapshot")
            expected_target = dict(
                profile_id=profile["id"],
                requirement_id=requirement["id"],
                scope_version_id=profile["scope_version_id"],
                asset_id=source["asset_id"],
                requirement_sha256=canonical_digest(requirement),
            )
            if snapshot is not None and expected_target not in snapshot:
                continue
            cursor.execute(
                "INSERT INTO securescope_requirement_check_attributions "
                "(client_id,evidence_id,profile_id,engagement_id,scope_id,scope_version_id,requirement_id,asset_id,rule_version,requirement_sha256) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    client_id,
                    evidence_id,
                    profile["id"],
                    profile["engagement_id"],
                    profile["scope_id"],
                    profile["scope_version_id"],
                    requirement["id"],
                    source["asset_id"],
                    RULE_VERSION,
                    canonical_digest(requirement),
                ),
            )


def annotate_sources(cursor, client_id, rows, engagement_id=None, scope_id=None):
    """Recompute eligibility from immutable attribution and verified artifacts, without writes.

    Args:
        cursor: Tenant transaction; client_id: Owner; rows: Evidence rows to annotate in place.
        engagement_id, scope_id: Optional selected context.
    Returns:
        None. Historical normalized payloads remain unchanged.
    Raises:
        DatabaseError: On query failure; invalid artifacts instead yield ineligible rows.
    """
    selected = [r for r in rows if r.get("tool_id") == "nuclei"]
    if not selected:
        return
    profiles = {p["id"]: p for p in current_profiles(cursor, client_id, scope_id)}
    cursor.execute(
        "SELECT x.*,a.storage_reference,e.collected_at,e.source_key AS actual_source,e.validation_status,"
        "e.verification_origin,e.validator,e.collection_method,e.normalized_payload,j.asset_ip,j.asset_payload,"
        "j.status AS job_status,j.provider_status,j.created_at AS job_created_at "
        "FROM securescope_nuclei_requirement_sources x "
        "JOIN securescope_evidence_records e ON e.client_id=x.client_id AND e.id=x.evidence_id "
        "JOIN securescope_evidence_artifacts a ON a.client_id=x.client_id AND a.id=x.artifact_id AND e.artifact_id=a.id "
        "AND a.sha256=x.artifact_sha256 "
        "JOIN securescope_nuclei_jobs j ON j.client_id=x.client_id "
        "AND 'nuclei:'||j.job_uuid||':attempt:'||j.attempt_number=x.source_key "
        "JOIN securescope_assets asset ON asset.client_id=j.client_id AND asset.id=x.asset_id AND asset.ip=j.asset_ip "
        "WHERE x.client_id=%s AND x.evidence_id=ANY(%s)",
        (client_id, [r["id"] for r in selected]),
    )
    sources = {r["evidence_id"]: dict(r) for r in cursor.fetchall()}
    cursor.execute(
        "SELECT * FROM securescope_requirement_check_attributions WHERE client_id=%s AND evidence_id=ANY(%s)",
        (client_id, [r["id"] for r in selected]),
    )
    links = [dict(r) for r in cursor.fetchall()]
    verified = {}
    for row in selected:
        row.update(
            eligible_requirement_ids=[],
            source_verification_current=False,
            nuclei_verified_source={},
        )
        row["source_review_reason"] = (
            "No verified M3 source attribution; collect new scoped evidence."
        )
        source = sources.get(row["id"])
        if not source:
            continue
        if row["id"] not in verified:
            try:
                raw = read_artifact(
                    client_id,
                    source["storage_reference"],
                    expected_sha256=source["artifact_sha256"],
                )
                facts = source_facts(
                    raw, source["asset_id"], source["asset_ip"], source["observed_at"]
                )
                valid = (
                    canonical_digest(facts) == source["facts_sha256"]
                    and facts == source["facts"]
                    and source["observed_at"] == source["collected_at"]
                    and source["job_created_at"]
                    <= source["observed_at"]
                    <= datetime.now(timezone.utc)
                    and source["actual_source"] == source["source_key"]
                    and source["job_status"] in {"Finalizing", "Completed"}
                    and source["provider_status"] == "Completed"
                    and source["validation_status"] == "Validated"
                    and source["verification_origin"] == "System collector"
                    and source["validator"] == "system:nuclei-worker"
                    and source["collection_method"] == "Existing worker"
                )
                verified[row["id"]] = facts if valid else None
            except (EvidenceStorageError, ValueError, UnicodeError):
                verified[row["id"]] = None
        facts = verified[row["id"]]
        if facts is None:
            row["source_review_reason"] = (
                "Source artifact, timestamp or canonical job verification failed."
            )
            continue
        row.update(
            nuclei_verified_source=facts, sha256=source["artifact_sha256"], attribution_contexts=[]
        )
        # Derived read facts never trust a caller's arbitrary technical_checks or asset list.
        payload = dict(row.get("normalized_payload") or {})
        metadata = dict(payload.get("metadata") or {})
        metadata["assurance"] = dict(complete=facts["complete"], asset_ids=[facts["asset_id"]])
        payload["metadata"] = metadata
        row["normalized_payload"] = payload
        for link in links:
            p = profiles.get(link["profile_id"])
            if (
                link["evidence_id"] != row["id"]
                or not p
                or (scope_id and link["scope_id"] != scope_id)
                or (engagement_id and link["engagement_id"] != engagement_id)
                or (row.get("control_id") and p["control_id"] != row["control_id"])
            ):
                continue
            job_payload = source.get("asset_payload") or {}
            frozen = job_payload.get("m3_requirement_targets")
            target = dict(
                profile_id=link["profile_id"],
                requirement_id=link["requirement_id"],
                scope_version_id=link["scope_version_id"],
                asset_id=link["asset_id"],
                requirement_sha256=link["requirement_sha256"],
            )
            origin = job_payload.get("evidence_collection_context") or {}
            if (frozen is not None and target not in frozen) or (
                origin
                and any(
                    origin.get(k) != v
                    for k, v in dict(
                        scope_id=link["scope_id"],
                        engagement_id=link["engagement_id"],
                        control_id=p["control_id"],
                        requirement_id=link["requirement_id"],
                    ).items()
                )
            ):
                continue
            req = next(
                (
                    r
                    for r in p["config"].get("requirements", [])
                    if r["id"] == link["requirement_id"]
                ),
                None,
            )
            if (
                req
                and canonical_digest(req) == link["requirement_sha256"]
                and p["scope_version_id"] == link["scope_version_id"]
            ):
                row["eligible_requirement_ids"].append(req["id"])
                row["attribution_contexts"].append(
                    dict(
                        profile_id=p["id"],
                        profile_version=p["profile_version"],
                        scope_version_id=p["scope_version_id"],
                        scope_id=p["scope_id"],
                        engagement_id=p["engagement_id"],
                        requirement_id=req["id"],
                        asset_id=link["asset_id"],
                        rule_version=RULE_VERSION,
                    )
                )
        row["source_verification_current"] = bool(row["eligible_requirement_ids"])
        row["source_review_reason"] = (
            ""
            if row["source_verification_current"]
            else "Current approved profile/requirement attribution is unavailable."
        )
