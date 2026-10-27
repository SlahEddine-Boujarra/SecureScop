"""Scoped assurance reads and writes extending canonical profiles and evidence links."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from securescope.grc.assurance_requirements import (
    apply_safety_signals,
    evaluate_assurance,
    evaluate_requirement,
    evidence_freshness,
    validate_requirements,
)
from securescope.integrations.credential_store import open_configuration, seal_configuration
from securescope.persistence.control_implementation_repository import (
    REVIEWERS,
    _documents,
    _load_bundle,
)
from securescope.persistence.evidence_repository import _append_audit_event
from securescope.persistence.foundation_repository import (
    FoundationError,
    member_role,
    workspace_cursor,
)
from securescope.persistence.grc_repository import GrcRepositoryError, create_profile_version

EVENT = "control_requirement_evaluation"


def _context(
    cursor, client_id: int, actor: str, engagement: int, scope: int, *, write: bool = False
) -> str:
    """Validate tenant membership and the selected canonical scope.

    Args:
        cursor: Authorized transaction cursor.
        client_id: Tenant ID.
        actor: Trusted principal.
        engagement: Engagement ID.
        scope: Scope ID.
        write: Require consultant or administrator authority.
    Returns:
        Membership role.
    Raises:
        FoundationError: For foreign context or insufficient permissions.
    """
    role = member_role(cursor, client_id, actor)
    if not role or (write and role not in REVIEWERS):
        raise FoundationError("An authorized workspace membership is required.")
    cursor.execute(
        "SELECT id FROM securescope_scope_definitions WHERE client_id=%s "
        "AND engagement_id=%s AND id=%s AND NOT archived",
        (client_id, engagement, scope),
    )
    if not cursor.fetchone():
        raise FoundationError("Select a current ISMS Scope in this engagement.")
    return role


def _evidence(cursor, client_id: int, control_id: str, engagement: int, scope: int) -> list[dict]:
    """Load bounded evidence summaries, leaving raw observations and artifacts unloaded.

    Args:
        cursor: Transaction cursor.
        client_id: Tenant ID.
        control_id: Canonical control reference.
        engagement: Engagement ID.
        scope: Scope ID.
    Returns:
        At most 500 scoped mapped summaries with normalized rule facts.
    Raises:
        DatabaseError: If reads fail.
    """
    cursor.execute(
        "SELECT DISTINCT m.control_id,e.id,e.title,e.tool_id,e.collection"
        "_method,e.collected_at,e.expires_at,"
        "e.validation_status,e.verification_origin,e.source_key,e.ob"
        "servation_count,e.validator,e.validated_at,e.source_asset_or"
        "_system,e.freshness_status,"
        "m.consultant_approved AS mapping_approved,m.mapping_origin,"
        "m.rationale,l.scope_id,l.engagement_id,s.name AS scope_name,"
        "e.normalized_payload AS normalized_payload "
        "FROM securescope_evidence_records e "
        "JOIN securescope_evidence_control_mappings m ON "
        "m.client_id=e.client_id AND m.evidence_id=e.id "
        "JOIN securescope_engagement_record_links l ON "
        "l.client_id=e.client_id AND l.evidence_id=e.id "
        "JOIN securescope_scope_definitions s ON s.client_id=l.client_id AND s.id=l.scope_id "
        "WHERE e.client_id=%s AND (%s='' OR m.control_id=%s) AND "
        "l.engagement_id=%s AND l.scope_id=%s "
        "AND l.link_origin <> 'Legacy backfill' ORDER BY e.collected_at DESC LIMIT 501",
        (client_id, control_id, control_id, engagement, scope),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    incomplete = len(rows) > 500
    rows = rows[:500]
    for row in rows:
        row["evidence_window_incomplete"] = incomplete
    from securescope.persistence.evidence_repository import apply_evidence_currency

    apply_evidence_currency(cursor, client_id, rows, engagement, scope)
    for row in rows:
        metadata = (row.get("normalized_payload") or {}).get("metadata", {})
        row["automated_checks"] = [
            c
            for c in metadata.get("automated_checks", [])
            if row["control_id"] in c.get("mapped_controls", [])
        ]
        row["asset_tag"] = (metadata.get("provenance") or {}).get("asset_tag")
        row["automated_observations"] = [
            {"title": o.get("title"), "effect": c["effect"]}
            for o in (row.get("normalized_payload") or {}).get("observations", [])
            for c in (o.get("attributes") or {}).get("automated_checks", [])
            if row["control_id"] in c.get("mapped_controls", [])
        ]
        # Evaluation only needs normalized facts; the full report stays in canonical evidence.
        row["normalized_payload"] = {"metadata": metadata}
    return rows


def load_workspace(client: str, control_id: str, actor: str, engagement: int, scope: int) -> dict:
    """Join existing records into one scoped Control Workspace without copying source data.

    Args:
        client: Workspace name.
        control_id: Existing control identifier.
        actor: Trusted authenticated principal.
        engagement: Selected engagement ID.
        scope: Selected ISMS Scope ID.
    Returns:
        Profile inputs, derived conclusions, existing actions and audit summaries.
    Raises:
        FoundationError: If membership, context or database reads fail.
        CredentialStoreError: If a historical snapshot cannot be decrypted.
    """
    with workspace_cursor(client) as (cursor, client_id):
        role = _context(cursor, client_id, actor, engagement, scope)
        bundle = _load_bundle(cursor, client_id, control_id, scope)
        config = (bundle["profile"].get("assessment_scope") or {}).get(
            "implementation_requirements"
        ) or {}
        from securescope.grc.requirement_templates import merge_baseline

        proposed, pending = merge_baseline(control_id, config)
        if pending:
            config = dict(config, requirements=proposed, baseline_preview=True)
            bundle["profile"]["assessment_scope"] = dict(
                bundle["profile"].get("assessment_scope") or {}
            )
            bundle["profile"]["assessment_scope"]["implementation_requirements"] = config
        if config.get("scope_id") != scope:
            # Legacy assessments remain accessible in their original profile. They
            # cannot certify a newly selected scope without an explicit assessment.
            bundle.update(assessment={}, criteria=[], validator_authorized=False)
        bundle.update(engagement_id=engagement, scope_id=scope)
        bundle["documents"] = _documents(cursor, client_id, engagement, scope)
        bundle["requirement_evidence"] = _evidence(cursor, client_id, control_id, engagement, scope)
        cursor.execute(
            "SELECT v.* FROM securescope_scope_versions v JOIN securescope_scope_definitions s "
            "ON s.client_id=v.client_id AND s.id=v.scope_id AND s.current_approved_version_id=v.id "
            "WHERE v.client_id=%s AND v.engagement_id=%s AND v.scope_id=%s AND v.status='Approved'",
            (client_id, engagement, scope),
        )
        bundle["scope"] = dict(cursor.fetchone() or {})
        cursor.execute(
            "SELECT i.* FROM securescope_soa_items i JOIN "
            "securescope_soa_versions v ON v.client_id=i.client_id AND "
            "v.id=i.soa_version_id JOIN securescope_engagement_record_links "
            "l ON l.client_id=v.client_id AND l.soa_version_id=v.id WHERE "
            "i.client_id=%s AND i.control_id=%s AND v.status='Approved' AND "
            "l.engagement_id=%s AND l.scope_id=%s AND l.link_origin <> "
            "'Legacy backfill' ORDER BY v.version_number DESC LIMIT 1",
            (client_id, control_id, engagement, scope),
        )
        bundle["soa"] = dict(cursor.fetchone() or {})
        cursor.execute(
            "SELECT * FROM securescope_interested_party_requirements WHERE "
            "client_id=%s AND engagement_id=%s AND scope_id=%s ORDER BY id "
            "LIMIT 500",
            (client_id, engagement, scope),
        )
        bundle["party_requirements"] = [dict(r) for r in cursor.fetchall()]
        cursor.execute(
            "SELECT risk_ref,threat,asset,risk_owner,treatment_option,treatme"
            "nt_action,control_references FROM securescope_risk_register "
            "WHERE client_id=%s AND primary_scope_id=%s AND "
            "control_references @> %s::jsonb ORDER BY risk_ref LIMIT 200",
            (client_id, scope, json.dumps([control_id])),
        )
        bundle["risks"] = [dict(r) for r in cursor.fetchall()]
        cursor.execute(
            "SELECT id,recommended_action,action_owner,priority,due_date,stat"
            "us,success_criteria FROM securescope_improvement_actions WHERE "
            "client_id=%s AND control_id=%s AND affected_scope=%s ORDER BY "
            "id DESC LIMIT 200",
            (client_id, control_id, f"ISMS Scope #{scope}"),
        )
        bundle["actions"] = [dict(r) for r in cursor.fetchall()]
        cursor.execute(
            "SELECT id,ip,asset_tag FROM securescope_assets WHERE "
            "client_id=%s ORDER BY id LIMIT 1000",
            (client_id,),
        )
        bundle["assets"] = [dict(r) for r in cursor.fetchall()]
        asset_ids = sorted(
            {i for r in config.get("requirements", []) for i in r.get("asset_ids", [])}
        )
        identities = [r["ip"] for r in bundle["assets"] if r["id"] in asset_ids]
        cursor.execute(
            "SELECT id,title,severity,lifecycle_status FROM "
            "securescope_findings WHERE client_id=%s AND "
            "asset_identity=ANY(%s) AND severity IN ('High','Critical') AND "
            "lifecycle_status NOT IN ('Closed','False positive') LIMIT 100",
            (client_id, identities),
        )
        contradictions = [dict(r) for r in cursor.fetchall()]
        bundle["blockers"] = [f"Finding #{r['id']}: {r['title']}" for r in contradictions]
        bundle["blockers"] += [
            f"Remediation #{r['id']} is unresolved."
            for r in bundle["actions"]
            if r["status"] not in {"Completed", "Cancelled"}
        ]
        apply_safety_signals(bundle, datetime.now(timezone.utc))
        cursor.execute(
            "SELECT id,summary,actor,created_at,event_payload->'scope_id' AS "
            "scope_id FROM securescope_evidence_audit_events WHERE "
            "client_id=%s AND entity_type='control_profile' AND entity_id=%s "
            "AND event_payload->>'scope_id'=%s ORDER BY id DESC LIMIT 50",
            (client_id, control_id, str(scope)),
        )
        history = []
        for row in cursor.fetchall():
            if row.get("scope_id") == scope:
                history.append({k: row[k] for k in ("id", "summary", "actor", "created_at")})
        cursor.execute(
            (
                "SELECT profile_version,created_at,created_by FROM "
                "securescope_control_assessment_profiles WHERE client_id=%s AND "
                "control_id=%s AND "
                "assessment_scope->'implementation_requirements'->>'scope_id'=%s "
                "ORDER BY profile_version DESC LIMIT 30"
            ),
            (client_id, control_id, str(scope)),
        )
        for item in cursor.fetchall():
            history.append(
                dict(
                    id=f"profile-{item['profile_version']}",
                    summary=f"Requirement / profile version {item['profile_version']} saved",
                    actor=item.get("created_by") or "Recorded user",
                    created_at=item["created_at"],
                )
            )
        for item in bundle["requirement_evidence"]:
            if item.get("validated_at"):
                history.append(
                    dict(
                        id=f"evidence-{item['id']}",
                        summary=f"Evidence {item['title']}: {item['validation_status']}",
                        actor=item.get("validator") or "Recorded reviewer",
                        created_at=item["validated_at"],
                    )
                )
        if bundle.get("assessment"):
            item = bundle["assessment"]
            history.append(
                dict(
                    id=f"assessment-{item['id']}",
                    summary="Assessment recorded: "
                    + str(item.get("assessment_status") or "Not assessed"),
                    actor=item.get("validator") or item.get("assessor") or "Recorded assessor",
                    created_at=item["created_at"],
                )
            )
        history.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        bundle = json.loads(json.dumps(bundle, default=str))
        result = evaluate_assurance(bundle, now=datetime.now(timezone.utc))
        return dict(bundle=bundle, result=result, history=history, role=role)


def save_requirements(
    client: str,
    control_id: str,
    actor: str,
    engagement: int,
    scope: int,
    expected: int,
    requirements: list[dict],
    *,
    auto: bool,
    owner: str,
    seed_baseline: bool = False,
) -> int:
    """Version structured criteria and canonical relationships in the existing profile.

    Args:
        client: Tenant name.
        control_id: Existing control reference.
        actor: Trusted reviewer principal.
        engagement: Current engagement ID.
        scope: Current scope ID.
        expected: Profile version originally opened.
        requirements: Structured criteria referencing existing records.
        auto: Whether eligible machine-only conclusions may be verified automatically.
        owner: Accountable control owner.
    Returns:
        New immutable profile version number.
    Raises:
        FoundationError: On invalid links, unauthorized automation or foreign context.
        GrcRepositoryError: On invalid profile fields or concurrent edits.
    """
    from securescope.grc.requirement_templates import supersede_seeded_requirements

    requirements = supersede_seeded_requirements(validate_requirements(requirements))
    if len({a for r in requirements for a in r.get("asset_ids", [])}) > 1000:
        raise FoundationError("A control profile supports at most 1000 explicitly scoped assets.")
    with workspace_cursor(client) as (cursor, client_id):
        role = _context(cursor, client_id, actor, engagement, scope, write=True)
        profile = _load_bundle(cursor, client_id, control_id, scope)["profile"]
        config = dict(
            (profile.get("assessment_scope") or {}).get("implementation_requirements") or {}
        )
        original_config = dict(config)
        if int(profile["profile_version"]) != expected:
            raise GrcRepositoryError("Control profile changed. Reload before saving.")
        if auto != bool(config.get("continuous_auto_assurance")) and role != "Administrator":
            raise FoundationError("Only an Administrator can change Continuous Auto-Assurance.")
        documents = {d["policy_id"] for d in _documents(cursor, client_id, engagement, scope)}
        evidence = {e["id"]: e for e in _evidence(cursor, client_id, control_id, engagement, scope)}
        for requirement in requirements:
            if set(requirement.get("policy_ids", [])) - documents:
                raise FoundationError("A linked policy is outside the current scope.")
            for link in requirement.get("evidence_links", []):
                if link.get("evidence_id") not in evidence:
                    raise FoundationError(
                        "Link evidence to this control and scope in Evidence first."
                    )
            party_id = requirement.get("party_requirement_id")
            if party_id:
                cursor.execute(
                    "SELECT id FROM securescope_interested_party_requirements WHERE "
                    "client_id=%s AND engagement_id=%s AND scope_id=%s AND id=%s",
                    (client_id, engagement, scope, party_id),
                )
                if not cursor.fetchone():
                    raise FoundationError("Interested Party requirement is outside this scope.")
            assets = requirement.get("asset_ids", [])
            cursor.execute(
                "SELECT id FROM securescope_assets WHERE client_id=%s AND id=ANY(%s)",
                (client_id, assets),
            )
            if {r["id"] for r in cursor.fetchall()} != set(assets):
                raise FoundationError("Select canonical assets from this workspace.")
        cursor.execute(
            "SELECT v.id FROM securescope_scope_versions v JOIN securescope_scope_definitions s "
            "ON s.client_id=v.client_id AND s.id=v.scope_id AND s.current_approved_version_id=v.id "
            "WHERE v.client_id=%s AND v.scope_id=%s AND v.status='Approved'",
            (client_id, scope),
        )
        scope_version = cursor.fetchone()
        config.update(
            scope_version_id=scope_version["id"] if scope_version else None,
            requirements=requirements,
            continuous_auto_assurance=auto,
            auto_enabled_by=(
                actor
                if auto and not config.get("continuous_auto_assurance")
                else config.get("auto_enabled_by")
            ),
            engagement_id=engagement,
            scope_id=scope,
            reviewed=not seed_baseline,
            baseline_review_pending=seed_baseline,
        )
        config.pop("baseline_preview", None)
        if seed_baseline:
            from securescope.grc.requirement_templates import template_version_for

            config["baseline_template_version"] = template_version_for(control_id)
            config["baseline_review_pending"] = True
        if config == original_config and owner == profile.get("control_owner"):
            return int(profile["profile_version"])
    return create_profile_version(
        client,
        control_id,
        measurement_model=profile["measurement_model"],
        control_owner=owner,
        assessment_owner=profile.get("assessment_owner") or actor,
        assessment_scope={
            **profile["assessment_scope"],
            "description": profile["assessment_scope"].get("description") or f"ISMS Scope #{scope}",
            "implementation_requirements": config,
        },
        assessment_methods=profile.get("assessment_methods") or ["Examine", "Test"],
        evidence_requirements=profile.get("evidence_requirements") or ["Requirement evidence"],
        automation_level="Partial" if auto else "Manual",
        supported_data_sources=profile.get("supported_data_sources") or [],
        actor=actor,
        expected_profile_version=expected,
        context_scope_id=scope,
    )


def record_evaluation(
    client: str, control_id: str, actor: str, engagement: int, scope: int
) -> dict:
    """Append an explainable encrypted result snapshot to the existing audit trail.

    Args:
        client: Tenant name.
        control_id: Existing control identifier.
        actor: Authorized reviewer.
        engagement: Current engagement ID.
        scope: Current scope ID.
    Returns:
        Current server-calculated result.
    Raises:
        FoundationError: For authorization or persistence failure.
        CredentialStoreError: If snapshot encryption fails.
    """
    view = load_workspace(client, control_id, actor, engagement, scope)
    if view["role"] not in REVIEWERS:
        raise FoundationError("Reviewer membership is required to record evaluations.")
    result = view["result"]
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope, write=True)
        cursor.execute(
            "SELECT event_payload FROM securescope_evidence_audit_events "
            "WHERE client_id=%s AND entity_type='control_profile' AND "
            "entity_id=%s AND event_type=%s AND "
            "event_payload->>'scope_id'=%s ORDER BY id DESC LIMIT 1",
            (client_id, control_id, EVENT, str(scope)),
        )
        previous = cursor.fetchone()
        if previous:
            recorded = open_configuration(
                previous["event_payload"]["snapshot_ciphertext"].encode()
            )["result"]
            comparable = {k: v for k, v in result.items() if k != "evaluated_at"}
            if comparable == {k: v for k, v in recorded.items() if k != "evaluated_at"}:
                return result
        _append_audit_event(
            cursor,
            client_id,
            event_type=EVENT,
            entity_type="control_profile",
            entity_id=control_id,
            actor=actor,
            summary=(
                f"{result['implementation']} · {result['assurance']} · "
                f"{result['satisfied']}/{result['mandatory_count']} mandatory requirements"
            ),
            payload={
                "scope_id": scope,
                "engagement_id": engagement,
                "snapshot_ciphertext": seal_configuration(
                    dict(result=result, inputs=view["bundle"])
                ).decode(),
            },
        )
    return result


def create_requirement_action(
    client: str,
    control_id: str,
    actor: str,
    engagement: int,
    scope: int,
    requirement_id: str,
    *,
    owner: str,
    due_date,
    priority: str,
) -> int:
    """Create canonical improvement work for a requirement without inventing an assessment.

    Args:
        client: Tenant name.
        control_id: Existing control ID.
        actor: Authorized reviewer.
        engagement: Current engagement ID.
        scope: Current scope ID.
        requirement_id: Stable profile requirement ID.
        owner: Responsible person.
        due_date: Explicit committed date.
        priority: Existing priority enum.
    Returns:
        Existing or newly created canonical improvement action ID.
    Raises:
        FoundationError: For invalid fields, permissions or unknown requirement.
    """
    if not owner.strip() or priority not in {"Critical", "High", "Medium", "Low"} or not due_date:
        raise FoundationError("Record an owner, priority and due date.")
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope, write=True)
        profile = _load_bundle(cursor, client_id, control_id, scope)["profile"]
        requirements = (
            profile["assessment_scope"]
            .get("implementation_requirements", {})
            .get("requirements", [])
        )
        requirement = next((r for r in requirements if r["id"] == requirement_id), None)
        if not requirement:
            raise FoundationError("Requirement changed. Reload before creating remediation.")
        reference = f"Control requirement {requirement_id}"
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"requirement-action:{client_id}:{scope}:{control_id}:{requirement_id}",),
        )
        cursor.execute(
            "SELECT id FROM securescope_improvement_actions WHERE "
            "client_id=%s AND control_id=%s AND affected_scope=%s AND "
            "dependencies=%s AND status NOT IN ('Completed','Cancelled') "
            "LIMIT 1",
            (client_id, control_id, f"ISMS Scope #{scope}", reference),
        )
        existing = cursor.fetchone()
        if existing:
            return int(existing["id"])
        cursor.execute(
            "INSERT INTO securescope_improvement_actions "
            "(client_id,action_uuid,control_id,affected_scope,recommended_act"
            "ion,action_owner,risk_owner,priority,dependencies,due_date,sla_d"
            "ays,success_criteria,verification_method,expected_evidence) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (
                client_id,
                str(uuid.uuid4()),
                control_id,
                f"ISMS Scope #{scope}",
                requirement["title"],
                owner,
                "",
                priority,
                reference,
                due_date,
                max(1, (due_date - datetime.now(timezone.utc).date()).days),
                requirement["expected_result"],
                requirement["rule"],
                "Current scoped evidence satisfying this requirement",
            ),
        )
        identity = int(cursor.fetchone()["id"])
        _append_audit_event(
            cursor,
            client_id,
            event_type="requirement_remediation_created",
            entity_type="control_profile",
            entity_id=control_id,
            actor=actor,
            summary=f'Remediation #{identity}: {requirement["title"]}',
            payload={"scope_id": scope, "requirement_id": requirement_id, "action_id": identity},
        )
        return identity


def link_evidence_scope(
    client: str,
    control_id: str,
    actor: str,
    engagement: int,
    scope: int,
    evidence_id: int,
    rationale: str,
) -> None:
    """Confirm an existing evidence item covers the selected scope and control.

    Args:
        client: Workspace name.
        control_id: Existing control ID.
        actor: Trusted reviewer principal.
        engagement: Selected engagement ID.
        scope: Selected scope ID.
        evidence_id: Existing canonical evidence ID.
        rationale: Why this evidence applies to the boundary and control.
    Returns:
        None; preserves original source records and adds explicit relationships.
    Raises:
        FoundationError: For foreign evidence, missing rationale or denied access.
    """
    if not rationale.strip():
        raise FoundationError("Explain why the evidence covers this control and scope.")
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope, write=True)
        _load_bundle(cursor, client_id, control_id, scope)
        cursor.execute(
            "SELECT id FROM securescope_evidence_records WHERE client_id=%s AND id=%s",
            (client_id, evidence_id),
        )
        if not cursor.fetchone():
            raise FoundationError("Evidence does not belong to this workspace.")
        from securescope.persistence.evidence_repository import _insert_evidence_scope_link

        _insert_evidence_scope_link(
            cursor,
            client_id,
            engagement,
            scope,
            evidence_id,
            actor,
            rationale,
        )
        cursor.execute(
            "INSERT INTO securescope_evidence_control_mappings "
            "(client_id,evidence_id,control_id,mapping_origin,evidence_dimens"
            "ion,rationale,consultant_approved,approved_by,approved_at) "
            "VALUES (%s,%s,%s,'Consultant "
            "mapping','Implementation',%s,TRUE,%s,NOW()) ON CONFLICT "
            "(client_id,evidence_id,control_id,evidence_dimension) DO UPDATE "
            "SET rationale=EXCLUDED.rationale,consultant_approved=TRUE,approv"
            "ed_by=EXCLUDED.approved_by,approved_at=NOW()",
            (client_id, evidence_id, control_id, rationale, actor),
        )
        _append_audit_event(
            cursor,
            client_id,
            event_type="requirement_evidence_linked",
            entity_type="control_profile",
            entity_id=control_id,
            actor=actor,
            summary=f"Evidence EV-{evidence_id} linked to Scope #{scope}",
            payload={"scope_id": scope, "evidence_id": evidence_id, "rationale": rationale},
        )


def evidence_choices(
    client: str, actor: str, engagement: int, scope: int, search: str = ""
) -> list[dict]:
    """Search canonical evidence metadata without loading raw reports.

    Args:
        client: Workspace name.
        actor: Authenticated principal.
        engagement: Current engagement.
        scope: Current scope.
        search: Title text, bound as a parameter.
    Returns:
        Up to 100 recent matching evidence records.
    Raises:
        FoundationError: If access or reads fail.
    """
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope)
        cursor.execute(
            "SELECT id,title,tool_id,validation_status,collected_at FROM "
            "securescope_evidence_records WHERE client_id=%s AND title ILIKE "
            "%s ORDER BY collected_at DESC LIMIT 100",
            (client_id, "%" + search[:200] + "%"),
        )
        return [dict(row) for row in cursor.fetchall()]


def requirement_actions(client: str, actor: str, engagement: int, scope: int) -> list[dict]:
    """Read canonical requirement work for the selected scope.

    Args:
        client: Tenant name.
        actor: Current principal.
        engagement: Current engagement.
        scope: Current scope.
    Returns:
        Bounded improvement action metadata.
    Raises:
        FoundationError: If authorization or persistence fails.
    """
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope)
        cursor.execute(
            "SELECT id,control_id,recommended_action,action_owner,priority,du"
            "e_date,status,success_criteria FROM "
            "securescope_improvement_actions WHERE client_id=%s AND "
            "affected_scope=%s AND dependencies LIKE 'Control requirement %%' "
            "ORDER BY due_date,id LIMIT 500",
            (client_id, f"ISMS Scope #{scope}"),
        )
        return [dict(row) for row in cursor.fetchall()]


def update_requirement_action(
    client: str,
    actor: str,
    engagement: int,
    scope: int,
    identity: int,
    status: str,
    note: str,
    *,
    evidence_id: int | None = None,
) -> None:
    """Update canonical work status with an auditable closure rationale.

    Args:
        client: Tenant name.
        actor: Reviewer principal.
        engagement: Current engagement.
        scope: Current scope.
        identity: Existing improvement action ID.
        status: Existing operational status.
        note: Required rationale and evidence reference when completing.
    Returns:
        None.
    Raises:
        FoundationError: For invalid state, absent notes or foreign action.
    """
    if (
        status
        not in {
            "Open",
            "In progress",
            "Blocked",
            "Ready for verification",
            "Completed",
            "Cancelled",
        }
        or not note.strip()
    ):
        raise FoundationError("Choose a valid status and record a progress/verification note.")
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope, write=True)
        cursor.execute(
            "SELECT id,control_id,status,dependencies FROM "
            "securescope_improvement_actions WHERE client_id=%s AND id=%s "
            "AND affected_scope=%s FOR UPDATE",
            (client_id, identity, f"ISMS Scope #{scope}"),
        )
        action = cursor.fetchone()
        if not action:
            raise FoundationError("Remediation does not belong to this scope.")
        verification = None
        if status == "Completed":
            if action["status"] != "Ready for verification":
                raise FoundationError(
                    "Move remediation to Ready for verification before completing it."
                )
            bundle = _load_bundle(cursor, client_id, action["control_id"], scope)
            config = (bundle["profile"].get("assessment_scope") or {}).get(
                "implementation_requirements"
            ) or {}
            requirement_id = str(action.get("dependencies") or "").removeprefix(
                "Control requirement "
            )
            requirement = next(
                (r for r in config.get("requirements", []) if r["id"] == requirement_id), None
            )
            if config.get("scope_id") != scope or not requirement:
                raise FoundationError(
                    "The original scoped requirement must be reviewed before closure."
                )
            bundle.update(scope_id=scope, engagement_id=engagement)
            bundle["documents"] = _documents(cursor, client_id, engagement, scope)
            bundle["requirement_evidence"] = _evidence(
                cursor, client_id, action["control_id"], engagement, scope
            )
            proof = next(
                (e for e in bundle["requirement_evidence"] if e["id"] == evidence_id), None
            )
            now = datetime.now(timezone.utc)
            if (
                not proof
                or not proof.get("mapping_approved")
                or proof.get("validation_status") != "Validated"
                or not proof.get("validator")
                or not proof.get("validated_at")
                or evidence_freshness(proof, requirement.get("max_age_days", 90), now)
                not in {"Current", "Expiring Soon"}
            ):
                raise FoundationError(
                    "Select fresh, validated canonical evidence mapped to this control and scope."
                )
            verification = evaluate_requirement(requirement, bundle, now)
            if verification["result"] != "PASS":
                raise FoundationError(
                    (
                        "Verification has not passed this requirement. Keep "
                        "remediation open and review the evidence."
                    )
                )
        cursor.execute(
            "UPDATE securescope_improvement_actions SET "
            "status=%s,updated_at=NOW() WHERE client_id=%s AND id=%s",
            (status, client_id, identity),
        )
        _append_audit_event(
            cursor,
            client_id,
            event_type="requirement_remediation_updated",
            entity_type="control_profile",
            entity_id=action["control_id"],
            actor=actor,
            summary=f'Remediation #{identity}: {action["status"]} → {status}',
            payload={
                "scope_id": scope,
                "engagement_id": engagement,
                "action_id": identity,
                "note": note,
                "evidence_id": evidence_id,
                "verification": json.loads(json.dumps(verification, default=str)),
            },
        )


def configured_profiles(client: str, actor: str, engagement: int, scope: int) -> list[dict]:
    """List current scope configurations for compact dashboards and asset backlinks.

    Args:
        client: Tenant name.
        actor: Authenticated principal.
        engagement: Selected engagement.
        scope: Selected scope.
    Returns:
        Latest scoped profile metadata, with no raw provider payloads.
    Raises:
        FoundationError: For unauthorized context or failed reads.
    """
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope)
        cursor.execute(
            "SELECT DISTINCT ON (control_id) "
            "control_id,control_name,control_owner,profile_version,assessment"
            "_scope FROM securescope_control_assessment_profiles WHERE "
            "client_id=%s AND assessment_scope->'implementation_requirements'"
            "->>'scope_id'=%s ORDER BY control_id,profile_version DESC",
            (client_id, str(scope)),
        )
        return [dict(row) for row in cursor.fetchall()]


def automated_candidates():
    """Yield enabled profiles in deterministic batches for the existing worker.

    Args:
        None.
    Returns:
        Iterator of latest scoped configurations and their enabling principals.
    Raises:
        DatabaseError: If a candidate batch cannot be read.
    """
    from psycopg2.extras import RealDictCursor

    from securescope.persistence.db_service import connect

    offset = 0
    while True:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "WITH current AS (SELECT DISTINCT ON "
                    "(p.client_id,p.control_id,p.assessment_scope->"
                    "'implementation_requirements'->>'scope_id') "
                    "p.*,c.name AS client_name FROM securescope_control_assessment_profiles p "
                    "JOIN securescope_clients c ON c.id=p.client_id ORDER BY "
                    "p.client_id,p.control_id,p.assessment_scope->"
                    "'implementation_requirements'->>'scope_id',p.profile_version DESC) "
                    "SELECT client_name,control_id,assessment_scope FROM current WHERE "
                    "assessment_scope->'implementation_requirements'->>"
                    "'continuous_auto_assurance'='true' ORDER BY client_id,control_id,"
                    "assessment_scope->'implementation_requirements'->>'scope_id' "
                    "LIMIT 200 OFFSET %s",
                    (offset,),
                )
                batch = [dict(row) for row in cursor.fetchall()]
        yield from batch
        if len(batch) < 200:
            break
        offset += len(batch)


def assurance_overview(
    client: str, actor: str, engagement: int, scope: int, overview_rows: list[dict]
) -> list[dict]:
    """Evaluate current scoped summaries in bounded bulk reads without raw scanner data.

    Args:
        client: Current tenant name.
        actor: Authenticated principal.
        engagement: Current engagement ID.
        scope: Current scope ID.
        overview_rows: Canonical latest assessment overview records.
    Returns:
        Current independent control dimensions and actionable requirement summaries.
    Raises:
        FoundationError: For denied access or database errors.
    """
    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope)
        documents = _documents(cursor, client_id, engagement, scope)
        evidence = _evidence(cursor, client_id, "", engagement, scope)
        cursor.execute(
            "SELECT v.* FROM securescope_scope_versions v JOIN securescope_scope_definitions s "
            "ON s.client_id=v.client_id AND s.id=v.scope_id AND s.current_approved_version_id=v.id "
            "WHERE v.client_id=%s AND v.scope_id=%s AND v.status='Approved'",
            (client_id, scope),
        )
        scope_version = dict(cursor.fetchone() or {})
        cursor.execute(
            "SELECT i.* FROM securescope_soa_items i WHERE i.client_id=%s "
            "AND i.soa_version_id=(SELECT v.id FROM securescope_soa_versions "
            "v JOIN securescope_engagement_record_links l ON "
            "l.client_id=v.client_id AND l.soa_version_id=v.id WHERE "
            "v.client_id=%s AND v.status='Approved' AND l.engagement_id=%s "
            "AND l.scope_id=%s AND l.link_origin <> 'Legacy backfill' ORDER "
            "BY v.version_number DESC LIMIT 1)",
            (client_id, client_id, engagement, scope),
        )
        soa = {r["control_id"]: dict(r) for r in cursor.fetchall()}
        cursor.execute(
            "SELECT u.email FROM securescope_workspace_memberships m JOIN "
            "securescope_users u ON u.id=m.user_id WHERE m.client_id=%s AND "
            "m.active AND u.active AND m.role IN "
            "('Administrator','Consultant')",
            (client_id,),
        )
        validators = {r["email"] for r in cursor.fetchall()}
        cursor.execute(
            "SELECT a.id,a.ip FROM securescope_assets a WHERE a.client_id=%s", (client_id,)
        )
        asset_ips = {r["id"]: r["ip"] for r in cursor.fetchall()}
        cursor.execute(
            "SELECT id,title,asset_identity FROM securescope_findings WHERE "
            "client_id=%s AND severity IN ('High','Critical') AND "
            "lifecycle_status NOT IN ('Closed','False positive')",
            (client_id,),
        )
        findings = [dict(r) for r in cursor.fetchall()]
        cursor.execute(
            "SELECT id,control_id FROM securescope_improvement_actions WHERE "
            "client_id=%s AND affected_scope=%s AND status NOT IN "
            "('Completed','Cancelled')",
            (client_id, f"ISMS Scope #{scope}"),
        )
        actions = [dict(r) for r in cursor.fetchall()]
        cursor.execute(
            "SELECT control_references FROM securescope_risk_register "
            "WHERE client_id=%s AND primary_scope_id=%s",
            (client_id, scope),
        )
        linked_risks = [dict(row) for row in cursor.fetchall()]
        assessment_ids = [r["assessment_id"] for r in overview_rows if r.get("assessment_id")]
        cursor.execute(
            (
                "SELECT * FROM securescope_control_criterion_results WHERE "
                "client_id=%s AND assessment_id=ANY(%s)"
            ),
            (client_id, assessment_ids),
        )
        criteria = [dict(r) for r in cursor.fetchall()]
        output = []
        for source_row in overview_rows:
            from copy import deepcopy

            from securescope.grc.requirement_templates import merge_baseline

            row = deepcopy(source_row)
            config = (row.get("assessment_scope") or {}).get("implementation_requirements") or {}
            if config.get("scope_id") not in {None, scope}:
                continue
            proposed, pending = merge_baseline(row["control_id"], config)
            if pending:
                config = dict(config, requirements=proposed, baseline_preview=True)
                row["assessment_scope"] = dict(row.get("assessment_scope") or {})
                row["assessment_scope"]["implementation_requirements"] = config
            assessment = (
                dict(
                    created_at=row.get("assessed_at"),
                    assessment_status=row.get("assessment_status"),
                    validation_status=row.get("validation_status"),
                )
                if row.get("assessed_at") and config.get("scope_id") == scope
                else {}
            )
            bundle = dict(
                profile=row,
                scope_id=scope,
                engagement_id=engagement,
                scope=scope_version,
                documents=documents,
                requirement_evidence=[e for e in evidence if e["control_id"] == row["control_id"]],
                soa=soa.get(row["control_id"], {}),
                assessment=assessment,
                criteria=[c for c in criteria if c["assessment_id"] == row.get("assessment_id")],
                validator_authorized=bool(assessment) and row.get("validator") in validators,
            )
            ips = {
                asset_ips.get(i)
                for requirement in config.get("requirements", [])
                for i in requirement.get("asset_ids", [])
            }
            bundle["blockers"] = [
                f"Finding #{r['id']}: {r['title']}" for r in findings if r["asset_identity"] in ips
            ]
            bundle["blockers"] += [
                f"Remediation #{r['id']} is unresolved."
                for r in actions
                if r["control_id"] == row["control_id"]
            ]
            apply_safety_signals(bundle, datetime.now(timezone.utc))
            result = evaluate_assurance(bundle, now=datetime.now(timezone.utc))
            output.append(
                dict(
                    control_id=row["control_id"],
                    title=row["control_name"],
                    owner=row.get("control_owner"),
                    open_work=sum(a["control_id"] == row["control_id"] for a in actions),
                    linked_risks=sum(
                        row["control_id"] in (risk.get("control_references") or [])
                        for risk in linked_risks
                    ),
                    result=result,
                )
            )
        return output


def policy_control_references(
    client: str, actor: str, engagement: int, scope: int, policy_id: str
) -> list[str]:
    """Resolve reverse policy links from current scoped requirement relationships.

    Args:
        client: Tenant name.
        actor: Authenticated principal.
        engagement: Selected engagement ID.
        scope: Selected scope ID.
        policy_id: Canonical policy identity.
    Returns:
        Existing control IDs whose current requirements reference this policy.
    Raises:
        FoundationError: On denied access or failed reads.
    """
    return [
        p["control_id"]
        for p in configured_profiles(client, actor, engagement, scope)
        if any(
            policy_id in r.get("policy_ids", [])
            for r in p["assessment_scope"]
            .get("implementation_requirements", {})
            .get("requirements", [])
        )
    ]


def collect_inventory_evidence(
    client: str, control_id: str, actor: str, engagement: int, scope: int
) -> int:
    """Collect current asset/classification facts into the canonical Evidence store.

    Args:
        client: Tenant name.
        control_id: Existing profile reference.
        actor: Authorized requesting principal.
        engagement: Current engagement.
        scope: Current scope.
    Returns:
        New immutable evidence source identity, pending validation unless automation was authorized.
    Raises:
        FoundationError: If no scoped assets are configured or permissions fail.
        EvidenceRepositoryError: If the source or mapping cannot be saved.
    """
    from datetime import timedelta

    from securescope.persistence.evidence_repository import (
        create_evidence_record,
        review_evidence_record,
    )

    with workspace_cursor(client) as (cursor, client_id):
        _context(cursor, client_id, actor, engagement, scope, write=True)
        profile = _load_bundle(cursor, client_id, control_id, scope)["profile"]
        config = profile["assessment_scope"].get("implementation_requirements") or {}
        asset_ids = sorted(
            {
                i
                for r in config.get("requirements", [])
                for i in r.get("asset_ids", [])
                if r.get("rule") in {"Classification coverage", "Asset discovery"}
            }
        )
        if not asset_ids:
            raise FoundationError(
                "Configure applicable assets on inventory/classification requirements first."
            )
        cursor.execute(
            "SELECT id,ip,payload->>'information_classification' AS "
            "classification FROM securescope_assets WHERE client_id=%s AND "
            "id=ANY(%s)",
            (client_id, asset_ids),
        )
        assets = [dict(row) for row in cursor.fetchall()]
        if {r["id"] for r in assets} != set(asset_ids):
            raise FoundationError(
                "An applicable asset was removed. Review the requirement boundary."
            )
    now = datetime.now(timezone.utc)
    facts = dict(
        complete=True,
        asset_ids=asset_ids,
        asset_ips=[r["ip"] for r in assets],
        classification=dict(
            evaluated_asset_ids=asset_ids,
            satisfied_asset_ids=[
                r["id"]
                for r in assets
                if str(r.get("classification") or "").lower()
                not in {"", "unknown", "unclassified", "not set", "not classified"}
            ],
        ),
    )
    identity = create_evidence_record(
        client,
        tool_id="asset_inventory",
        collection_method="Existing worker",
        evidence_type="Asset inventory and classification observation",
        title=f"{control_id} · Scoped Asset Inventory",
        summary=f"{len(assets)} configured assets observed in the canonical inventory.",
        scope_description=f"ISMS Scope #{scope}",
        source_asset_or_system="Canonical Asset Management",
        owner=profile.get("control_owner") or actor,
        submitted_by=actor,
        collected_at=now,
        expires_at=now + timedelta(days=30),
        confidence="High",
        normalized={"metadata": {"assurance": facts}, "observations": []},
        suggested_controls=[control_id],
    )
    link_evidence_scope(
        client,
        control_id,
        actor,
        engagement,
        scope,
        identity,
        "Assets explicitly configured in this scoped Control Profile; "
        "collected from canonical inventory.",
    )
    if config.get("continuous_auto_assurance"):
        review_evidence_record(
            client,
            identity,
            decision="Validated",
            validator=actor,
            comment=(
                "Machine inventory facts validated under the "
                "administrator-enabled continuous assurance configuration; does "
                "not approve governance decisions."
            ),
            approved_controls=[control_id],
        )
    return identity


def seed_control_baseline(
    client: str, control_id: str, actor: str, engagement: int, scope: int, view: dict
) -> bool:
    """Persist authored baseline criteria once using canonical profile versioning.

    Args:
        client: Workspace name.
        control_id: Canonical entry reference.
        actor: Authorized session principal.
        engagement: Selected engagement.
        scope: Selected ISMS Scope.
        view: Authorized current workspace snapshot.
    Returns:
        True when a new version was created, otherwise False.
    Raises:
        FoundationError: If permissions or links fail validation.
        GrcRepositoryError: If the profile was changed concurrently.
    """
    from securescope.grc.requirement_templates import merge_baseline

    profile = view["bundle"]["profile"]
    config = profile.get("assessment_scope", {}).get("implementation_requirements") or {}
    requirements, needed = merge_baseline(control_id, config)
    if not needed or view["role"] not in {"Administrator", "Consultant"}:
        return False
    save_requirements(
        client,
        control_id,
        actor,
        engagement,
        scope,
        profile["profile_version"],
        requirements,
        auto=bool(config.get("continuous_auto_assurance")),
        owner=profile.get("control_owner") or actor,
        seed_baseline=True,
    )
    return True
