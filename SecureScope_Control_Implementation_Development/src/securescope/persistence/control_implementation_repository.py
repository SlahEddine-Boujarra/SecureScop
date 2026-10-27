"""Reuse profile versions and immutable encrypted evidence audit snapshots."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from securescope.grc.control_implementation import evaluate_implementation, input_fingerprint
from securescope.integrations.credential_store import open_configuration, seal_configuration
from securescope.persistence.evidence_repository import _append_audit_event
from securescope.persistence.foundation_repository import (
    FoundationError,
    member_role,
    workspace_cursor,
)
from securescope.persistence.grc_repository import create_profile_version
from securescope.policies.repository import policy_rows

LOGGER = logging.getLogger(__name__)
REVIEWERS = {"Administrator", "Consultant"}
EVENT = "control_implementation_evaluated"


def _documents(cursor: Any, client_id: int, engagement: int, scope: int) -> list[dict]:
    """Read existing document metadata without decrypting document bodies.

    Args:
        cursor: Workspace transaction cursor.
        client_id: Trusted tenant identifier.
        engagement: Selected engagement identifier.
        scope: Selected scope identifier.
    Returns:
        Current scoped policy-library metadata.
    Raises:
        DatabaseError: If the lookup fails.
    """
    cursor.execute(
        "SELECT * FROM securescope_foundation_versions WHERE client_id=%s "
        "AND engagement_id=%s AND scope_id=%s AND register_key='policy' "
        "ORDER BY version DESC LIMIT 1",
        (client_id, engagement, scope),
    )
    snapshot = cursor.fetchone()
    rows = policy_rows(dict(snapshot), scope) if snapshot else []
    return [
        {
            key: row.get(key)
            for key in (
                "policy_id",
                "policy_version",
                "title",
                "status",
                "controls",
                "review_date",
                "updated_at",
            )
        }
        for row in rows
    ]


def _load_bundle(cursor: Any, client_id: int, control_id: str, scope_id: int | None = None) -> dict:
    """Load current implementation inputs from existing client-scoped tables.

    Args:
        cursor: Dict cursor inside an authorized workspace transaction.
        client_id: Trusted workspace identifier.
        control_id: Existing control reference.
    Returns:
        JSON-compatible versioned inputs.
    Raises:
        FoundationError: If the control is outside the workspace.
        DatabaseError: If scoped queries fail.
    """
    cursor.execute(
        "SELECT * FROM securescope_control_assessment_profiles WHERE client_id=%s "
        "AND control_id=%s AND (%s IS NULL OR "
        "assessment_scope->'implementation_requirements'->>'scope_id'=%s OR "
        "assessment_scope->'implementation_requirements'->>'scope_id' IS NULL) "
        "ORDER BY (assessment_scope->'implementation_requirements'->>'scope_id'=%s) "
        "DESC NULLS LAST, profile_version DESC LIMIT 1",
        (client_id, control_id, scope_id, str(scope_id), str(scope_id)),
    )
    profile = cursor.fetchone()
    if not profile:
        raise FoundationError("Select an existing control in this workspace.")
    profile = dict(profile)
    bundle = {"profile": profile}
    for name, table, order in (
        ("target", "securescope_control_targets", "target_version"),
        ("assessment", "securescope_control_assessments", "id"),
    ):
        cursor.execute(
            f"SELECT * FROM {table} WHERE client_id=%s AND profile_id=%s "
            f"ORDER BY {order} DESC LIMIT 1",
            (client_id, profile["id"]),
        )
        bundle[name] = dict(cursor.fetchone() or {})
    assessment = bundle["assessment"]
    for name, table in (
        ("criteria", "securescope_control_criterion_results"),
        ("dimensions", "securescope_control_dimension_results"),
        ("tests", "securescope_control_effectiveness_tests"),
        ("evidence", "securescope_control_evidence"),
    ):
        cursor.execute(
            f"SELECT * FROM {table} WHERE client_id=%s AND assessment_id=%s ORDER BY id",
            (client_id, assessment.get("id", -1)),
        )
        bundle[name] = [dict(row) for row in cursor.fetchall()]
    references = sorted(
        {
            int(match)
            for e in bundle["evidence"]
            for match in re.findall(r"Evidence #(\d+)", e.get("raw_evidence_reference") or "")
        }
    )
    bundle["linked_evidence"] = []
    for evidence_id in references:
        cursor.execute(
            "SELECT evidence.id,evidence.collected_at,evidence.expires_at,evi"
            "dence.validation_status,evidence.tool_id,evidence.collection_method,"
            "evidence.verification_origin,evidence.source_key,"
            "evidence.validator,mapping.mapping_origin,"
            "evidence.freshness_status,mapping.consultant_approved FROM "
            "securescope_evidence_records evidence "
            "JOIN securescope_evidence_control_mappings mapping ON "
            "mapping.client_id=evidence.client_id "
            "AND mapping.evidence_id=evidence.id WHERE evidence.client_id=%s AND evidence.id=%s "
            "AND mapping.control_id=%s",
            (client_id, evidence_id, control_id),
        )
        bundle["linked_evidence"].append(dict(cursor.fetchone() or {"id": evidence_id}))
    validator = assessment.get("validator") or ""
    bundle["validator_authorized"] = (
        bool(validator) and member_role(cursor, client_id, validator) in REVIEWERS
    )
    config = (profile.get("assessment_scope") or {}).get("implementation_requirements") or {}
    cursor.execute(
        "SELECT * FROM securescope_scope_versions WHERE client_id=%s AND engagement_id=%s "
        "AND scope_id=%s ORDER BY version_number DESC LIMIT 1",
        (client_id, config.get("engagement_id", -1), config.get("scope_id", -1)),
    )
    bundle["scope"] = dict(cursor.fetchone() or {})
    bundle["documents"] = _documents(
        cursor, client_id, config.get("engagement_id", -1), config.get("scope_id", -1)
    )
    cursor.execute(
        "SELECT item.* FROM securescope_soa_items item WHERE "
        "item.client_id=%s AND item.control_id=%s "
        "AND item.soa_version_id=(SELECT id FROM securescope_soa_versions WHERE client_id=%s "
        "AND status='Approved' AND EXISTS (SELECT 1 FROM securescope_engagement_record_links link "
        "WHERE link.client_id=securescope_soa_versions.client_id AND link."
        "soa_version_id=securescope_soa_versions.id "
        "AND link.engagement_id=%s AND link.scope_id=%s AND link.link_origin <> 'Legacy backfill') "
        "ORDER BY version_number DESC LIMIT 1)",
        (
            client_id,
            control_id,
            client_id,
            config.get("engagement_id", -1),
            config.get("scope_id", -1),
        ),
    )
    bundle["soa"] = dict(cursor.fetchone() or {})
    return json.loads(json.dumps(bundle, default=str))


def implementation_view(client: str, control_id: str, actor: str) -> dict:
    """Read the live evaluation separately from the last immutable snapshot.

    Args:
        client: Workspace name.
        control_id: Existing control reference.
        actor: Trusted session identity.
    Returns:
        Current result, inputs, previous snapshot and change flag.
    Raises:
        FoundationError: If membership or scoped reads fail.
        CredentialStoreError: If snapshot decryption fails.
    """
    with workspace_cursor(client) as (cursor, client_id):
        if not member_role(cursor, client_id, actor):
            raise FoundationError("An active workspace membership is required.")
        bundle = _load_bundle(cursor, client_id, control_id)
        current = evaluate_implementation(bundle, now=datetime.now(timezone.utc))
        cursor.execute(
            "SELECT event_payload FROM securescope_evidence_audit_events WHERE client_id=%s "
            "AND event_type=%s AND entity_type='control_profile' AND "
            "entity_id=%s ORDER BY id DESC LIMIT 1",
            (client_id, EVENT, control_id),
        )
        record = cursor.fetchone()
        previous = (
            open_configuration(record["event_payload"]["snapshot_ciphertext"].encode())
            if record
            else None
        )
        changed = bool(
            previous
            and (
                previous["result"]["input_fingerprint"] != current["input_fingerprint"]
                or previous["result"]["status"] != current["status"]
                or previous["result"].get("engine_version") != current["engine_version"]
            )
        )
        return dict(bundle=bundle, current=current, previous=previous, inputs_changed=changed)


def save_implementation_evaluation(client: str, control_id: str, actor: str, expected: str) -> dict:
    """Recompute the result and append encrypted inputs to existing audit history.

    Args:
        client: Workspace name.
        control_id: Existing control reference.
        actor: Trusted reviewer identity.
        expected: Fingerprint originally presented to the reviewer.
    Returns:
        The server-computed result recorded in history.
    Raises:
        FoundationError: If unauthorized or the preview is stale.
        CredentialStoreError: If snapshot encryption fails.
    """
    with workspace_cursor(client) as (cursor, client_id):
        if member_role(cursor, client_id, actor) not in REVIEWERS:
            LOGGER.warning("Denied implementation evaluation write")
            raise FoundationError("Consultant or Administrator membership is required.")
        bundle = _load_bundle(cursor, client_id, control_id)
        if input_fingerprint(bundle) != expected:
            raise FoundationError("Implementation inputs changed. Reload and review before saving.")
        result = evaluate_implementation(bundle, now=datetime.now(timezone.utc))
        encrypted = seal_configuration(
            dict(result=result, inputs=bundle, recorded_by=actor)
        ).decode()
        _append_audit_event(
            cursor,
            client_id,
            event_type=EVENT,
            entity_type="control_profile",
            entity_id=control_id,
            actor=actor,
            summary="Recorded evidence-based implementation evaluation",
            payload={"snapshot_ciphertext": encrypted},
        )
        return result


def document_choices(client: str, actor: str, engagement: int, scope: int) -> list[dict]:
    """Resolve existing documents within the active client context.

    Args:
        client: Workspace name.
        actor: Trusted session principal.
        engagement: Selected engagement identifier.
        scope: Selected scope identifier.
    Returns:
        Document metadata from the existing policy library.
    Raises:
        FoundationError: If the actor is not a workspace member.
    """
    with workspace_cursor(client) as (cursor, client_id):
        if not member_role(cursor, client_id, actor):
            raise FoundationError("An active workspace membership is required.")
        return _documents(cursor, client_id, engagement, scope)


def save_implementation_requirements(
    client: str,
    control_id: str,
    actor: str,
    expected_version: int,
    *,
    engagement: int,
    scope: int,
    policy_ids: list[str],
    procedure_ids: list[str],
    policy_rationale: str,
    procedure_rationale: str,
    review_days: int,
    criteria: list[str],
) -> int:
    """Save requirements as a version of the existing Control Profile.

    Args:
        client: Workspace name.
        control_id: Existing control reference.
        actor: Trusted session principal.
        expected_version: Profile version opened for editing.
        engagement: Selected engagement identifier.
        scope: Selected scope identifier.
        policy_ids: Required policy document identities.
        procedure_ids: Required procedure document identities.
        policy_rationale: Reason a separate policy is unnecessary, if none selected.
        procedure_rationale: Reason a separate procedure is unnecessary, if none selected.
        review_days: Maximum evidence and assessment age in days.
        criteria: Required observable implementation criteria.
    Returns:
        Newly created profile version number.
    Raises:
        FoundationError: On invalid requirements, context, permissions or stale profile.
        GrcRepositoryError: If the profile version cannot be saved.
    """
    criteria = [item.strip() for item in criteria if item.strip()]
    if not criteria or len(criteria) > 50 or any(len(item) > 2000 for item in criteria):
        raise FoundationError("Define 1 to 50 criteria, up to 2000 characters each.")
    if len(set(criteria)) != len(criteria):
        raise FoundationError("Implementation criteria must be unique.")
    if type(review_days) is not int or not 1 <= review_days <= 3650:
        raise FoundationError("Choose a review interval from 1 to 3650 days.")
    if any(len(text) > 2000 for text in (policy_rationale, procedure_rationale)):
        raise FoundationError("Document rationales must be at most 2000 characters.")
    with workspace_cursor(client) as (cursor, client_id):
        if member_role(cursor, client_id, actor) not in REVIEWERS:
            raise FoundationError("Consultant or Administrator membership is required.")
        profile = _load_bundle(cursor, client_id, control_id)["profile"]
        if profile["profile_version"] != expected_version:
            raise FoundationError("Profile changed. Reload before saving requirements.")
        cursor.execute(
            "SELECT id FROM securescope_scope_definitions WHERE client_id=%s "
            "AND engagement_id=%s AND id=%s",
            (client_id, engagement, scope),
        )
        if not cursor.fetchone():
            raise FoundationError("Select a scope in this workspace and engagement.")
        cursor.execute(
            "SELECT id, status FROM securescope_scope_versions WHERE client_id=%s "
            "AND engagement_id=%s AND scope_id=%s ORDER BY version_number DESC LIMIT 1",
            (client_id, engagement, scope),
        )
        scope_version = cursor.fetchone()
        if not scope_version or scope_version["status"] != "Approved":
            raise FoundationError(
                "Approve the selected scope before saving implementation requirements."
            )
        choices = {d["policy_id"]: d for d in _documents(cursor, client_id, engagement, scope)}
        config = dict(
            reviewed=True,
            scope_version_id=scope_version["id"],
            review_days=review_days,
            engagement_id=engagement,
            scope_id=scope,
            criteria=criteria,
        )
        for kind, selected, rationale in (
            ("policy", policy_ids, policy_rationale),
            ("procedure", procedure_ids, procedure_rationale),
        ):
            if not selected and not rationale.strip():
                raise FoundationError(f"Link a {kind} or explain why it is unnecessary.")
            if any(
                key not in choices or control_id not in (choices[key].get("controls") or [])
                for key in selected
            ):
                raise FoundationError(
                    "Choose documents mapped to this control in the selected scope."
                )
            config[kind + "_links"] = [
                dict(id=key, version=choices[key]["policy_version"])
                for key in sorted(set(selected))
            ]
            config[kind + "_rationale"] = rationale.strip()
    # Rechecks identity and the opened profile version within the existing write transaction.
    return create_profile_version(
        client,
        control_id,
        measurement_model=profile["measurement_model"],
        control_owner=profile["control_owner"],
        assessment_owner=profile["assessment_owner"],
        assessment_scope={**profile["assessment_scope"], "implementation_requirements": config},
        assessment_methods=profile["assessment_methods"],
        evidence_requirements=profile["evidence_requirements"],
        automation_level=profile["automation_level"],
        supported_data_sources=profile["supported_data_sources"],
        actor=actor,
        expected_profile_version=expected_version,
    )
