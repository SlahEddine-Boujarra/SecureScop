"""Versioned control assessment, SoA and gap persistence for SecureScope."""

from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, timezone
from typing import Any, Mapping, Sequence

from psycopg2.extras import Json, RealDictCursor

from securescope.core.gap_assessment_domain import (
    ASSESSMENT_MODELS,
    ASSESSMENT_STATUSES,
    ASSURANCE_DIMENSIONS,
    CRITERION_RESULTS,
    TEST_RESULTS,
    CoverageResult,
    calculate_coverage,
    validate_assessment_status,
)
from securescope.grc.control_catalog import ISO_CONTROL_CATALOG
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


class GrcRepositoryError(RuntimeError):
    """Raised when control-assessment persistence fails."""


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve an existing client inside the current transaction.

    Args:
        cursor: Active PostgreSQL cursor.
        client_name: Exact workspace name.

    Returns:
        Positive client identifier.

    Raises:
        GrcRepositoryError: If the workspace does not exist.
    """

    cursor.execute(
        "SELECT id FROM securescope_clients WHERE name = %s;",
        (str(client_name).strip(),),
    )
    row = cursor.fetchone()
    if not row:
        raise GrcRepositoryError(f"Client workspace not found: {client_name}")
    return int(row[0] if not isinstance(row, dict) else row["id"])


def _default_profile(control_id: str, catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Build a conservative default profile for one ISO requirement or control.

    Args:
        control_id: ISO/IEC 27001 Annex A.8 control identifier.
        catalog: Existing SecureScope control catalog entry.

    Returns:
        Default version-one profile fields.

    Raises:
        GrcRepositoryError: If the control identity is empty.
    """

    if not control_id.strip():
        raise GrcRepositoryError("Control profile requires an identifier.")
    quantitative_controls = {"A.8.1", "A.8.8"}
    effectiveness_controls = {"A.8.13", "A.8.16", "A.8.17", "A.8.29"}
    composite_controls = {"A.8.8", "A.8.13", "A.8.15", "A.8.16", "A.8.17"}
    if control_id in composite_controls:
        measurement_model = "composite"
    elif control_id in quantitative_controls:
        measurement_model = "quantitative_coverage"
    elif control_id in effectiveness_controls:
        measurement_model = "effectiveness_test"
    else:
        measurement_model = "checklist"
    supported_sources = list(catalog.get("supported_data_sources") or [])
    automation_level = str(catalog.get("automation_level") or "Manual")
    control_name = str(catalog.get("name") or control_id)
    description = str(
        catalog.get("description") or f"Assess implementation and effectiveness of {control_name}."
    )
    return {
        "control_id": control_id,
        "control_name": control_name,
        "control_objective": description,
        "expected_security_outcome": description,
        "measurement_model": measurement_model,
        "assessment_methods": ["Examine", "Interview", "Test", "Observe", "Measure"],
        "evidence_requirements": list(
            catalog.get("evidence_requirements")
            or [
                "Traceable evidence for design and implementation",
                "Evidence covering the approved scope and assessment period",
                "Effectiveness evidence where the control outcome must be tested",
                "Authorized analyst validation",
            ]
        ),
        "measurement_criteria": {
            "preserve_qualitative_results": True,
            "do_not_infer_compliance_from_scanners": True,
        },
        "target_state_criteria": {
            "design_adequacy": "Reviewed",
            "implementation": "Implemented",
            "scope_coverage": "Approved target achieved",
            "operating_effectiveness": "Validated",
            "evidence_assurance": "Current and sufficient",
            "validation": "Authorized",
        },
        "effectiveness_tests": (
            ["Control-specific effectiveness test and retained result"]
            if measurement_model in {"effectiveness_test", "composite"}
            else []
        ),
        "validation_requirements": {
            "authorized_reviewer": True,
            "scanner_only_conclusion_forbidden": True,
        },
        "automation_level": automation_level,
        "supported_data_sources": supported_sources,
    }


def seed_control_profiles(client_name: str) -> int:
    """Create version-one profiles for clauses 4-10 and all Annex A controls.

    Args:
        client_name: Exact workspace name.

    Returns:
        Number of profiles newly inserted.

    Raises:
        GrcRepositoryError: If PostgreSQL seeding fails.
    """

    run_pending_migrations()
    inserted = 0
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                for control_id, catalog in ISO_CONTROL_CATALOG.items():
                    profile = _default_profile(control_id, catalog)
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_assessment_profiles (
                            client_id,
                            control_id,
                            control_name,
                            profile_version,
                            control_objective,
                            expected_security_outcome,
                            assessment_methods,
                            evidence_requirements,
                            measurement_model,
                            measurement_criteria,
                            target_state_criteria,
                            effectiveness_tests,
                            validation_requirements,
                            automation_level,
                            supported_data_sources,
                            approval_status
                        )
                        VALUES (
                            %s, %s, %s, 1, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, 'Draft'
                        )
                        ON CONFLICT (client_id, control_id, profile_version)
                        DO NOTHING;
                        """,
                        (
                            client_id,
                            profile["control_id"],
                            profile["control_name"],
                            profile["control_objective"],
                            profile["expected_security_outcome"],
                            Json(profile["assessment_methods"]),
                            Json(profile["evidence_requirements"]),
                            profile["measurement_model"],
                            Json(profile["measurement_criteria"]),
                            Json(profile["target_state_criteria"]),
                            Json(profile["effectiveness_tests"]),
                            Json(profile["validation_requirements"]),
                            profile["automation_level"],
                            Json(profile["supported_data_sources"]),
                        ),
                    )
                    inserted += int(cursor.rowcount)
        return inserted
    except DatabaseError as exc:
        LOGGER.error("Control profile seeding failed for %s: %s", client_name, exc)
        raise GrcRepositoryError(str(exc)) from exc


def list_control_overview(client_name: str, *, scope_id: int | None = None) -> list[dict[str, Any]]:
    """List every latest control profile with its latest assessment and target.

    Args:
        client_name: Exact workspace name.

    Returns:
        Workspace-scoped control overview rows, including unassessed controls.

    Raises:
        GrcRepositoryError: If PostgreSQL cannot load the overview.
    """

    seed_control_profiles(client_name)
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    WITH latest_profiles AS (
                        SELECT DISTINCT ON (control_id) *
                        FROM securescope_control_assessment_profiles
                        WHERE client_id = %s AND (%s IS NULL OR
                            assessment_scope->'implementation_requirements'->>'scope_id'=%s OR
                            assessment_scope->'implementation_requirements'->>'scope_id' IS NULL)
                        ORDER BY control_id,
                            (assessment_scope->'implementation_requirements'->>'scope_id'=%s)
                            DESC NULLS LAST, profile_version DESC
                    )
                    SELECT
                        profile.id AS profile_id,
                        profile.control_id,
                        profile.control_name,
                        profile.profile_version,
                        profile.control_objective,
                        profile.expected_security_outcome,
                        profile.applicability,
                        profile.inclusion_justification,
                        profile.exclusion_justification,
                        profile.control_owner,
                        profile.assessment_owner,
                        profile.assessment_scope,
                        profile.assessment_methods,
                        profile.evidence_requirements,
                        profile.measurement_model,
                        profile.automation_level,
                        profile.supported_data_sources,
                        profile.approval_status,
                        target.id AS target_id,
                        target.target_version,
                        target.target_description,
                        target.target_value,
                        target.unit AS target_unit,
                        target.target_date,
                        COALESCE(
                            assessment.assessment_status,
                            'Not assessed'
                        ) AS assessment_status,
                        assessment.current_value,
                        assessment.target_value AS assessed_target_value,
                        assessment.remaining_gap,
                        assessment.additional_required,
                        assessment.evidence_freshness,
                        assessment.confidence,
                        assessment.validation_status,
                        assessment.assurance_score,
                        assessment.created_at AS assessed_at,
                        assessment.id AS assessment_id,
                        assessment.validator,
                        assessment.current_state,
                        assessment.scope_definition,
                        COALESCE(evidence_pool.approved_evidence_count, 0)
                            AS approved_evidence_count,
                        COALESCE(evidence_pool.current_evidence_count, 0)
                            AS current_evidence_count,
                        evidence_pool.latest_evidence_at,
                        COALESCE(assessment_evidence.current_count, 0)
                            AS assessment_current_evidence_count,
                        soa.applicability AS soa_applicability,
                        soa.exclusion_justification AS soa_exclusion_justification,
                        soa.approved AS soa_approved
                    FROM latest_profiles profile
                    LEFT JOIN LATERAL (
                        SELECT *
                        FROM securescope_control_targets target_row
                        WHERE target_row.client_id = profile.client_id
                          AND target_row.profile_id = profile.id
                        ORDER BY target_row.target_version DESC
                        LIMIT 1
                    ) target ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT *
                        FROM securescope_control_assessments assessment_row
                        WHERE assessment_row.client_id = profile.client_id
                          AND assessment_row.profile_id = profile.id
                        ORDER BY assessment_row.created_at DESC
                        LIMIT 1
                    ) assessment ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT
                            COUNT(DISTINCT evidence.id) AS approved_evidence_count,
                            COUNT(DISTINCT evidence.id) FILTER (
                                WHERE evidence.freshness_status IN (
                                    'Current', 'Approaching expiration'
                                )
                                  AND (evidence.expires_at IS NULL
                                       OR evidence.expires_at > NOW())
                            ) AS current_evidence_count,
                            MAX(evidence.collected_at) AS latest_evidence_at
                        FROM securescope_evidence_control_mappings mapping
                        JOIN securescope_evidence_records evidence
                          ON evidence.client_id = mapping.client_id
                         AND evidence.id = mapping.evidence_id
                        WHERE mapping.client_id = profile.client_id
                          AND mapping.control_id = profile.control_id
                          AND mapping.consultant_approved = TRUE
                          AND evidence.validation_status = 'Validated'
                    ) evidence_pool ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT COUNT(*) AS current_count
                        FROM securescope_control_evidence evidence
                        WHERE evidence.client_id = profile.client_id
                          AND evidence.assessment_id = assessment.id
                          AND evidence.validation_status = 'Validated'
                          AND evidence.freshness_status IN ('Current', 'Approaching expiration')
                          AND (evidence.expiration_date IS NULL
                               OR evidence.expiration_date > NOW())
                    ) assessment_evidence ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT item.applicability, item.exclusion_justification, item.approved
                        FROM securescope_soa_items item
                        WHERE item.client_id = profile.client_id
                          AND item.control_id = profile.control_id
                          AND item.soa_version_id = (
                              SELECT version.id FROM securescope_soa_versions version
                              WHERE version.client_id = profile.client_id
                                AND version.status = 'Approved'
                                AND EXISTS (SELECT 1 FROM securescope_engagement_record_links link
                                  WHERE link.client_id=version.client_id
                                  AND link.soa_version_id=version.id
                                  AND link.link_origin <> 'Legacy backfill'
                                  AND link.scope_id::text=profile.assessment_scope
                                    ->'implementation_requirements'->>'scope_id'
                                  AND link.engagement_id::text=profile.assessment_scope
                                    ->'implementation_requirements'->>'engagement_id')
                              ORDER BY version.version_number DESC LIMIT 1
                          )
                    ) soa ON TRUE
                    ORDER BY profile.control_id;
                    """,
                    (client_id, scope_id, str(scope_id), str(scope_id)),
                )
                rows = [dict(row) for row in cursor.fetchall()]
                from securescope.grc.control_implementation import evaluate_implementation
                from securescope.persistence.control_implementation_repository import _load_bundle

                for row in rows:
                    if (row.get("assessment_scope") or {}).get(
                        "implementation_requirements"
                    ) and not (row.get("assessment_scope") or {}).get(
                        "implementation_requirements", {}
                    ).get(
                        "requirements"
                    ):
                        row["implementation_evaluation"] = evaluate_implementation(
                            _load_bundle(cursor, client_id, row["control_id"], scope_id),
                            now=datetime.now(timezone.utc),
                        )
                return rows
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def control_detail_history(
    client_name: str,
    control_id: str,
) -> dict[str, list[dict[str, Any]]]:
    """Load profile, target, assessment, dimension, evidence and gap history.

    Args:
        client_name: Exact workspace name.
        control_id: Annex A.8 control identifier.

    Returns:
        Workspace-scoped control detail history grouped by entity type.

    Raises:
        GrcRepositoryError: If the control or PostgreSQL query is invalid.
    """

    if control_id not in ISO_CONTROL_CATALOG:
        raise GrcRepositoryError(f"Unsupported control: {control_id}")
    seed_control_profiles(client_name)
    queries = {
        "profiles": """
            SELECT *
            FROM securescope_control_assessment_profiles
            WHERE client_id = %s AND control_id = %s
            ORDER BY profile_version DESC;
        """,
        "targets": """
            SELECT target.*, profile.profile_version
            FROM securescope_control_targets target
            JOIN securescope_control_assessment_profiles profile
              ON profile.client_id = target.client_id
             AND profile.id = target.profile_id
            WHERE target.client_id = %s AND profile.control_id = %s
            ORDER BY target.created_at DESC;
        """,
        "assessments": """
            SELECT assessment.*, profile.profile_version
            FROM securescope_control_assessments assessment
            JOIN securescope_control_assessment_profiles profile
              ON profile.client_id = assessment.client_id
             AND profile.id = assessment.profile_id
            WHERE assessment.client_id = %s AND profile.control_id = %s
            ORDER BY assessment.created_at DESC;
        """,
        "dimensions": """
            SELECT dimension.*, assessment.created_at AS assessed_at
            FROM securescope_control_dimension_results dimension
            JOIN securescope_control_assessments assessment
              ON assessment.client_id = dimension.client_id
             AND assessment.id = dimension.assessment_id
            JOIN securescope_control_assessment_profiles profile
              ON profile.client_id = assessment.client_id
             AND profile.id = assessment.profile_id
            WHERE dimension.client_id = %s AND profile.control_id = %s
            ORDER BY assessment.created_at DESC, dimension.dimension;
        """,
        "evidence": """
            SELECT evidence.*
            FROM securescope_control_evidence evidence
            JOIN securescope_control_assessments assessment
              ON assessment.client_id = evidence.client_id
             AND assessment.id = evidence.assessment_id
            JOIN securescope_control_assessment_profiles profile
              ON profile.client_id = assessment.client_id
             AND profile.id = assessment.profile_id
            WHERE evidence.client_id = %s AND profile.control_id = %s
            ORDER BY evidence.collection_date DESC;
        """,
        "evidence_hub": """
            SELECT
                evidence.id,
                evidence.title,
                evidence.tool_id,
                evidence.collection_method,
                evidence.evidence_type,
                evidence.summary,
                evidence.scope_description,
                evidence.collected_at,
                evidence.expires_at,
                evidence.freshness_status,
                evidence.validation_status,
                evidence.validator,
                mapping.evidence_dimension,
                mapping.rationale,
                mapping.consultant_approved,
                artifact.sha256,
                artifact.original_filename
            FROM securescope_evidence_control_mappings mapping
            JOIN securescope_evidence_records evidence
              ON evidence.client_id = mapping.client_id
             AND evidence.id = mapping.evidence_id
            LEFT JOIN securescope_evidence_artifacts artifact
              ON artifact.client_id = evidence.client_id
             AND artifact.id = evidence.artifact_id
            WHERE mapping.client_id = %s AND mapping.control_id = %s
            ORDER BY evidence.collected_at DESC;
        """,
        "gaps": """
            SELECT *
            FROM securescope_control_gaps
            WHERE client_id = %s AND control_id = %s
            ORDER BY created_at DESC;
        """,
    }
    result: dict[str, list[dict[str, Any]]] = {}
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                for name, query in queries.items():
                    cursor.execute(query, (client_id, control_id))
                    result[name] = [dict(row) for row in cursor.fetchall()]
                return result
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def create_profile_version(
    client_name: str,
    control_id: str,
    *,
    measurement_model: str,
    control_owner: str,
    assessment_owner: str,
    assessment_scope: Mapping[str, Any],
    assessment_methods: Sequence[str],
    evidence_requirements: Sequence[str],
    automation_level: str,
    supported_data_sources: Sequence[str],
    actor: str,
    expected_profile_version: int | None = None,
    context_scope_id: int | None = None,
) -> int:
    """Create a new immutable version of a control assessment profile.

    Args:
        client_name: Exact workspace name.
        control_id: Supported Annex A.8 control identifier.
        measurement_model: One supported multi-model assessment method.
        control_owner: Accountable control owner.
        assessment_owner: Assessment performer/owner.
        assessment_scope: Approved scope definition.
        assessment_methods: Examine, Interview, Test, Observe and/or Measure.
        evidence_requirements: Required evidence descriptions.
        automation_level: Manual, Partial or Automated recommendation level.
        supported_data_sources: Configured evidence sources.
        actor: User creating the version.
        expected_profile_version: Version opened by the editor, when supplied.
        context_scope_id: Optional canonical scope selecting the profile being versioned.

    Returns:
        Newly assigned profile version number.

    Raises:
        GrcRepositoryError: If fields are invalid or persistence fails.
    """

    if control_id not in ISO_CONTROL_CATALOG:
        raise GrcRepositoryError(f"Unsupported control: {control_id}")
    if measurement_model not in ASSESSMENT_MODELS:
        raise GrcRepositoryError(f"Unsupported measurement model: {measurement_model}")
    if not all(
        value.strip() for value in (control_owner, assessment_owner, automation_level, actor)
    ):
        raise GrcRepositoryError("Profile version requires owners, automation level and actor.")
    if not dict(assessment_scope).get("description"):
        raise GrcRepositoryError("Profile version requires an approved scope.")
    if not assessment_methods or not evidence_requirements:
        raise GrcRepositoryError(
            "Profile version requires assessment methods and evidence requirements."
        )
    seed_control_profiles(client_name)
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE id = %s FOR UPDATE",
                    (client_id,),
                )
                from securescope.persistence.foundation_repository import member_role

                if member_role(cursor, client_id, actor) not in {"Administrator", "Consultant"}:
                    LOGGER.warning("Denied Control Profile version write")
                    raise GrcRepositoryError("Consultant or Administrator membership is required.")
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_control_assessment_profiles
                    WHERE client_id = %s AND control_id = %s
                    ORDER BY profile_version DESC
                    LIMIT 1
                    FOR UPDATE;
                    """,
                    (client_id, control_id),
                )
                previous = cursor.fetchone()
                if not previous:
                    raise GrcRepositoryError(f"Control profile not found: {control_id}")
                new_version = int(previous["profile_version"]) + 1
                if context_scope_id is not None:
                    cursor.execute(
                        "SELECT * FROM securescope_control_assessment_profiles "
                        "WHERE client_id=%s AND control_id=%s AND ("
                        "assessment_scope->'implementation_requirements'->>'scope_id'=%s OR "
                        "assessment_scope->'implementation_requirements'->>'scope_id' IS NULL) "
                        "ORDER BY (assessment_scope->'implementation_requirements'->>'sco"
                        "pe_id'=%s) "
                        "DESC NULLS LAST, profile_version DESC LIMIT 1 FOR UPDATE",
                        (client_id, control_id, str(context_scope_id), str(context_scope_id)),
                    )
                    previous = cursor.fetchone()
                    if not previous:
                        raise GrcRepositoryError("No profile is available for the selected scope.")
                if (
                    expected_profile_version is not None
                    and int(previous["profile_version"]) != expected_profile_version
                ):
                    raise GrcRepositoryError(
                        "This profile changed in another session. Reload before saving."
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_control_assessment_profiles (
                        client_id,
                        control_id,
                        control_name,
                        profile_version,
                        control_objective,
                        expected_security_outcome,
                        applicability,
                        inclusion_justification,
                        exclusion_justification,
                        assessment_scope,
                        scope_inclusion_rules,
                        scope_exclusion_rules,
                        risk_addressed,
                        control_owner,
                        assessment_owner,
                        assessment_frequency,
                        assessment_methods,
                        evidence_requirements,
                        measurement_model,
                        measurement_criteria,
                        target_state_criteria,
                        effectiveness_tests,
                        validation_requirements,
                        acceptable_evidence_age_days,
                        scoring_rules,
                        automation_level,
                        supported_data_sources,
                        approval_status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, 'Draft', %s
                    );
                    """,
                    (
                        client_id,
                        control_id,
                        previous["control_name"],
                        new_version,
                        previous["control_objective"],
                        previous["expected_security_outcome"],
                        previous["applicability"],
                        previous["inclusion_justification"],
                        previous["exclusion_justification"],
                        Json(dict(assessment_scope)),
                        Json(previous["scope_inclusion_rules"] or []),
                        Json(previous["scope_exclusion_rules"] or []),
                        previous["risk_addressed"],
                        control_owner.strip(),
                        assessment_owner.strip(),
                        previous["assessment_frequency"],
                        Json(list(assessment_methods)),
                        Json(list(evidence_requirements)),
                        measurement_model,
                        Json(previous["measurement_criteria"] or {}),
                        Json(previous["target_state_criteria"] or {}),
                        Json(previous["effectiveness_tests"] or []),
                        Json(previous["validation_requirements"] or {}),
                        previous["acceptable_evidence_age_days"],
                        Json(previous["scoring_rules"]) if previous["scoring_rules"] else None,
                        automation_level.strip(),
                        Json(list(supported_data_sources)),
                        actor.strip(),
                    ),
                )
                return new_version
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def create_control_target(
    client_name: str,
    profile_id: int,
    *,
    target_description: str,
    target_value: float | None,
    unit: str,
    target_date: date,
    rationale: str,
    risk_basis: str,
    remaining_scope_justification: str,
    required_evidence: Sequence[str],
    required_effectiveness_test: str,
    approver: str,
    approval_date: date,
    risk_refs: Sequence[int] | None = None,
) -> int:
    """Create a new approved, versioned target for one control profile.

    Args:
        client_name: Exact workspace name.
        profile_id: Workspace profile identifier.
        target_description: Expected target state.
        target_value: Optional quantitative target value.
        unit: Unit for quantitative targets.
        target_date: Approved target date.
        rationale: Business/control rationale.
        risk_basis: Legacy risk basis retained for historical callers.
        risk_refs: Canonical client-scoped risk references selected for new targets.
        remaining_scope_justification: Treatment of coverage below 100 percent.
        required_evidence: Evidence required to demonstrate achievement.
        required_effectiveness_test: Required effectiveness test.
        approver: Authorized target approver.
        approval_date: Formal approval date.

    Returns:
        New target version number.

    Raises:
        GrcRepositoryError: If mandatory approval data or persistence is invalid.
    """

    if risk_refs is not None:
        if not risk_refs or any(type(ref) is not int or ref <= 0 for ref in risk_refs):
            raise GrcRepositoryError("Select at least one canonical risk.")
        risk_refs = sorted(set(risk_refs))
        risk_basis = ", ".join(f"R-{ref}" for ref in risk_refs)
    mandatory = {
        "target_description": target_description,
        "rationale": rationale,
        "risk_basis": risk_basis,
        "approver": approver,
    }
    missing = [name for name, value in mandatory.items() if not value.strip()]
    if missing:
        raise GrcRepositoryError("Control target is missing: " + ", ".join(missing))
    if target_value is not None and unit.strip() == "%" and target_value < 100:
        if not remaining_scope_justification.strip():
            raise GrcRepositoryError(
                "A target below 100 percent requires remaining-scope justification."
            )
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                if risk_refs is not None:
                    cursor.execute(
                        "SELECT risk_ref FROM securescope_risk_register "
                        "WHERE client_id=%s AND risk_ref = ANY(%s) FOR KEY SHARE",
                        (client_id, list(risk_refs)),
                    )
                    if {int(row[0]) for row in cursor.fetchall()} != set(risk_refs):
                        raise GrcRepositoryError(
                            "A selected risk is outside this workspace or no longer exists."
                        )
                cursor.execute(
                    """
                    SELECT id
                    FROM securescope_control_assessment_profiles
                    WHERE client_id = %s AND id = %s
                    FOR UPDATE;
                    """,
                    (client_id, int(profile_id)),
                )
                if not cursor.fetchone():
                    raise GrcRepositoryError("Control profile is outside the selected workspace.")
                cursor.execute(
                    """
                    SELECT COALESCE(MAX(target_version), 0) + 1
                    FROM securescope_control_targets
                    WHERE client_id = %s AND profile_id = %s;
                    """,
                    (client_id, int(profile_id)),
                )
                target_version = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_control_targets (
                        client_id,
                        profile_id,
                        target_version,
                        target_description,
                        target_metric,
                        target_value,
                        unit,
                        target_date,
                        rationale,
                        risk_basis,
                        remaining_scope_justification,
                        required_evidence,
                        required_effectiveness_test,
                        approver,
                        approval_date
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    );
                    """,
                    (
                        client_id,
                        int(profile_id),
                        target_version,
                        target_description.strip(),
                        "coverage" if unit.strip() == "%" else None,
                        target_value,
                        unit.strip() or None,
                        target_date,
                        rationale.strip(),
                        risk_basis.strip(),
                        remaining_scope_justification.strip() or None,
                        Json(list(required_evidence)),
                        required_effectiveness_test.strip() or None,
                        approver.strip(),
                        approval_date,
                    ),
                )
                return target_version
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def save_coverage_assessment(
    client_name: str,
    profile_id: int,
    *,
    total_in_scope: int,
    covered_in_scope: int,
    target_coverage: float,
    scope_definition: str,
    denominator_definition: str,
    accountable_owner: str,
    evidence_freshness: str,
    confidence: str,
    automated: bool,
    actor: str,
) -> tuple[int, CoverageResult]:
    """Calculate and persist one quantitative control assessment.

    Args:
        client_name: Exact workspace name.
        profile_id: Workspace profile identifier.
        total_in_scope: Approved denominator.
        covered_in_scope: Validated numerator.
        target_coverage: Approved target percentage.
        scope_definition: Explicit assessed population.
        denominator_definition: Explicit denominator rule.
        accountable_owner: Control owner.
        evidence_freshness: Current, Approaching expiration, Expired or Unknown.
        confidence: Low, Medium or High.
        automated: Whether the result is scanner/integration-produced.
        actor: User or service creating the assessment.

    Returns:
        New assessment ID and calculated coverage result.

    Raises:
        InvalidCoverageScopeError: If coverage values are invalid.
        GrcRepositoryError: If mandatory fields or persistence are invalid.
    """

    result = calculate_coverage(total_in_scope, covered_in_scope, target_coverage)
    validate_assessment_status(result.status, automated=automated)
    mandatory = {
        "scope_definition": scope_definition,
        "denominator_definition": denominator_definition,
        "accountable_owner": accountable_owner,
        "actor": actor,
    }
    missing = [name for name, value in mandatory.items() if not value.strip()]
    if missing:
        raise GrcRepositoryError("Coverage assessment is missing: " + ", ".join(missing))
    if evidence_freshness not in {"Current", "Approaching expiration", "Expired", "Unknown"}:
        raise GrcRepositoryError(f"Invalid evidence freshness: {evidence_freshness}")
    if confidence not in {"Low", "Medium", "High"}:
        raise GrcRepositoryError(f"Invalid assessment confidence: {confidence}")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT profile.id, profile.control_id, target.id, target.target_value
                    FROM securescope_control_assessment_profiles profile
                    LEFT JOIN LATERAL (
                        SELECT target_row.id, target_row.target_value
                        FROM securescope_control_targets target_row
                        WHERE target_row.client_id = profile.client_id
                          AND target_row.profile_id = profile.id
                        ORDER BY target_row.target_version DESC
                        LIMIT 1
                    ) target ON TRUE
                    WHERE profile.client_id = %s AND profile.id = %s;
                    """,
                    (client_id, int(profile_id)),
                )
                profile_row = cursor.fetchone()
                if not profile_row:
                    raise GrcRepositoryError("Control profile is outside the selected workspace.")
                control_id = str(profile_row[1])
                target_id = profile_row[2]
                approved_target_value = profile_row[3]
                if target_id is None or approved_target_value is None:
                    raise GrcRepositoryError(
                        "Approve a versioned quantitative target before assessment."
                    )
                if float(approved_target_value) != float(result.target_coverage):
                    raise GrcRepositoryError(
                        "Assessment target does not match the latest approved target."
                    )
                gap_statement = (
                    f"{result.additional_required} additional in-scope units are "
                    f"required to reach the approved {result.target_coverage}% target."
                    if result.additional_required
                    else ""
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_control_assessments (
                        client_id,
                        profile_id,
                        target_id,
                        assessment_status,
                        automated_recommendation,
                        scope_definition,
                        current_state,
                        target_state,
                        gap_statement,
                        measurement_details,
                        denominator_definition,
                        total_in_scope,
                        covered_in_scope,
                        current_value,
                        target_value,
                        unit,
                        calculation_formula,
                        remaining_gap,
                        additional_required,
                        evidence_freshness,
                        confidence,
                        accountable_owner,
                        validation_status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, '%%', %s, %s, %s, %s,
                        %s, %s, 'Pending', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(profile_id),
                        int(target_id),
                        result.status,
                        result.status if automated else None,
                        scope_definition.strip(),
                        (
                            f"{result.covered_in_scope} of "
                            f"{result.total_in_scope} approved units are covered."
                        ),
                        f"Reach {result.target_coverage}% validated coverage.",
                        gap_statement,
                        Json(
                            {
                                "model": "quantitative_coverage",
                                "technical_coverage_only": True,
                            }
                        ),
                        denominator_definition.strip(),
                        result.total_in_scope,
                        result.covered_in_scope,
                        result.current_coverage,
                        result.target_coverage,
                        "covered_in_scope / total_in_scope * 100",
                        result.coverage_gap,
                        result.additional_required,
                        evidence_freshness,
                        confidence,
                        accountable_owner.strip(),
                        actor.strip(),
                    ),
                )
                assessment_id = int(cursor.fetchone()[0])
                for dimension in ASSURANCE_DIMENSIONS:
                    dimension_status = (
                        result.status if dimension == "Scope coverage" else "Insufficient evidence"
                    )
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_dimension_results (
                            client_id,
                            assessment_id,
                            dimension,
                            status,
                            score,
                            rationale,
                            confidence,
                            validation_status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 'Pending');
                        """,
                        (
                            client_id,
                            assessment_id,
                            dimension,
                            dimension_status,
                            (result.current_coverage if dimension == "Scope coverage" else None),
                            (
                                "Quantitative coverage measurement."
                                if dimension == "Scope coverage"
                                else "This dimension requires independent evidence and validation."
                            ),
                            confidence if dimension == "Scope coverage" else "Low",
                        ),
                    )
                if result.coverage_gap and result.coverage_gap > 0:
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_gaps (
                            client_id,
                            gap_uuid,
                            assessment_id,
                            control_id,
                            gap_statement,
                            affected_scope,
                            related_risk,
                            current_value,
                            target_value,
                            unit,
                            remaining_effort,
                            priority,
                            recommended_treatment,
                            required_verification
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s,
                            'Control objective not achieved across approved scope.',
                            %s, %s, '%%', %s, 'High',
                            'Implement coverage for the remaining approved units.',
                            'Collect fresh evidence and validate the resulting coverage.'
                        );
                        """,
                        (
                            client_id,
                            str(uuid.uuid4()),
                            assessment_id,
                            control_id,
                            gap_statement,
                            scope_definition.strip(),
                            result.current_coverage,
                            result.target_coverage,
                            (f"{result.additional_required} additional " "validated units"),
                        ),
                    )
                return assessment_id, result
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def save_manual_control_assessment(
    client_name: str,
    profile_id: int,
    *,
    assessment_status: str,
    current_state: str,
    target_state: str,
    gap_statement: str,
    scope_definition: str,
    accountable_owner: str,
    evidence_source: str,
    evidence_reference: str,
    evidence_summary: str,
    evidence_freshness: str,
    evidence_expiration: datetime | None,
    confidence: str,
    dimension_results: Mapping[str, str],
    criteria: Sequence[Mapping[str, Any]],
    effectiveness_test: Mapping[str, Any] | None,
    related_risk: str,
    remaining_effort: str,
    priority: str,
    recommended_treatment: str,
    required_verification: str,
    actor: str,
    validator: str = "",
) -> tuple[int, int | None]:
    """Persist a qualitative, process, SLA, test, risk or composite assessment.

    Args:
        client_name: Exact workspace name.
        profile_id: Workspace-scoped control profile identifier.
        assessment_status: Conservative assessment conclusion.
        current_state: Evidence-backed current-state narrative.
        target_state: Approved target-state narrative.
        gap_statement: Qualitative gap statement, empty when no gap exists.
        scope_definition: Explicit assessed scope.
        accountable_owner: Accountable control owner.
        evidence_source: Evidence source or collection method.
        evidence_reference: Traceable raw evidence reference.
        evidence_summary: Concise evidence description.
        evidence_freshness: Current, approaching expiration, expired or unknown.
        evidence_expiration: Optional evidence expiration timestamp.
        confidence: Low, Medium or High assessment confidence.
        dimension_results: Independent result for all six assurance dimensions.
        criteria: Optional criterion-level results with evidence and comments.
        effectiveness_test: Optional control-effectiveness test result.
        related_risk: Risk addressed by an identified gap.
        remaining_effort: Work remaining to reach target.
        priority: Critical, High, Medium or Low gap priority.
        recommended_treatment: Recommended treatment for an identified gap.
        required_verification: Evidence/test required before gap closure.
        actor: Assessor recording the result.
        validator: Optional authorized validator.

    Returns:
        Assessment identifier and optional generated gap identifier.

    Raises:
        GrcRepositoryError: If data is incomplete, unsafe or outside the workspace.
        InvalidAssessmentStatusError: If a positive conclusion violates assurance rules.
    """

    mandatory = {
        "current_state": current_state,
        "target_state": target_state,
        "scope_definition": scope_definition,
        "accountable_owner": accountable_owner,
        "actor": actor,
    }
    missing = [name for name, value in mandatory.items() if not value.strip()]
    if missing:
        raise GrcRepositoryError("Manual control assessment is missing: " + ", ".join(missing))
    if assessment_status not in ASSESSMENT_STATUSES:
        raise GrcRepositoryError(f"Unsupported assessment status: {assessment_status}")
    if assessment_status in {"Not applicable", "Accepted residual risk"}:
        raise GrcRepositoryError(
            "Use the approved Statement of Applicability or risk-acceptance "
            "workflow for this status."
        )
    if set(dimension_results) != set(ASSURANCE_DIMENSIONS):
        raise GrcRepositoryError("All six assurance dimensions require independent results.")
    invalid_dimensions = [
        status
        for status in dimension_results.values()
        if status not in ASSESSMENT_STATUSES
        or status in {"Not applicable", "Accepted residual risk"}
    ]
    if invalid_dimensions:
        raise GrcRepositoryError("Unsupported dimension status: " + ", ".join(invalid_dimensions))
    test_result = str((effectiveness_test or {}).get("result") or "")
    if effectiveness_test:
        required_test_fields = (
            "test_scenario",
            "test_objective",
            "expected_outcome",
            "observed_outcome",
            "tested_sample",
            "evidence_reference",
            "tester",
        )
        missing_test = [
            field_name
            for field_name in required_test_fields
            if not str(effectiveness_test.get(field_name) or "").strip()
        ]
        if missing_test:
            raise GrcRepositoryError("Effectiveness test is missing: " + ", ".join(missing_test))
    successful_test = test_result == "Successful"
    validate_assessment_status(
        assessment_status,
        automated=False,
        effectiveness_evidence=successful_test,
        authorized_validation=bool(validator.strip()),
        not_applicable_approved=bool(validator.strip()),
        risk_acceptance_approved=False,
    )
    if (
        assessment_status
        in {
            "Target achieved",
            "Implemented and effective",
            "Implemented but not verified",
        }
        and not evidence_reference.strip()
    ):
        raise GrcRepositoryError(
            "A positive implementation conclusion requires traceable evidence."
        )
    gap_statuses = {
        "Not implemented",
        "Gap identified",
        "Partially implemented",
        "Insufficient evidence",
    }
    if assessment_status in gap_statuses:
        gap_fields = {
            "gap_statement": gap_statement,
            "related_risk": related_risk,
            "remaining_effort": remaining_effort,
            "recommended_treatment": recommended_treatment,
            "required_verification": required_verification,
        }
        missing_gap = [name for name, value in gap_fields.items() if not value.strip()]
        if missing_gap:
            raise GrcRepositoryError("Identified gap is missing: " + ", ".join(missing_gap))
    if priority not in {"Critical", "High", "Medium", "Low"}:
        raise GrcRepositoryError(f"Unsupported gap priority: {priority}")
    if evidence_freshness not in {"Current", "Approaching expiration", "Expired", "Unknown"}:
        raise GrcRepositoryError(f"Invalid evidence freshness: {evidence_freshness}")
    if confidence not in {"Low", "Medium", "High"}:
        raise GrcRepositoryError(f"Invalid assessment confidence: {confidence}")
    if evidence_expiration is not None:
        expiration = evidence_expiration
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        if expiration <= datetime.now(timezone.utc):
            raise GrcRepositoryError("Evidence expiration must be in the future.")

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT profile.control_id, profile.measurement_model, target.id
                    FROM securescope_control_assessment_profiles profile
                    LEFT JOIN LATERAL (
                        SELECT target_row.id
                        FROM securescope_control_targets target_row
                        WHERE target_row.client_id = profile.client_id
                          AND target_row.profile_id = profile.id
                        ORDER BY target_row.target_version DESC
                        LIMIT 1
                    ) target ON TRUE
                    WHERE profile.client_id = %s AND profile.id = %s;
                    """,
                    (client_id, int(profile_id)),
                )
                profile = cursor.fetchone()
                if not profile:
                    raise GrcRepositoryError("Control profile is outside the selected workspace.")
                control_id = str(profile[0])
                measurement_model = str(profile[1])
                target_id = profile[2]
                if target_id is None:
                    raise GrcRepositoryError(
                        "Approve a versioned target before recording an assessment."
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_control_assessments (
                        client_id,
                        profile_id,
                        target_id,
                        assessment_status,
                        scope_definition,
                        current_state,
                        target_state,
                        gap_statement,
                        measurement_details,
                        evidence_freshness,
                        confidence,
                        accountable_owner,
                        validation_status,
                        validator,
                        validation_date,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(profile_id),
                        int(target_id),
                        assessment_status,
                        scope_definition.strip(),
                        current_state.strip(),
                        target_state.strip(),
                        gap_statement.strip(),
                        Json({"model": measurement_model}),
                        evidence_freshness,
                        confidence,
                        accountable_owner.strip(),
                        "Validated" if validator.strip() else "Pending",
                        validator.strip() or None,
                        date.today() if validator.strip() else None,
                        actor.strip(),
                    ),
                )
                assessment_id = int(cursor.fetchone()[0])
                for dimension in ASSURANCE_DIMENSIONS:
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_dimension_results (
                            client_id,
                            assessment_id,
                            dimension,
                            status,
                            rationale,
                            confidence,
                            validation_status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            client_id,
                            assessment_id,
                            dimension,
                            dimension_results[dimension],
                            f"Manual assessment of {dimension.lower()}.",
                            confidence,
                            "Validated" if validator.strip() else "Pending",
                        ),
                    )
                for index, criterion in enumerate(criteria, start=1):
                    result = str(criterion.get("result") or "Not assessed")
                    if result not in CRITERION_RESULTS:
                        raise GrcRepositoryError(f"Unsupported criterion result: {result}")
                    identifier = str(
                        criterion.get("criterion_identifier") or f"criterion-{index}"
                    ).strip()
                    description = str(criterion.get("description") or "").strip()
                    if not description:
                        raise GrcRepositoryError(f"Criterion {identifier} requires a description.")
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_criterion_results (
                            client_id,
                            assessment_id,
                            criterion_identifier,
                            description,
                            required,
                            assessment_method,
                            expected_evidence,
                            result,
                            evidence_reference,
                            assessor,
                            assessor_comment,
                            validation_status
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s
                        );
                        """,
                        (
                            client_id,
                            assessment_id,
                            identifier,
                            description,
                            bool(criterion.get("required", True)),
                            str(criterion.get("assessment_method") or "Examine"),
                            str(criterion.get("expected_evidence") or ""),
                            result,
                            str(criterion.get("evidence_reference") or "") or None,
                            actor.strip(),
                            str(criterion.get("assessor_comment") or ""),
                            "Validated" if validator.strip() else "Pending",
                        ),
                    )
                if effectiveness_test:
                    if test_result not in TEST_RESULTS:
                        raise GrcRepositoryError(
                            f"Unsupported effectiveness-test result: {test_result}"
                        )
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_effectiveness_tests (
                            client_id,
                            assessment_id,
                            test_scenario,
                            test_objective,
                            expected_outcome,
                            observed_outcome,
                            test_date,
                            tested_sample,
                            exceptions,
                            evidence_reference,
                            tester,
                            result,
                            corrective_action,
                            retest_required,
                            retest_due_date
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s
                        );
                        """,
                        (
                            client_id,
                            assessment_id,
                            str(effectiveness_test.get("test_scenario") or ""),
                            str(effectiveness_test.get("test_objective") or ""),
                            str(effectiveness_test.get("expected_outcome") or ""),
                            str(effectiveness_test.get("observed_outcome") or ""),
                            effectiveness_test.get("test_date") or date.today(),
                            str(effectiveness_test.get("tested_sample") or ""),
                            str(effectiveness_test.get("exceptions") or ""),
                            str(effectiveness_test.get("evidence_reference") or ""),
                            str(effectiveness_test.get("tester") or actor).strip(),
                            test_result,
                            str(effectiveness_test.get("corrective_action") or ""),
                            bool(effectiveness_test.get("retest_required")),
                            effectiveness_test.get("retest_due_date"),
                        ),
                    )
                if evidence_reference.strip():
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_evidence (
                            client_id,
                            assessment_id,
                            evidence_identifier,
                            evidence_source,
                            evidence_type,
                            collection_method,
                            collection_date,
                            raw_evidence_reference,
                            evidence_summary,
                            owner,
                            freshness_status,
                            expiration_date,
                            confidence,
                            validation_status,
                            validator,
                            validation_date
                        )
                        VALUES (
                            %s, %s, %s, %s, 'Assessment evidence', 'Manual',
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        );
                        """,
                        (
                            client_id,
                            assessment_id,
                            f"{control_id}-{assessment_id}-evidence-1",
                            evidence_source.strip() or "Manual assessment",
                            datetime.now(timezone.utc),
                            evidence_reference.strip(),
                            evidence_summary.strip(),
                            accountable_owner.strip(),
                            evidence_freshness,
                            evidence_expiration,
                            confidence,
                            "Validated" if validator.strip() else "Pending",
                            validator.strip() or None,
                            date.today() if validator.strip() else None,
                        ),
                    )
                gap_id: int | None = None
                if assessment_status in gap_statuses:
                    cursor.execute(
                        """
                        INSERT INTO securescope_control_gaps (
                            client_id,
                            gap_uuid,
                            assessment_id,
                            control_id,
                            gap_statement,
                            affected_scope,
                            supporting_evidence,
                            related_risk,
                            remaining_effort,
                            priority,
                            recommended_treatment,
                            required_verification
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s
                        )
                        RETURNING id;
                        """,
                        (
                            client_id,
                            str(uuid.uuid4()),
                            assessment_id,
                            control_id,
                            gap_statement.strip(),
                            scope_definition.strip(),
                            Json(
                                [evidence_reference.strip()] if evidence_reference.strip() else []
                            ),
                            related_risk.strip(),
                            remaining_effort.strip(),
                            priority,
                            recommended_treatment.strip(),
                            required_verification.strip(),
                        ),
                    )
                    gap_id = int(cursor.fetchone()[0])
                return assessment_id, gap_id
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def list_control_gaps_and_actions(client_name: str) -> list[dict[str, Any]]:
    """List workspace gaps with linked action and milestone counts.

    Args:
        client_name: Exact workspace name.

    Returns:
        Workspace-scoped gap rows and action progress counts.

    Raises:
        GrcRepositoryError: If PostgreSQL cannot load the records.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        gap.*,
                        COUNT(DISTINCT action.id) AS action_count,
                        COUNT(DISTINCT milestone.id) AS milestone_count,
                        COUNT(DISTINCT action.id) FILTER (
                            WHERE action.status = 'Completed'
                        ) AS completed_action_count
                    FROM securescope_control_gaps gap
                    LEFT JOIN securescope_improvement_actions action
                      ON action.client_id = gap.client_id
                     AND action.gap_id = gap.id
                    LEFT JOIN securescope_improvement_milestones milestone
                      ON milestone.client_id = action.client_id
                     AND milestone.action_id = action.id
                    WHERE gap.client_id = %s
                    GROUP BY gap.id
                    ORDER BY gap.updated_at DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def create_improvement_action(
    client_name: str,
    gap_id: int,
    *,
    recommended_action: str,
    action_owner: str,
    risk_owner: str,
    priority: str,
    required_resources: str,
    dependencies: str,
    start_date: date,
    due_date: date,
    sla_days: int,
    success_criteria: str,
    verification_method: str,
    expected_evidence: str,
    milestone_title: str,
    milestone_owner: str,
    milestone_due_date: date,
    milestone_success_criteria: str,
    actor: str,
) -> int:
    """Create a workspace gap action with its first milestone and audit record.

    Args:
        client_name: Exact workspace name.
        gap_id: Workspace-scoped control gap identifier.
        recommended_action: Action to implement.
        action_owner: Accountable action owner.
        risk_owner: Related risk owner.
        priority: Critical, High, Medium or Low.
        required_resources: People, tools or budget required.
        dependencies: Blocking dependencies.
        start_date: Planned start date.
        due_date: Committed due date.
        sla_days: Action SLA in calendar days.
        success_criteria: Measurable completion criteria.
        verification_method: Required closure verification.
        expected_evidence: Evidence expected at completion.
        milestone_title: Initial milestone title.
        milestone_owner: Initial milestone owner.
        milestone_due_date: Initial milestone due date.
        milestone_success_criteria: Initial milestone success criteria.
        actor: User creating the action.

    Returns:
        New improvement action identifier.

    Raises:
        GrcRepositoryError: If fields, dates, scope or persistence are invalid.
    """

    mandatory = {
        "recommended_action": recommended_action,
        "action_owner": action_owner,
        "risk_owner": risk_owner,
        "success_criteria": success_criteria,
        "verification_method": verification_method,
        "expected_evidence": expected_evidence,
        "milestone_title": milestone_title,
        "milestone_owner": milestone_owner,
        "milestone_success_criteria": milestone_success_criteria,
        "actor": actor,
    }
    missing = [name for name, value in mandatory.items() if not value.strip()]
    if missing:
        raise GrcRepositoryError("Improvement action is missing: " + ", ".join(missing))
    if priority not in {"Critical", "High", "Medium", "Low"}:
        raise GrcRepositoryError(f"Unsupported action priority: {priority}")
    if sla_days <= 0 or due_date < start_date:
        raise GrcRepositoryError("Action SLA and dates are invalid.")
    if milestone_due_date > due_date:
        raise GrcRepositoryError("Milestone due date cannot exceed action due date.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT control_id, affected_scope, related_risk, gap_statement
                    FROM securescope_control_gaps
                    WHERE client_id = %s AND id = %s
                    FOR UPDATE;
                    """,
                    (client_id, int(gap_id)),
                )
                gap = cursor.fetchone()
                if not gap:
                    raise GrcRepositoryError("Control gap is outside the selected workspace.")
                cursor.execute(
                    """
                    INSERT INTO securescope_improvement_actions (
                        client_id,
                        action_uuid,
                        gap_id,
                        control_id,
                        affected_scope,
                        related_risks,
                        recommended_action,
                        action_owner,
                        risk_owner,
                        priority,
                        required_resources,
                        dependencies,
                        start_date,
                        due_date,
                        sla_days,
                        success_criteria,
                        verification_method,
                        expected_evidence
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        int(gap_id),
                        str(gap[0]),
                        str(gap[1]),
                        Json([str(gap[2])]),
                        recommended_action.strip(),
                        action_owner.strip(),
                        risk_owner.strip(),
                        priority,
                        required_resources.strip(),
                        dependencies.strip(),
                        start_date,
                        due_date,
                        int(sla_days),
                        success_criteria.strip(),
                        verification_method.strip(),
                        expected_evidence.strip(),
                    ),
                )
                action_id = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_improvement_milestones (
                        client_id,
                        action_id,
                        title,
                        owner,
                        priority,
                        due_date,
                        sla_days,
                        success_criteria
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        action_id,
                        milestone_title.strip(),
                        milestone_owner.strip(),
                        priority,
                        milestone_due_date,
                        int(sla_days),
                        milestone_success_criteria.strip(),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_poam_items (
                        client_id,
                        poam_uuid,
                        gap_id,
                        action_id,
                        control_id,
                        weakness_description,
                        source_reference,
                        owner,
                        risk_owner,
                        priority,
                        sla_days,
                        scheduled_completion_date,
                        verification_method
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        int(gap_id),
                        action_id,
                        str(gap[0]),
                        str(gap[3]),
                        f"control-gap:{gap_id}",
                        action_owner.strip(),
                        risk_owner.strip(),
                        priority,
                        int(sla_days),
                        due_date,
                        verification_method.strip(),
                    ),
                )
                poam_id = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_entity_status_history (
                        client_id,
                        entity_type,
                        entity_id,
                        from_status,
                        to_status,
                        reason,
                        changed_by
                    )
                    VALUES
                        (%s, 'improvement_action', %s, NULL, 'Open', %s, %s),
                        (%s, 'poam_item', %s, NULL, 'Open', %s, %s);
                    """,
                    (
                        client_id,
                        action_id,
                        "Action created from an assessed control gap.",
                        actor.strip(),
                        client_id,
                        poam_id,
                        "POA&M item created from an assessed control gap.",
                        actor.strip(),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_audit_events (
                        client_id,
                        event_type,
                        entity_type,
                        entity_id,
                        actor,
                        summary,
                        after_state
                    )
                    VALUES (
                        %s, 'improvement_action.created', 'improvement_action',
                        %s, %s, %s, %s
                    );
                    """,
                    (
                        client_id,
                        str(action_id),
                        actor.strip(),
                        recommended_action.strip(),
                        Json(
                            {
                                "gap_id": int(gap_id),
                                "status": "Open",
                                "poam_id": poam_id,
                            }
                        ),
                    ),
                )
                return action_id
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def list_gap_summary(client_name: str) -> dict[str, int]:
    """Aggregate conservative control/gap statuses for one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Counts of applicable, assessed, unassessed, manual, insufficient and
        open-gap controls.

    Raises:
        GrcRepositoryError: If PostgreSQL aggregation fails.
    """

    rows = list_control_overview(client_name)
    statuses = [str(row.get("assessment_status") or "Not assessed") for row in rows]
    return {
        "applicable_controls": sum(
            1 for row in rows if str(row.get("applicability")) != "Not applicable"
        ),
        "assessed_controls": sum(1 for status in statuses if status != "Not assessed"),
        "not_assessed": statuses.count("Not assessed"),
        "manual_assessment_required": statuses.count("Manual assessment required"),
        "insufficient_evidence": statuses.count("Insufficient evidence"),
        "controls_with_gaps": sum(
            1
            for status in statuses
            if status in {"Gap identified", "Not implemented", "Partially implemented"}
        ),
    }


def save_statement_of_applicability(
    client_name: str,
    items: Sequence[Mapping[str, Any]],
    *,
    prepared_by: str,
    approved_by: str = "",
    approve: bool = False,
    notes: str = "",
    engagement_id: int | None = None,
    scope_id: int | None = None,
    actor: str = "",
) -> int:
    """Create one versioned Statement of Applicability snapshot.

    Args:
        client_name: Exact workspace name.
        items: Control-level applicability and justification records.
        prepared_by: Person preparing the SoA version.
        approved_by: Authorized approver for an approved version.
        approve: Whether to mark the new version Approved.
        notes: Version notes.
        engagement_id: Explicit owning engagement for scoped versions.
        scope_id: Explicit owning ISMS Scope; omitted for legacy compatibility.
        actor: Active workspace member creating the scoped version.

    Returns:
        New SoA version number.

    Raises:
        GrcRepositoryError: If items, justifications, approval or persistence
            are incomplete.
    """

    if not prepared_by.strip() or not items:
        raise GrcRepositoryError("SoA requires a preparer and control items.")
    if approve and not approved_by.strip():
        raise GrcRepositoryError("Approved SoA versions require an approver.")
    normalized_items: list[dict[str, Any]] = []
    missing, exclusions, invalid = [], [], []
    for item in items:
        control_id = str(item.get("control_id") or "").strip()
        applicability = str(item.get("applicability") or "Applicable").strip()
        inclusion = str(item.get("inclusion_justification") or "").strip()
        exclusion = str(item.get("exclusion_justification") or "").strip()
        if not control_id or applicability not in {"Applicable", "Not applicable"}:
            invalid.append(control_id or "Unnamed control")
        elif not (inclusion if applicability == "Applicable" else exclusion):
            missing.append(control_id)
        if approve and applicability == "Not applicable" and not item.get("approved"):
            exclusions.append(control_id)
        normalized_items.append(dict(item))
    errors = []
    if missing:
        errors.append(
            f"{len(missing)} controls are missing required justification: " + ", ".join(missing)
        )
    if exclusions:
        errors.append(
            f"{len(exclusions)} exclusions still require approval: " + ", ".join(exclusions)
        )
    if invalid:
        errors.append("Invalid applicability or identifier: " + ", ".join(invalid))
    if errors:
        operation = "approve this SoA" if approve else "create draft"
        raise GrcRepositoryError(f"Cannot {operation}. " + "; ".join(errors))
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                if engagement_id is not None or scope_id is not None:
                    _validate_soa_context(
                        cursor, client_id, engagement_id, scope_id, actor, approve
                    )
                    prepared_by = actor
                    approved_by = actor if approve else ""
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE id=%s FOR UPDATE", (client_id,)
                )
                cursor.execute(
                    """
                    SELECT COALESCE(MAX(version_number), 0) + 1
                    FROM securescope_soa_versions
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                version = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_soa_versions (
                        client_id,
                        version_number,
                        status,
                        prepared_by,
                        approved_by,
                        approval_date,
                        notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        version,
                        "Approved" if approve else "Draft",
                        prepared_by.strip(),
                        approved_by.strip() or None,
                        date.today() if approve else None,
                        notes.strip(),
                    ),
                )
                soa_version_id = int(cursor.fetchone()[0])
                for item in normalized_items:
                    cursor.execute(
                        """
                        INSERT INTO securescope_soa_items (
                            client_id,
                            soa_version_id,
                            control_id,
                            control_name,
                            necessary_control,
                            applicability,
                            inclusion_justification,
                            exclusion_justification,
                            implementation_status,
                            control_owner,
                            related_risks,
                            related_treatment_plans,
                            evidence,
                            effectiveness_review,
                            reviewer,
                            review_date,
                            approved
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s
                        );
                        """,
                        (
                            client_id,
                            soa_version_id,
                            item["control_id"],
                            str(item.get("control_name") or item["control_id"]),
                            bool(item.get("necessary_control", True)),
                            item["applicability"],
                            str(item.get("inclusion_justification") or "").strip() or None,
                            str(item.get("exclusion_justification") or "").strip() or None,
                            str(item.get("implementation_status") or "Not assessed"),
                            str(item.get("control_owner") or "Unassigned"),
                            Json(list(item.get("related_risks") or [])),
                            Json(list(item.get("related_treatment_plans") or [])),
                            Json(list(item.get("evidence") or [])),
                            str(item.get("effectiveness_review") or ""),
                            approved_by.strip() or None,
                            date.today() if approve else None,
                            bool(item.get("approved")) and approve,
                        ),
                    )
                if scope_id is not None:
                    _link_soa_scope(
                        cursor,
                        client_id,
                        soa_version_id,
                        engagement_id,
                        scope_id,
                        actor,
                        "Prepared for the selected ISMS scope.",
                    )
                return version
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def latest_statement_of_applicability(
    client_name: str,
    *,
    engagement_id: int | None = None,
    scope_id: int | None = None,
    version_id: int | None = None,
) -> dict[str, Any] | None:
    """Load the latest SoA version and all its workspace-scoped items.

    Args:
        client_name: Exact workspace name.

    Returns:
        SoA version with ``items``, or None when no version exists.

    Raises:
        GrcRepositoryError: If PostgreSQL cannot load the SoA.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT version.*
                    FROM securescope_soa_versions version
                    WHERE version.client_id = %s AND
                    """
                    + _soa_scope_predicate()
                    + """
                    AND (%s IS NULL OR version.id=%s)
                    ORDER BY version_number DESC
                    LIMIT 1;
                    """,
                    (
                        client_id,
                        scope_id,
                        engagement_id,
                        scope_id,
                        scope_id,
                        version_id,
                        version_id,
                    ),
                )
                version = cursor.fetchone()
                if not version:
                    return None
                result = dict(version)
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_soa_items
                    WHERE client_id = %s AND soa_version_id = %s
                    ORDER BY control_id;
                    """,
                    (client_id, int(version["id"])),
                )
                result["items"] = [dict(row) for row in cursor.fetchall()]
                return result
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def list_statement_of_applicability_versions(
    client_name: str,
    *,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> list[dict[str, Any]]:
    """List all Statement of Applicability versions for one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Version metadata ordered newest first.

    Raises:
        GrcRepositoryError: If PostgreSQL cannot load version history.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        version.id,
                        version.version_number,
                        version.status,
                        version.prepared_by,
                        version.approved_by,
                        version.approval_date,
                        version.notes,
                        version.created_at,
                        COUNT(item.id) AS control_count
                    FROM securescope_soa_versions version
                    LEFT JOIN securescope_soa_items item
                      ON item.client_id = version.client_id
                     AND item.soa_version_id = version.id
                    WHERE version.client_id = %s AND
                    """
                    + _soa_scope_predicate()
                    + """
                    GROUP BY version.id
                    ORDER BY version.version_number DESC;
                    """,
                    (client_id, scope_id, engagement_id, scope_id, scope_id),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def create_risk_treatment_plan(
    client_name: str,
    *,
    title: str,
    risk_reference: str,
    treatment_option: str,
    linked_controls: Sequence[str],
    linked_gaps: Sequence[int],
    linked_findings: Sequence[int],
    linked_actions: Sequence[int],
    owner: str,
    risk_owner: str,
    required_resources: str,
    dependencies: str,
    due_date: date,
    residual_risk: str,
    validation_evidence: str,
    approver: str,
    approval_date: date,
    milestone_title: str,
    milestone_owner: str,
    milestone_due_date: date,
    milestone_success_criteria: str,
) -> int:
    """Create an approved Risk Treatment Plan and its first milestone.

    Args:
        client_name: Exact workspace name.
        title: Treatment plan title.
        risk_reference: Linked risk identifier.
        treatment_option: Modify, mitigate, avoid, accept or transfer/share.
        linked_controls: Related control identifiers.
        linked_gaps: Related gap identifiers.
        linked_findings: Related canonical finding identifiers.
        linked_actions: Related remediation/improvement action identifiers.
        owner: Treatment plan owner.
        risk_owner: Accountable risk owner.
        required_resources: Required resources.
        dependencies: Blocking dependencies.
        due_date: Plan due date.
        residual_risk: Expected residual risk.
        validation_evidence: Required validation evidence.
        approver: Authorized approver.
        approval_date: Formal approval date.
        milestone_title: First milestone title.
        milestone_owner: First milestone owner.
        milestone_due_date: First milestone due date.
        milestone_success_criteria: First milestone success criteria.

    Returns:
        New Risk Treatment Plan identifier.

    Raises:
        GrcRepositoryError: If mandatory fields, dates, option or persistence fail.
    """

    options = {"Remediate or modify", "Mitigate", "Avoid", "Accept", "Transfer or share"}
    if treatment_option not in options:
        raise GrcRepositoryError(f"Unsupported treatment option: {treatment_option}")
    mandatory = {
        "title": title,
        "risk_reference": risk_reference,
        "owner": owner,
        "risk_owner": risk_owner,
        "residual_risk": residual_risk,
        "validation_evidence": validation_evidence,
        "approver": approver,
        "milestone_title": milestone_title,
        "milestone_owner": milestone_owner,
        "milestone_success_criteria": milestone_success_criteria,
    }
    missing = [name for name, value in mandatory.items() if not value.strip()]
    if missing:
        raise GrcRepositoryError("Risk Treatment Plan is missing: " + ", ".join(missing))
    if milestone_due_date > due_date:
        raise GrcRepositoryError("Milestone due date cannot exceed plan due date.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    INSERT INTO securescope_risk_treatment_plans (
                        client_id,
                        plan_uuid,
                        title,
                        risk_reference,
                        treatment_option,
                        linked_controls,
                        linked_gaps,
                        linked_findings,
                        linked_actions,
                        owner,
                        risk_owner,
                        required_resources,
                        dependencies,
                        due_date,
                        residual_risk,
                        validation_evidence,
                        approver,
                        approval_date
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        title.strip(),
                        risk_reference.strip(),
                        treatment_option,
                        Json(list(linked_controls)),
                        Json([int(value) for value in linked_gaps]),
                        Json([int(value) for value in linked_findings]),
                        Json([int(value) for value in linked_actions]),
                        owner.strip(),
                        risk_owner.strip(),
                        required_resources.strip(),
                        dependencies.strip(),
                        due_date,
                        residual_risk.strip(),
                        validation_evidence.strip(),
                        approver.strip(),
                        approval_date,
                    ),
                )
                plan_id = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_risk_treatment_milestones (
                        client_id,
                        treatment_plan_id,
                        title,
                        owner,
                        due_date,
                        success_criteria
                    )
                    VALUES (%s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        plan_id,
                        milestone_title.strip(),
                        milestone_owner.strip(),
                        milestone_due_date,
                        milestone_success_criteria.strip(),
                    ),
                )
                return plan_id
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def list_risk_treatment_plans(client_name: str) -> list[dict[str, Any]]:
    """List Risk Treatment Plans and milestone progress for one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Workspace-scoped treatment plans.

    Raises:
        GrcRepositoryError: If PostgreSQL cannot load plans.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        plan.*,
                        COUNT(milestone.id) AS milestone_count,
                        COUNT(milestone.id) FILTER (
                            WHERE milestone.status = 'Completed'
                        ) AS completed_milestones
                    FROM securescope_risk_treatment_plans plan
                    LEFT JOIN securescope_risk_treatment_milestones milestone
                      ON milestone.client_id = plan.client_id
                     AND milestone.treatment_plan_id = plan.id
                    WHERE plan.client_id = %s
                    GROUP BY plan.id
                    ORDER BY plan.due_date, plan.updated_at DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def _soa_scope_predicate() -> str:
    """Return a fixed SQL ownership predicate for explicit scope links.

    Returns:
        SQL with scope, engagement, scope, scope parameters. No caller text is interpolated.
    Raises:
        No exceptions are raised.
    """
    return """((%s IS NOT NULL AND EXISTS (
        SELECT 1 FROM securescope_engagement_record_links link
        WHERE link.client_id=version.client_id
                                  AND link.soa_version_id=version.id
        AND link.engagement_id=%s AND link.scope_id=%s
        AND link.link_origin <> 'Legacy backfill'))
        OR (%s IS NULL AND NOT EXISTS (
        SELECT 1 FROM securescope_engagement_record_links link
        WHERE link.client_id=version.client_id
                                  AND link.soa_version_id=version.id
        AND link.scope_id IS NOT NULL AND link.link_origin <> 'Legacy backfill')))"""


def _soa_scalar(row):
    """Read one scalar from tuple or mapping cursors; return None for no row."""
    return next(iter(row.values())) if isinstance(row, dict) else row[0] if row else None


def _validate_soa_context(cursor, client_id, engagement_id, scope_id, actor, approve=False):
    """Validate canonical scope ownership and trusted workspace permissions.

    Args:
        cursor: Current transaction cursor.
        client_id: Tenant ID.
        engagement_id: Selected engagement ID.
        scope_id: Selected scope ID.
        actor: Trusted session principal.
        approve: Whether Administrator approval permission is required.
    Returns:
        None.
    Raises:
        GrcRepositoryError: For missing, foreign or unauthorized context.
    """
    if not engagement_id or not scope_id or not actor:
        raise GrcRepositoryError(
            "Select an engagement and ISMS scope and sign in before saving SoA."
        )
    cursor.execute(
        "SELECT 1 FROM securescope_scope_definitions WHERE client_id=%s AN"
        "D engagement_id=%s AND id=%s AND NOT archived",
        (client_id, engagement_id, scope_id),
    )
    if not cursor.fetchone():
        raise GrcRepositoryError("SoA scope is outside the active client/engagement or archived.")
    cursor.execute(
        "SELECT m.role FROM securescope_workspace_memberships m JOIN secur"
        "escope_users u ON u.id=m.user_id WHERE m.client_id=%s AND lower(u"
        ".email)=lower(%s) AND m.active AND u.active",
        (client_id, actor),
    )
    role = _soa_scalar(cursor.fetchone())
    if (
        role not in {"Administrator", "Consultant", "Client contributor"}
        or approve
        and role != "Administrator"
    ):
        raise GrcRepositoryError(
            "Contributor membership is required; SoA approval requires an Administrator."
        )


def _link_soa_scope(cursor, client_id, version_id, engagement_id, scope_id, actor, rationale):
    """Associate one existing SoA version without copying items or deleting legacy links.

    Args:
        cursor: Transaction cursor; the SoA version must be locked by the caller.
        client_id: Tenant ID.
        version_id: Existing SoA ID.
        engagement_id: Confirmed engagement ID.
        scope_id: Confirmed scope ID.
        actor: Authorized principal.
        rationale: Human association rationale.
    Returns:
        None.
    Raises:
        GrcRepositoryError: If an explicit assignment already exists.
    """
    cursor.execute(
        "SELECT id FROM securescope_engagement_record_links WHERE client_i"
        "d=%s AND soa_version_id=%s AND scope_id IS NOT NULL AND link_orig"
        "in <> 'Legacy backfill'",
        (client_id, version_id),
    )
    if cursor.fetchone():
        raise GrcRepositoryError(
            "This SoA version already has an explicit scope. Open that scope to inspect it."
        )
    cursor.execute(
        "INSERT INTO securescope_engagement_record_links (client_id,engage"
        "ment_id,scope_id,link_key,soa_version_id,link_origin,rationale,li"
        "nked_by) VALUES (%s,%s,%s,%s,%s,'Manual association',%s,%s)",
        (
            client_id,
            engagement_id,
            scope_id,
            f"soa-scope:{version_id}",
            version_id,
            rationale,
            actor,
        ),
    )
    cursor.execute(
        "INSERT INTO securescope_audit_events (client_id,event_type,entity"
        "_type,entity_id,actor,summary,after_state) VALUES (%s,'soa.scope_"
        "assigned','soa_version',%s,%s,%s,%s)",
        (
            client_id,
            str(version_id),
            actor,
            rationale,
            Json({"engagement_id": engagement_id, "scope_id": scope_id}),
        ),
    )


def assign_legacy_soa_scope(
    client_name: str,
    version_id: int,
    *,
    engagement_id: int,
    scope_id: int,
    actor: str,
    rationale: str,
) -> None:
    """Explicitly assign an unassigned legacy SoA, preserving version and item identities.

    Args:
        client_name: Active tenant name.
        version_id: Existing unassigned SoA version ID.
        engagement_id: Confirmed engagement ID.
        scope_id: Confirmed scope ID.
        actor: Trusted signed-in principal.
        rationale: Required association rationale.
    Returns:
        None.
    Raises:
        GrcRepositoryError: For unauthorized, foreign or already assigned records.
    """
    if not rationale.strip():
        raise GrcRepositoryError("Explain why this historical SoA belongs to the selected scope.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                _validate_soa_context(cursor, client_id, engagement_id, scope_id, actor, True)
                cursor.execute(
                    "SELECT id FROM securescope_soa_versions WHERE client_id=%s AND id"
                    "=%s FOR UPDATE",
                    (client_id, version_id),
                )
                if not cursor.fetchone():
                    raise GrcRepositoryError("SoA version does not belong to this workspace.")
                _link_soa_scope(
                    cursor, client_id, version_id, engagement_id, scope_id, actor, rationale.strip()
                )
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc
