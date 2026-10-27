"""Workspace-scoped persistence for findings, remediation and risk decisions."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
import uuid
from typing import Any, Iterable, Mapping, Sequence

from psycopg2.extras import Json, RealDictCursor

from securescope.core.finding_domain import (
    ACTIVE_FINDING_STATUSES,
    deduplicate_scan_history,
    severity_rank,
    status_after_new_observation,
    validate_finding_transition,
)
from securescope.core.gap_assessment_domain import RiskAcceptance
from securescope.core.remediation_domain import RemediationPlanInput
from securescope.persistence.db_service import DatabaseError, connect, get_client_id
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


class ExposureRepositoryError(RuntimeError):
    """Raised when an exposure-management persistence operation fails."""


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve one existing workspace inside the current transaction.

    Args:
        cursor: Active PostgreSQL cursor.
        client_name: Exact client workspace name.

    Returns:
        Positive client identifier.

    Raises:
        ExposureRepositoryError: If the workspace does not exist.
    """

    cursor.execute(
        "SELECT id FROM securescope_clients WHERE name = %s;",
        (str(client_name).strip(),),
    )
    row = cursor.fetchone()
    if not row:
        raise ExposureRepositoryError(f"Client workspace not found: {client_name}")
    return int(row[0] if not isinstance(row, dict) else row["id"])


def _preferred_severity(current: str, incoming: str) -> str:
    """Return the higher of two normalized severity labels.

    Args:
        current: Current severity label.
        incoming: Incoming severity label.

    Returns:
        Highest severity according to SecureScope ordering.

    Raises:
        ValueError: Never raised for normal labels.
    """

    return incoming if severity_rank(incoming) > severity_rank(current) else current


def synchronize_findings_from_history(
    client_name: str,
    scan_history: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    """Idempotently synchronize canonical findings from existing scan history.

    Args:
        client_name: Exact workspace name.
        scan_history: Workspace-filtered OpenVAS/Nuclei scan records.

    Returns:
        Counts for canonical findings, inserted observations and reopened items.

    Raises:
        ExposureRepositoryError: If PostgreSQL synchronization fails.
        FindingDomainError: Propagated if a finding lacks canonical identity.
    """

    run_pending_migrations()
    client_id = get_client_id(client_name, create=False)
    canonical_findings = deduplicate_scan_history(client_id, scan_history)
    inserted_observations = 0
    reopened_findings = 0
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                transaction_client_id = _client_id(cursor, client_name)
                if transaction_client_id != client_id:
                    raise ExposureRepositoryError(
                        "Workspace identity changed during finding synchronization."
                    )
                for aggregate in canonical_findings:
                    cursor.execute(
                        """
                        SELECT id, lifecycle_status, severity, last_seen
                        FROM securescope_findings
                        WHERE client_id = %s AND fingerprint = %s
                        FOR UPDATE;
                        """,
                        (client_id, aggregate.fingerprint),
                    )
                    existing = cursor.fetchone()
                    if existing:
                        finding_id = int(existing["id"])
                        old_status = str(existing["lifecycle_status"])
                        preferred_severity = _preferred_severity(
                            str(existing["severity"]),
                            aggregate.severity,
                        )
                    else:
                        finding_id = 0
                        old_status = "New"
                        preferred_severity = aggregate.severity

                    newly_inserted = 0
                    if not existing:
                        cursor.execute(
                            """
                            INSERT INTO securescope_findings (
                                client_id,
                                finding_uuid,
                                fingerprint,
                                asset_identity,
                                vulnerability_identity,
                                title,
                                severity,
                                port,
                                protocol,
                                component,
                                lifecycle_status,
                                first_seen,
                                last_seen,
                                scanners,
                                most_recent_evidence
                            )
                            VALUES (
                                %s, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, 'New', %s, %s, %s, %s
                            )
                            RETURNING id;
                            """,
                            (
                                client_id,
                                str(uuid.uuid4()),
                                aggregate.fingerprint,
                                aggregate.asset_identity,
                                aggregate.vulnerability_identity,
                                aggregate.title,
                                preferred_severity,
                                aggregate.observations[0].port,
                                aggregate.observations[0].protocol,
                                aggregate.observations[0].component,
                                aggregate.first_seen,
                                aggregate.last_seen,
                                Json(sorted(aggregate.scanners)),
                                Json(dict(aggregate.observations[-1].raw)),
                            ),
                        )
                        finding_id = int(cursor.fetchone()["id"])
                        cursor.execute(
                            """
                            INSERT INTO securescope_finding_status_history (
                                client_id,
                                finding_id,
                                from_status,
                                to_status,
                                reason
                            )
                            VALUES (%s, %s, NULL, 'New', %s);
                            """,
                            (
                                client_id,
                                finding_id,
                                "Canonical finding created from scanner evidence.",
                            ),
                        )

                    for observation in aggregate.observations:
                        cursor.execute(
                            """
                            INSERT INTO securescope_finding_observations (
                                client_id,
                                finding_id,
                                observation_key,
                                scanner,
                                report_id,
                                provider_observation_id,
                                observed_at,
                                severity,
                                raw_evidence
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (client_id, observation_key) DO NOTHING
                            RETURNING id;
                            """,
                            (
                                client_id,
                                finding_id,
                                observation.observation_key,
                                observation.scanner,
                                observation.report_id,
                                observation.observation_key,
                                observation.observed_at,
                                observation.severity,
                                Json(dict(observation.raw)),
                            ),
                        )
                        if cursor.fetchone():
                            newly_inserted += 1
                    inserted_observations += newly_inserted

                    new_status = old_status
                    if existing and newly_inserted:
                        new_status = status_after_new_observation(old_status)
                    if new_status == "Reopened" and old_status != "Reopened":
                        reopened_findings += 1
                        cursor.execute(
                            """
                            INSERT INTO securescope_finding_status_history (
                                client_id,
                                finding_id,
                                from_status,
                                to_status,
                                reason
                            )
                            VALUES (%s, %s, %s, 'Reopened', %s);
                            """,
                            (
                                client_id,
                                finding_id,
                                old_status,
                                "A new scanner observation resurfaced the finding.",
                            ),
                        )

                    cursor.execute(
                        """
                        UPDATE securescope_findings
                        SET severity = %s,
                            lifecycle_status = %s,
                            first_seen = LEAST(first_seen, %s),
                            last_seen = GREATEST(last_seen, %s),
                            observation_count = (
                                SELECT COUNT(*)
                                FROM securescope_finding_observations observation
                                WHERE observation.client_id = %s
                                  AND observation.finding_id = %s
                            ),
                            scanners = (
                                SELECT COALESCE(
                                    jsonb_agg(scanner ORDER BY scanner),
                                    '[]'::jsonb
                                )
                                FROM (
                                    SELECT DISTINCT scanner
                                    FROM securescope_finding_observations
                                    WHERE client_id = %s AND finding_id = %s
                                ) scanner_rows
                            ),
                            most_recent_evidence = %s,
                            version = version + 1,
                            updated_at = NOW()
                        WHERE client_id = %s AND id = %s;
                        """,
                        (
                            preferred_severity,
                            new_status,
                            aggregate.first_seen,
                            aggregate.last_seen,
                            client_id,
                            finding_id,
                            client_id,
                            finding_id,
                            Json(dict(aggregate.observations[-1].raw)),
                            client_id,
                            finding_id,
                        ),
                    )
        return {
            "canonical_findings": len(canonical_findings),
            "inserted_observations": inserted_observations,
            "reopened_findings": reopened_findings,
        }
    except DatabaseError as exc:
        LOGGER.error("Finding synchronization failed for %s: %s", client_name, exc)
        raise ExposureRepositoryError(str(exc)) from exc


def list_findings(
    client_name: str,
    *,
    statuses: Sequence[str] | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """List canonical findings for exactly one workspace.

    Args:
        client_name: Exact workspace name.
        statuses: Optional lifecycle status filter.
        limit: Maximum number of rows from 1 to 10,000.

    Returns:
        Workspace-scoped canonical finding rows.

    Raises:
        ExposureRepositoryError: If filters are invalid or PostgreSQL fails.
    """

    if not 1 <= int(limit) <= 10_000:
        raise ExposureRepositoryError("Finding limit must be from 1 to 10000.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                parameters: list[Any] = [client_id]
                status_clause = ""
                if statuses:
                    status_clause = "AND lifecycle_status = ANY(%s)"
                    parameters.append(list(statuses))
                parameters.append(int(limit))
                cursor.execute(
                    f"""
                    SELECT
                        id,
                        finding_uuid::text AS finding_uuid,
                        fingerprint,
                        asset_identity,
                        vulnerability_identity,
                        title,
                        severity,
                        cvss,
                        port,
                        protocol,
                        component,
                        lifecycle_status AS status,
                        treatment_decision,
                        first_seen,
                        last_seen,
                        observation_count,
                        scanners,
                        kev_known_exploited,
                        epss_score,
                        verification_state,
                        most_recent_evidence,
                        version
                    FROM securescope_findings
                    WHERE client_id = %s
                    {status_clause}
                    ORDER BY
                        CASE severity
                            WHEN 'Critical' THEN 1
                            WHEN 'High' THEN 2
                            WHEN 'Medium' THEN 3
                            WHEN 'Low' THEN 4
                            WHEN 'Info' THEN 5
                            ELSE 6
                        END,
                        last_seen DESC
                    LIMIT %s;
                    """,
                    tuple(parameters),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def transition_finding(
    client_name: str,
    finding_id: int,
    target_status: str,
    *,
    actor: str,
    reason: str,
    evidence_reference: str = "",
    analyst_authorized: bool = False,
    false_positive_approved: bool = False,
    risk_acceptance_approved: bool = False,
) -> dict[str, Any]:
    """Apply one validated workspace-scoped finding lifecycle transition.

    Args:
        client_name: Exact workspace name.
        finding_id: Canonical finding identifier.
        target_status: Requested lifecycle status.
        actor: Person or service requesting the change.
        reason: Audit rationale.
        evidence_reference: Verification evidence reference.
        analyst_authorized: Whether an authorized analyst approved closure.
        false_positive_approved: Whether a false-positive decision is approved.
        risk_acceptance_approved: Whether an approved risk acceptance exists.

    Returns:
        Updated finding row.

    Raises:
        InvalidFindingTransitionError: If the domain transition is invalid.
        FindingVerificationRequiredError: If closure evidence is insufficient.
        ExposureRepositoryError: If the finding is absent or PostgreSQL fails.
    """

    if not actor.strip() or not reason.strip():
        raise ExposureRepositoryError("Finding transition requires actor and reason.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT id, lifecycle_status
                    FROM securescope_findings
                    WHERE client_id = %s AND id = %s
                    FOR UPDATE;
                    """,
                    (client_id, int(finding_id)),
                )
                current = cursor.fetchone()
                if not current:
                    raise ExposureRepositoryError(f"Finding not found in workspace: {finding_id}")
                current_status = str(current["lifecycle_status"])
                validate_finding_transition(
                    current_status,
                    target_status,
                    verification_evidence=bool(evidence_reference.strip()),
                    analyst_authorized=analyst_authorized,
                    false_positive_approved=false_positive_approved,
                    risk_acceptance_approved=risk_acceptance_approved,
                )
                cursor.execute(
                    """
                    UPDATE securescope_findings
                    SET lifecycle_status = %s,
                        verification_state = CASE
                            WHEN %s = 'Closed' THEN 'Verified'
                            ELSE verification_state
                        END,
                        updated_by = %s,
                        version = version + 1,
                        updated_at = NOW()
                    WHERE client_id = %s AND id = %s
                    RETURNING *;
                    """,
                    (
                        target_status,
                        target_status,
                        actor.strip(),
                        client_id,
                        int(finding_id),
                    ),
                )
                updated = dict(cursor.fetchone())
                cursor.execute(
                    """
                    INSERT INTO securescope_finding_status_history (
                        client_id,
                        finding_id,
                        from_status,
                        to_status,
                        reason,
                        evidence_reference,
                        changed_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        int(finding_id),
                        current_status,
                        target_status,
                        reason.strip(),
                        evidence_reference.strip() or None,
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
                        before_state,
                        after_state
                    )
                    VALUES (%s, 'finding.status_changed', 'finding', %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        str(finding_id),
                        actor.strip(),
                        reason.strip(),
                        Json({"status": current_status}),
                        Json({"status": target_status}),
                    ),
                )
                return updated
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def create_remediation_plan(
    client_name: str,
    plan: RemediationPlanInput,
    finding_ids: Sequence[int],
    *,
    actor: str,
    initial_task: Mapping[str, Any],
) -> int:
    """Create one plan and link only findings from the same workspace.

    Args:
        client_name: Exact workspace name.
        plan: Validated remediation plan fields.
        finding_ids: Canonical finding identifiers to link.
        actor: Creating user or service.
        initial_task: Required first task and milestone fields.

    Returns:
        New remediation plan identifier.

    Raises:
        ExposureRepositoryError: If a linked finding belongs elsewhere or
            PostgreSQL persistence fails.
        RemediationValidationError: Raised when ``plan`` is constructed with
            incomplete mandatory fields.
    """

    if not actor.strip():
        raise ExposureRepositoryError("Remediation plan requires an actor.")
    required_task_fields = (
        "title",
        "owner",
        "priority",
        "due_date",
        "sla_days",
        "success_criteria",
        "verification_method",
        "milestone_title",
        "milestone_owner",
        "milestone_due_date",
        "milestone_success_criteria",
    )
    missing_task_fields = [
        field_name
        for field_name in required_task_fields
        if initial_task.get(field_name) in (None, "")
    ]
    if missing_task_fields:
        raise ExposureRepositoryError(
            "Initial remediation task is missing: " + ", ".join(missing_task_fields)
        )
    if str(initial_task["priority"]) not in {"Critical", "High", "Medium", "Low"}:
        raise ExposureRepositoryError("Initial task priority is invalid.")
    if int(initial_task["sla_days"]) <= 0:
        raise ExposureRepositoryError("Initial task SLA must be positive.")
    if initial_task["due_date"] > plan.due_date:
        raise ExposureRepositoryError("Initial task due date exceeds plan due date.")
    if initial_task["milestone_due_date"] > initial_task["due_date"]:
        raise ExposureRepositoryError("Initial milestone due date exceeds task due date.")
    unique_finding_ids = sorted({int(value) for value in finding_ids})
    if not unique_finding_ids:
        raise ExposureRepositoryError(
            "A vulnerability remediation plan requires at least one finding."
        )
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM securescope_findings
                    WHERE client_id = %s AND id = ANY(%s);
                    """,
                    (client_id, unique_finding_ids),
                )
                if int(cursor.fetchone()[0]) != len(unique_finding_ids):
                    raise ExposureRepositoryError(
                        "One or more findings are outside the selected workspace."
                    )
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                    (f"finding-plan:{client_id}:{unique_finding_ids}",),
                )
                cursor.execute(
                    "SELECT p.id FROM securescope_remediation_plans p "
                    "JOIN securescope_remediation_plan_findings f ON "
                    "f.client_id=p.client_id AND f.plan_id=p.id "
                    "WHERE p.client_id=%s AND p.status NOT IN ('Completed','Cancelled') "
                    "GROUP BY p.id HAVING array_agg(DISTINCT f.finding_id ORDER "
                    "BY f.finding_id)=%s::bigint[] "
                    "ORDER BY p.id LIMIT 1",
                    (client_id, unique_finding_ids),
                )
                existing = cursor.fetchone()
                if existing:
                    return int(existing[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_plans (
                        client_id,
                        plan_uuid,
                        title,
                        description,
                        priority,
                        treatment_decision,
                        remediation_owner,
                        technical_owner,
                        business_owner,
                        risk_owner,
                        start_date,
                        due_date,
                        sla_days,
                        required_resources,
                        dependencies,
                        implementation_steps,
                        compensating_controls,
                        expected_risk_reduction,
                        success_criteria,
                        validation_method,
                        created_by,
                        updated_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        plan.title.strip(),
                        plan.description.strip(),
                        plan.priority,
                        plan.treatment_decision,
                        plan.remediation_owner.strip(),
                        plan.technical_owner.strip(),
                        plan.business_owner.strip(),
                        plan.risk_owner.strip(),
                        plan.start_date,
                        plan.due_date,
                        int(plan.sla_days),
                        plan.required_resources.strip(),
                        plan.dependencies.strip(),
                        plan.implementation_steps.strip(),
                        plan.compensating_controls.strip(),
                        plan.expected_risk_reduction.strip(),
                        plan.success_criteria.strip(),
                        plan.validation_method.strip(),
                        actor.strip(),
                        actor.strip(),
                    ),
                )
                plan_id = int(cursor.fetchone()[0])
                for finding_id in unique_finding_ids:
                    cursor.execute(
                        """
                        INSERT INTO securescope_remediation_plan_findings (
                            client_id,
                            plan_id,
                            finding_id
                        )
                        VALUES (%s, %s, %s);
                        """,
                        (client_id, plan_id, finding_id),
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_tasks (
                        client_id,
                        plan_id,
                        title,
                        description,
                        owner,
                        priority,
                        start_date,
                        due_date,
                        sla_days,
                        success_criteria,
                        verification_method,
                        created_by,
                        updated_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        plan_id,
                        str(initial_task["title"]).strip(),
                        str(initial_task.get("description") or "").strip(),
                        str(initial_task["owner"]).strip(),
                        str(initial_task["priority"]),
                        initial_task.get("start_date") or plan.start_date,
                        initial_task["due_date"],
                        int(initial_task["sla_days"]),
                        str(initial_task["success_criteria"]).strip(),
                        str(initial_task["verification_method"]).strip(),
                        actor.strip(),
                        actor.strip(),
                    ),
                )
                task_id = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_milestones (
                        client_id,
                        plan_id,
                        task_id,
                        title,
                        owner,
                        priority,
                        due_date,
                        sla_days,
                        success_criteria
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        plan_id,
                        task_id,
                        str(initial_task["milestone_title"]).strip(),
                        str(initial_task["milestone_owner"]).strip(),
                        str(initial_task["priority"]),
                        initial_task["milestone_due_date"],
                        int(initial_task["sla_days"]),
                        str(initial_task["milestone_success_criteria"]).strip(),
                    ),
                )
                milestone_id = int(cursor.fetchone()[0])
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
                        (%s, 'remediation_plan', %s, NULL, 'Draft', %s, %s),
                        (%s, 'remediation_task', %s, NULL, 'Open', %s, %s),
                        (%s, 'remediation_milestone', %s, NULL, 'Open', %s, %s);
                    """,
                    (
                        client_id,
                        plan_id,
                        "Remediation plan created.",
                        actor.strip(),
                        client_id,
                        task_id,
                        "Initial remediation task created.",
                        actor.strip(),
                        client_id,
                        milestone_id,
                        "Initial remediation milestone created.",
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
                    VALUES (%s, 'remediation.created', 'remediation_plan', %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        str(plan_id),
                        actor.strip(),
                        plan.title.strip(),
                        Json(
                            {
                                "finding_ids": unique_finding_ids,
                                "task_id": task_id,
                                "milestone_id": milestone_id,
                            }
                        ),
                    ),
                )
                return plan_id
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def list_remediation_plans(client_name: str) -> list[dict[str, Any]]:
    """List remediation plans and progress counts for one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Workspace-scoped plan rows with finding/task/milestone counts.

    Raises:
        ExposureRepositoryError: If PostgreSQL cannot load the rows.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        plan.id,
                        plan.plan_uuid::text AS plan_uuid,
                        plan.title,
                        plan.description,
                        plan.priority,
                        plan.status,
                        plan.treatment_decision,
                        plan.remediation_owner,
                        plan.technical_owner,
                        plan.business_owner,
                        plan.risk_owner,
                        plan.start_date,
                        plan.due_date,
                        plan.sla_days,
                        plan.success_criteria,
                        plan.validation_method,
                        COUNT(DISTINCT link.finding_id) AS finding_count,
                        ARRAY_REMOVE(
                            ARRAY_AGG(DISTINCT link.finding_id),
                            NULL
                        ) AS finding_ids,
                        COUNT(DISTINCT task.id) AS task_count,
                        COUNT(DISTINCT milestone.id) AS milestone_count,
                        COUNT(DISTINCT task.id) FILTER (
                            WHERE task.status = 'Completed'
                        ) AS completed_task_count,
                        (
                            plan.due_date < CURRENT_DATE
                            AND plan.status NOT IN ('Completed', 'Cancelled')
                        ) AS overdue
                    FROM securescope_remediation_plans plan
                    LEFT JOIN securescope_remediation_plan_findings link
                      ON link.client_id = plan.client_id AND link.plan_id = plan.id
                    LEFT JOIN securescope_remediation_tasks task
                      ON task.client_id = plan.client_id AND task.plan_id = plan.id
                    LEFT JOIN securescope_remediation_milestones milestone
                      ON milestone.client_id = plan.client_id AND milestone.plan_id = plan.id
                    WHERE plan.client_id = %s
                    GROUP BY plan.id
                    ORDER BY overdue DESC, plan.due_date, plan.updated_at DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def list_remediation_work_items(client_name: str) -> list[dict[str, Any]]:
    """List remediation tasks and milestones with mandatory management fields.

    Args:
        client_name: Exact workspace name.

    Returns:
        Workspace-scoped task and milestone rows.

    Raises:
        ExposureRepositoryError: If PostgreSQL cannot load work items.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        'task' AS entity_type,
                        task.id,
                        task.plan_id,
                        plan.title AS plan_title,
                        task.title,
                        task.owner,
                        task.status,
                        task.priority,
                        task.sla_days,
                        task.due_date,
                        task.success_criteria,
                        task.verification_method,
                        NULL::text AS evidence_reference
                    FROM securescope_remediation_tasks task
                    JOIN securescope_remediation_plans plan
                      ON plan.client_id = task.client_id
                     AND plan.id = task.plan_id
                    WHERE task.client_id = %s
                    UNION ALL
                    SELECT
                        'milestone' AS entity_type,
                        milestone.id,
                        milestone.plan_id,
                        plan.title AS plan_title,
                        milestone.title,
                        milestone.owner,
                        milestone.status,
                        milestone.priority,
                        milestone.sla_days,
                        milestone.due_date,
                        milestone.success_criteria,
                        'Validate milestone success criteria' AS verification_method,
                        milestone.evidence_reference
                    FROM securescope_remediation_milestones milestone
                    JOIN securescope_remediation_plans plan
                      ON plan.client_id = milestone.client_id
                     AND plan.id = milestone.plan_id
                    WHERE milestone.client_id = %s
                    ORDER BY due_date, entity_type, id;
                    """,
                    (client_id, client_id),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def transition_remediation_work_item(
    client_name: str,
    entity_type: str,
    entity_id: int,
    target_status: str,
    *,
    actor: str,
    reason: str,
    evidence_reference: str = "",
) -> None:
    """Transition one task or milestone and retain status/audit history.

    Args:
        client_name: Exact workspace name.
        entity_type: ``task`` or ``milestone``.
        entity_id: Workspace-scoped work-item identifier.
        target_status: Requested work-item status.
        actor: User applying the transition.
        reason: Required audit rationale.
        evidence_reference: Required completion evidence reference.

    Returns:
        None after a committed transition.

    Raises:
        ExposureRepositoryError: If status, evidence, scope or persistence is invalid.
    """

    statuses = {
        "task": {
            "Open",
            "In progress",
            "Blocked",
            "Ready for verification",
            "Completed",
            "Cancelled",
        },
        "milestone": {"Open", "In progress", "Blocked", "Completed", "Cancelled"},
    }
    if entity_type not in statuses or target_status not in statuses[entity_type]:
        raise ExposureRepositoryError("Unsupported remediation work-item transition.")
    if not actor.strip() or not reason.strip():
        raise ExposureRepositoryError("Work-item transition requires actor and reason.")
    if target_status == "Completed" and not evidence_reference.strip():
        raise ExposureRepositoryError(
            "Completing a remediation work item requires verification evidence."
        )
    proof_id = None
    if target_status == "Completed":
        match = re.fullmatch(r"EV-(\d+)", evidence_reference.strip(), re.IGNORECASE)
        if not match:
            raise ExposureRepositoryError(
                (
                    "Select canonical verification evidence using EV-<id>; a "
                    "control ID is not evidence."
                )
            )
        proof_id = int(match.group(1))
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                if entity_type == "task":
                    cursor.execute(
                        """
                        SELECT status, plan_id
                        FROM securescope_remediation_tasks
                        WHERE client_id = %s AND id = %s
                        FOR UPDATE;
                        """,
                        (client_id, int(entity_id)),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT status, plan_id
                        FROM securescope_remediation_milestones
                        WHERE client_id = %s AND id = %s
                        FOR UPDATE;
                        """,
                        (client_id, int(entity_id)),
                    )
                current = cursor.fetchone()
                if not current:
                    raise ExposureRepositoryError(
                        "Remediation work item is outside the selected workspace."
                    )
                current_status, plan_id = str(current[0]), int(current[1])
                if target_status == "Completed":
                    if entity_type == "task" and current_status != "Ready for verification":
                        raise ExposureRepositoryError(
                            "Move the task to Ready for verification before completing it."
                        )
                    with connection.cursor(cursor_factory=RealDictCursor) as evidence_cursor:
                        from securescope.persistence.foundation_repository import member_role
                        from securescope.grc.assurance_requirements import evidence_freshness

                        if member_role(evidence_cursor, client_id, actor) not in {
                            "Administrator",
                            "Consultant",
                        }:
                            raise ExposureRepositoryError(
                                "An authorized reviewer must verify completion."
                            )
                        evidence_cursor.execute(
                            "SELECT id,validation_status,validator,validated_at,"
                            "collected_at,expires_at,freshness_status "
                            "FROM securescope_evidence_records WHERE client_id=%s AND "
                            "id=%s FOR SHARE",
                            (client_id, proof_id),
                        )
                        proof = evidence_cursor.fetchone()
                        if (
                            not proof
                            or proof["validation_status"] != "Validated"
                            or not proof.get("validator")
                            or not proof.get("validated_at")
                            or evidence_freshness(proof, 90, datetime.now(timezone.utc))
                            not in {"Current", "Expiring Soon"}
                        ):
                            raise ExposureRepositoryError(
                                "Completion needs fresh canonical evidence accepted by a reviewer."
                            )
                if entity_type == "task":
                    cursor.execute(
                        """
                        UPDATE securescope_remediation_tasks
                        SET status = %s,
                            updated_by = %s,
                            version = version + 1,
                            updated_at = NOW()
                        WHERE client_id = %s AND id = %s;
                        """,
                        (target_status, actor.strip(), client_id, int(entity_id)),
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE securescope_remediation_milestones
                        SET status = %s,
                            completion_date = CASE
                                WHEN %s = 'Completed' THEN CURRENT_DATE
                                ELSE completion_date
                            END,
                            evidence_reference = COALESCE(%s, evidence_reference),
                            updated_at = NOW()
                        WHERE client_id = %s AND id = %s;
                        """,
                        (
                            target_status,
                            target_status,
                            evidence_reference.strip() or None,
                            client_id,
                            int(entity_id),
                        ),
                    )
                if target_status == "Completed":
                    cursor.execute(
                        """
                        INSERT INTO securescope_verification_evidence (
                            client_id,
                            plan_id,
                            task_id,
                            milestone_id,
                            evidence_type,
                            source,
                            raw_reference,
                            summary,
                            collected_at,
                            confidence
                        )
                        VALUES (
                            %s, %s, %s, %s, 'Closure evidence', 'Manual',
                            %s, %s, NOW(), 'Medium'
                        );
                        """,
                        (
                            client_id,
                            plan_id,
                            int(entity_id) if entity_type == "task" else None,
                            int(entity_id) if entity_type == "milestone" else None,
                            evidence_reference.strip(),
                            reason.strip(),
                        ),
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_entity_status_history (
                        client_id,
                        entity_type,
                        entity_id,
                        from_status,
                        to_status,
                        reason,
                        evidence_reference,
                        changed_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        f"remediation_{entity_type}",
                        int(entity_id),
                        current_status,
                        target_status,
                        reason.strip(),
                        evidence_reference.strip() or None,
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
                        before_state,
                        after_state
                    )
                    VALUES (
                        %s, 'remediation.status_changed', %s, %s,
                        %s, %s, %s, %s
                    );
                    """,
                    (
                        client_id,
                        f"remediation_{entity_type}",
                        str(entity_id),
                        actor.strip(),
                        reason.strip(),
                        Json({"status": current_status}),
                        Json({"status": target_status}),
                    ),
                )
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def create_risk_acceptance(
    client_name: str,
    acceptance: RiskAcceptance,
    *,
    inherent_likelihood: str,
    inherent_impact: str,
    current_controls: str,
    review_frequency: str,
    actor: str,
    finding_id: int | None = None,
    gap_id: int | None = None,
    risk_reference: str | None = None,
) -> int:
    """Persist one complete, approved workspace risk acceptance.

    Args:
        client_name: Exact workspace name.
        acceptance: Validated residual-risk acceptance.
        inherent_likelihood: Inherent likelihood before treatment.
        inherent_impact: Inherent impact before treatment.
        current_controls: Existing safeguards.
        review_frequency: Required review cadence.
        actor: Creating user.
        finding_id: Optional linked canonical finding.
        gap_id: Optional linked control gap.
        risk_reference: Optional external/internal risk identifier.

    Returns:
        New risk acceptance identifier.

    Raises:
        RiskAcceptanceValidationError: If ``acceptance`` is incomplete.
        ExposureRepositoryError: If linkage or PostgreSQL persistence fails.
    """

    supplemental = {
        "inherent_likelihood": inherent_likelihood,
        "inherent_impact": inherent_impact,
        "current_controls": current_controls,
        "review_frequency": review_frequency,
        "actor": actor,
    }
    missing = [name for name, value in supplemental.items() if not value.strip()]
    if missing:
        raise ExposureRepositoryError("Risk acceptance is missing: " + ", ".join(missing))
    if not any((finding_id, gap_id, str(risk_reference or "").strip())):
        raise ExposureRepositoryError("Risk acceptance requires a finding, gap or risk reference.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                current_status = ""
                if finding_id is not None:
                    cursor.execute(
                        """
                        SELECT lifecycle_status
                        FROM securescope_findings
                        WHERE client_id = %s AND id = %s
                        FOR UPDATE;
                        """,
                        (client_id, int(finding_id)),
                    )
                    finding_row = cursor.fetchone()
                    if not finding_row:
                        raise ExposureRepositoryError(
                            "Risk acceptance finding is outside the selected workspace."
                        )
                    current_status = str(finding_row[0])
                    validate_finding_transition(
                        current_status,
                        "Accepted risk",
                        risk_acceptance_approved=True,
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_risk_acceptances (
                        client_id,
                        acceptance_uuid,
                        finding_id,
                        gap_id,
                        risk_reference,
                        business_justification,
                        risk_owner,
                        approver,
                        approval_date,
                        inherent_likelihood,
                        inherent_impact,
                        current_controls,
                        residual_likelihood,
                        residual_impact,
                        residual_risk_level,
                        compensating_controls,
                        evidence_reference,
                        effective_date,
                        expiration_date,
                        review_frequency,
                        acceptance_scope,
                        status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Approved', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        finding_id,
                        gap_id,
                        str(risk_reference or "").strip() or None,
                        acceptance.business_justification.strip(),
                        acceptance.risk_owner.strip(),
                        acceptance.approver.strip(),
                        acceptance.approval_date,
                        inherent_likelihood.strip(),
                        inherent_impact.strip(),
                        current_controls.strip(),
                        acceptance.residual_likelihood.strip(),
                        acceptance.residual_impact.strip(),
                        acceptance.residual_risk_level.strip(),
                        acceptance.compensating_controls.strip(),
                        acceptance.evidence_reference.strip(),
                        acceptance.effective_date,
                        acceptance.expiration_date,
                        review_frequency.strip(),
                        acceptance.acceptance_scope.strip(),
                        actor.strip(),
                    ),
                )
                acceptance_id = int(cursor.fetchone()[0])
                if finding_id is not None:
                    cursor.execute(
                        """
                        UPDATE securescope_findings
                        SET lifecycle_status = 'Accepted risk',
                            treatment_decision = 'Accept',
                            updated_by = %s,
                            version = version + 1,
                            updated_at = NOW()
                        WHERE client_id = %s AND id = %s;
                        """,
                        (actor.strip(), client_id, int(finding_id)),
                    )
                    if cursor.rowcount != 1:
                        raise ExposureRepositoryError(
                            "Risk acceptance finding is outside the selected workspace."
                        )
                    cursor.execute(
                        """
                        INSERT INTO securescope_finding_status_history (
                            client_id,
                            finding_id,
                            from_status,
                            to_status,
                            reason,
                            evidence_reference,
                            changed_by
                        )
                        VALUES (%s, %s, %s, 'Accepted risk', %s, %s, %s);
                        """,
                        (
                            client_id,
                            int(finding_id),
                            current_status,
                            acceptance.business_justification.strip(),
                            acceptance.evidence_reference.strip(),
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
                    VALUES (%s, 'risk_acceptance.approved', 'risk_acceptance',
                            %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        str(acceptance_id),
                        actor.strip(),
                        acceptance.business_justification.strip(),
                        Json(
                            {
                                "finding_id": finding_id,
                                "gap_id": gap_id,
                                "risk_reference": risk_reference,
                                "expiration_date": acceptance.expiration_date.isoformat(),
                                "status": "Approved",
                            }
                        ),
                    ),
                )
                return acceptance_id
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def mark_expired_risk_acceptances(client_name: str) -> int:
    """Mark expired risk acceptances as Due for review in one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Number of decisions moved to Due for review.

    Raises:
        ExposureRepositoryError: If PostgreSQL update fails.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    UPDATE securescope_risk_acceptances
                    SET status = 'Due for review', updated_at = NOW()
                    WHERE client_id = %s
                      AND status = 'Approved'
                      AND expiration_date <= CURRENT_DATE
                    RETURNING id, finding_id, gap_id, evidence_reference;
                    """,
                    (client_id,),
                )
                expired_rows = cursor.fetchall()
                for acceptance_id, finding_id, gap_id, evidence_reference in expired_rows:
                    if finding_id is not None:
                        cursor.execute(
                            """
                            UPDATE securescope_findings finding
                            SET lifecycle_status = 'Reopened',
                                treatment_decision = NULL,
                                verification_state = 'Risk review required',
                                version = version + 1,
                                updated_at = NOW()
                            WHERE finding.client_id = %s
                              AND finding.id = %s
                              AND finding.lifecycle_status = 'Accepted risk'
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM securescope_risk_acceptances acceptance
                                  WHERE acceptance.client_id = finding.client_id
                                    AND acceptance.finding_id = finding.id
                                    AND acceptance.status = 'Approved'
                                    AND acceptance.expiration_date > CURRENT_DATE
                              );
                            """,
                            (client_id, int(finding_id)),
                        )
                        if cursor.rowcount == 1:
                            cursor.execute(
                                """
                                INSERT INTO securescope_finding_status_history (
                                    client_id,
                                    finding_id,
                                    from_status,
                                    to_status,
                                    reason,
                                    evidence_reference,
                                    changed_by
                                )
                                VALUES (
                                    %s, %s, 'Accepted risk', 'Reopened',
                                    'Risk acceptance expired and requires review.',
                                    %s, 'system'
                                );
                                """,
                                (client_id, int(finding_id), evidence_reference),
                            )
                    if gap_id is not None:
                        cursor.execute(
                            """
                            UPDATE securescope_control_gaps gap
                            SET status = 'Reopened', updated_at = NOW()
                            WHERE gap.client_id = %s
                              AND gap.id = %s
                              AND gap.status = 'Accepted risk'
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM securescope_risk_acceptances acceptance
                                  WHERE acceptance.client_id = gap.client_id
                                    AND acceptance.gap_id = gap.id
                                    AND acceptance.status = 'Approved'
                                    AND acceptance.expiration_date > CURRENT_DATE
                              );
                            """,
                            (client_id, int(gap_id)),
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
                            %s, 'risk_acceptance.review_due', 'risk_acceptance',
                            %s, 'system',
                            'Risk acceptance expiration date reached.',
                            %s
                        );
                        """,
                        (
                            client_id,
                            str(acceptance_id),
                            Json(
                                {
                                    "status": "Due for review",
                                    "finding_id": finding_id,
                                    "gap_id": gap_id,
                                }
                            ),
                        ),
                    )
                return len(expired_rows)
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def workspace_dashboard_metrics(client_name: str) -> dict[str, Any]:
    """Aggregate executive exposure and GRC metrics for one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Metric dictionary. Optional enrichment values are ``None`` when data
        is unavailable rather than a misleading zero.

    Raises:
        ExposureRepositoryError: If PostgreSQL aggregation fails.
    """

    run_pending_migrations()
    mark_expired_risk_acceptances(client_name)
    active_statuses = sorted(ACTIVE_FINDING_STATUSES)
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s)
                        ) AS unique_active_findings,
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s) AND severity = 'Critical'
                        ) AS critical,
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s) AND severity = 'High'
                        ) AS high,
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s) AND severity = 'Medium'
                        ) AS medium,
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s) AND severity = 'Low'
                        ) AS low,
                        COUNT(*) FILTER (
                            WHERE lifecycle_status = ANY(%s) AND severity = 'Info'
                        ) AS informational,
                        CASE
                            WHEN COUNT(kev_known_exploited) = 0 THEN NULL
                            ELSE COUNT(*) FILTER (
                                WHERE lifecycle_status = ANY(%s)
                                  AND kev_known_exploited IS TRUE
                            )
                        END AS kev,
                        CASE
                            WHEN COUNT(epss_score) = 0 THEN NULL
                            ELSE COUNT(*) FILTER (
                                WHERE lifecycle_status = ANY(%s)
                                  AND epss_score >= 0.5
                            )
                        END AS high_epss,
                        AVG(EXTRACT(EPOCH FROM (NOW() - first_seen)) / 86400.0)
                            FILTER (WHERE lifecycle_status = ANY(%s)) AS mean_age_days
                    FROM securescope_findings
                    WHERE client_id = %s;
                    """,
                    (
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        active_statuses,
                        client_id,
                    ),
                )
                metrics = dict(cursor.fetchone())
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (
                            WHERE due_date < CURRENT_DATE
                              AND status NOT IN ('Completed', 'Cancelled')
                        ) AS overdue_remediation,
                        COUNT(*) FILTER (WHERE status = 'Completed') AS completed_plans,
                        COUNT(*) FILTER (
                            WHERE status = 'Completed'
                              AND updated_at::date <= due_date
                        ) AS sla_compliant_completed_plans,
                        COUNT(*) AS total_plans
                    FROM securescope_remediation_plans
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT COUNT(*) FILTER (
                        WHERE scheduled_completion_date < CURRENT_DATE
                          AND status NOT IN ('Completed', 'Cancelled')
                    ) AS overdue_poam_items
                    FROM securescope_poam_items
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT
                        COUNT(DISTINCT action.id) FILTER (
                            WHERE action.due_date < CURRENT_DATE
                              AND action.status NOT IN ('Completed', 'Cancelled')
                        ) AS overdue_actions,
                        COUNT(DISTINCT milestone.id) FILTER (
                            WHERE milestone.due_date < CURRENT_DATE
                              AND milestone.status NOT IN ('Completed', 'Cancelled')
                        ) AS overdue_milestones
                    FROM securescope_improvement_actions action
                    LEFT JOIN securescope_improvement_milestones milestone
                      ON milestone.client_id = action.client_id
                     AND milestone.action_id = action.id
                    WHERE action.client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    WITH first_closure AS (
                        SELECT finding_id, MIN(changed_at) AS closed_at
                        FROM securescope_finding_status_history
                        WHERE client_id = %s AND to_status = 'Closed'
                        GROUP BY finding_id
                    )
                    SELECT AVG(
                        EXTRACT(EPOCH FROM (closure.closed_at - finding.first_seen))
                        / 86400.0
                    ) AS mean_time_to_remediate_days
                    FROM first_closure closure
                    JOIN securescope_findings finding
                      ON finding.client_id = %s
                     AND finding.id = closure.finding_id;
                    """,
                    (client_id, client_id),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE status = 'Approved') AS accepted_risks,
                        COUNT(*) FILTER (
                            WHERE status = 'Approved'
                              AND expiration_date <= CURRENT_DATE + 30
                        ) AS accepted_risks_expiring,
                        COUNT(*) FILTER (WHERE status = 'Due for review') AS risk_reviews_due
                    FROM securescope_risk_acceptances
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (
                            WHERE status IN ('Open', 'In progress', 'Reopened')
                        ) AS open_gaps,
                        COUNT(*) FILTER (
                            WHERE status NOT IN ('Closed', 'Accepted risk')
                              AND priority IN ('Critical', 'High')
                        ) AS priority_gaps
                    FROM securescope_control_gaps
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (
                            WHERE assessment_status IN (
                                'Not assessed', 'Manual assessment required',
                                'Insufficient evidence'
                            )
                        ) AS controls_requiring_assessment,
                        COUNT(*) FILTER (
                            WHERE evidence_freshness IN (
                                'Approaching expiration', 'Expired'
                            )
                        ) AS evidence_due
                    FROM securescope_control_assessments
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                metrics.update(dict(cursor.fetchone()))
                total_plans = int(metrics.get("total_plans") or 0)
                completed_plans = int(metrics.get("completed_plans") or 0)
                sla_compliant = int(metrics.get("sla_compliant_completed_plans") or 0)
                metrics["remediation_completion_rate"] = (
                    round(completed_plans / total_plans * 100, 1) if total_plans else None
                )
                metrics["sla_compliance"] = (
                    round(sla_compliant / completed_plans * 100, 1) if completed_plans else None
                )
                mean_age = metrics.get("mean_age_days")
                metrics["mean_age_days"] = (
                    round(float(mean_age), 1) if mean_age is not None else None
                )
                mean_remediation = metrics.get("mean_time_to_remediate_days")
                metrics["mean_time_to_remediate_days"] = (
                    round(float(mean_remediation), 1) if mean_remediation is not None else None
                )
                return metrics
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def workspace_finding_analysis(
    client_name: str,
    *,
    days: int = 30,
) -> dict[str, list[dict[str, Any]]]:
    """Load workspace finding trends, age, scanner and SLA analysis.

    Args:
        client_name: Exact workspace name.
        days: Trend window; must be 7, 30 or 90 days.

    Returns:
        Workspace-scoped analysis tables for the executive Overview.

    Raises:
        ExposureRepositoryError: If the range or PostgreSQL query is invalid.
    """

    if int(days) not in {7, 30, 90}:
        raise ExposureRepositoryError("Finding trend range must be 7, 30 or 90 days.")
    run_pending_migrations()
    active_statuses = sorted(ACTIVE_FINDING_STATUSES)
    result: dict[str, list[dict[str, Any]]] = {}
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        changed_at::date AS event_date,
                        to_status AS status,
                        COUNT(*) AS event_count
                    FROM securescope_finding_status_history
                    WHERE client_id = %s
                      AND changed_at >= CURRENT_DATE - %s
                    GROUP BY changed_at::date, to_status
                    ORDER BY event_date, status;
                    """,
                    (client_id, int(days)),
                )
                result["status_trends"] = [dict(row) for row in cursor.fetchall()]
                cursor.execute(
                    """
                    SELECT
                        CASE
                            WHEN NOW() - first_seen < INTERVAL '30 days' THEN '0-30 days'
                            WHEN NOW() - first_seen < INTERVAL '60 days' THEN '31-60 days'
                            WHEN NOW() - first_seen < INTERVAL '90 days' THEN '61-90 days'
                            ELSE '90+ days'
                        END AS age_bucket,
                        COUNT(*) AS finding_count
                    FROM securescope_findings
                    WHERE client_id = %s AND lifecycle_status = ANY(%s)
                    GROUP BY age_bucket
                    ORDER BY MIN(NOW() - first_seen);
                    """,
                    (client_id, active_statuses),
                )
                result["age_buckets"] = [dict(row) for row in cursor.fetchall()]
                cursor.execute(
                    """
                    SELECT scanner, COUNT(DISTINCT finding_id) AS finding_count
                    FROM securescope_finding_observations
                    WHERE client_id = %s
                    GROUP BY scanner
                    ORDER BY finding_count DESC, scanner;
                    """,
                    (client_id,),
                )
                result["scanners"] = [dict(row) for row in cursor.fetchall()]
                cursor.execute(
                    """
                    SELECT asset_identity, COUNT(*) AS finding_count
                    FROM securescope_findings
                    WHERE client_id = %s AND lifecycle_status = ANY(%s)
                    GROUP BY asset_identity
                    ORDER BY finding_count DESC, asset_identity
                    LIMIT 10;
                    """,
                    (client_id, active_statuses),
                )
                result["affected_assets"] = [dict(row) for row in cursor.fetchall()]
                cursor.execute(
                    """
                    SELECT
                        finding.severity,
                        COUNT(DISTINCT plan.id) AS plan_count,
                        COUNT(DISTINCT plan.id) FILTER (
                            WHERE plan.status = 'Completed'
                              AND plan.updated_at::date <= plan.due_date
                        ) AS completed_within_sla,
                        COUNT(DISTINCT plan.id) FILTER (
                            WHERE plan.due_date < CURRENT_DATE
                              AND plan.status NOT IN ('Completed', 'Cancelled')
                        ) AS overdue
                    FROM securescope_findings finding
                    JOIN securescope_remediation_plan_findings link
                      ON link.client_id = finding.client_id
                     AND link.finding_id = finding.id
                    JOIN securescope_remediation_plans plan
                      ON plan.client_id = link.client_id
                     AND plan.id = link.plan_id
                    WHERE finding.client_id = %s
                    GROUP BY finding.severity
                    ORDER BY CASE finding.severity
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        WHEN 'Low' THEN 4
                        WHEN 'Info' THEN 5
                        ELSE 6
                    END;
                    """,
                    (client_id,),
                )
                result["sla_by_severity"] = [dict(row) for row in cursor.fetchall()]
                return result
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def list_audit_events(
    client_name: str,
    *,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """List recent audit events for exactly one workspace.

    Args:
        client_name: Exact workspace name.
        limit: Maximum rows from 1 to 5,000.

    Returns:
        Recent workspace audit events.

    Raises:
        ExposureRepositoryError: If the limit or PostgreSQL query is invalid.
    """

    if not 1 <= int(limit) <= 5_000:
        raise ExposureRepositoryError("Audit limit must be from 1 to 5000.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        id,
                        event_type,
                        entity_type,
                        entity_id,
                        actor,
                        summary,
                        before_state,
                        after_state,
                        created_at
                    FROM securescope_audit_events
                    WHERE client_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (client_id, int(limit)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc
