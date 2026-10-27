"""Workspace-scoped persistence for approved remediation execution requests."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any, Mapping

from psycopg2.extras import Json, RealDictCursor

from securescope.compliance.quick_remediation_service import REMEDIATION_EXECUTION_STATUSES
from securescope.compliance.remediation_recipe_service import RemediationRecipe
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.exposure_repository import ExposureRepositoryError, _client_id
from securescope.persistence.migration_service import run_pending_migrations


def create_approved_execution(
    client_name: str,
    *,
    plan_id: int,
    finding_id: int,
    recipe: RemediationRecipe,
    candidate_checksum: str,
    asset_identity: str,
    asset_ip: str,
    asset_tag: str,
    wazuh_agent_id: str,
    wazuh_agent_status: str,
    requested_by: str,
    approved_by: str,
    approval_recorded: bool,
) -> int:
    """Persist one explicitly approved, exact-asset execution request.

    Args:
        client_name: Exact SecureScope workspace.
        plan_id: Workspace remediation plan identifier.
        finding_id: Workspace canonical finding identifier.
        recipe: Integrity-checked allow-listed recipe.
        candidate_checksum: Prepared candidate SHA-256 digest.
        asset_identity: Exact canonical finding asset identity.
        asset_ip: Exact endpoint address to verify after the change.
        asset_tag: Persistent inventory tag.
        wazuh_agent_id: Exact synchronized Wazuh agent identifier.
        wazuh_agent_status: Current Wazuh agent state.
        requested_by: Requesting analyst.
        approved_by: Identified approver.
        approval_recorded: Explicit approval checkbox state.

    Returns:
        New execution identifier.

    Raises:
        ExposureRepositoryError: If approval, scope, or persistence is invalid.
    """

    if not approval_recorded or not approved_by.strip():
        raise ExposureRepositoryError(
            "Approved execution requires an identified explicit approver."
        )
    if not requested_by.strip() or not asset_identity.strip():
        raise ExposureRepositoryError(
            "Execution request requires an analyst and exact asset identity."
        )
    try:
        normalized_ip = str(ipaddress.ip_address(asset_ip.strip()))
    except ValueError as exc:
        raise ExposureRepositoryError("Execution target IP is invalid.") from exc
    if not wazuh_agent_id.strip() or wazuh_agent_id.strip() == "000":
        raise ExposureRepositoryError(
            "Execution requires a synchronized endpoint agent, not manager 000."
        )
    if len(candidate_checksum) != 64:
        raise ExposureRepositoryError("Candidate checksum is invalid.")
    recipe.verify_integrity()
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM securescope_remediation_plan_findings link
                    WHERE link.client_id = %s
                      AND link.plan_id = %s
                      AND link.finding_id = %s;
                    """,
                    (client_id, int(plan_id), int(finding_id)),
                )
                if int(cursor.fetchone()[0]) != 1:
                    raise ExposureRepositoryError(
                        "Plan and finding are not linked in the selected workspace."
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_executions (
                        client_id, execution_uuid, plan_id, finding_id,
                        recipe_id, recipe_version, recipe_checksum,
                        candidate_checksum, execution_level, status,
                        asset_identity, asset_ip, asset_tag,
                        wazuh_agent_id, wazuh_agent_status,
                        requested_by, approved_by, approved_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        'Approved execution', 'Approved', %s, %s, %s,
                        %s, %s, %s, %s, NOW()
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        str(uuid.uuid4()),
                        int(plan_id),
                        int(finding_id),
                        recipe.recipe_id,
                        recipe.version,
                        recipe.artifact_sha256,
                        candidate_checksum,
                        asset_identity.strip(),
                        normalized_ip,
                        asset_tag.strip(),
                        wazuh_agent_id.strip(),
                        wazuh_agent_status.strip(),
                        requested_by.strip(),
                        approved_by.strip(),
                    ),
                )
                execution_id = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_execution_events (
                        client_id, execution_id, from_status, to_status,
                        actor, reason, event_payload
                    )
                    VALUES (%s, %s, 'Awaiting approval', 'Approved', %s, %s, %s);
                    """,
                    (
                        client_id,
                        execution_id,
                        approved_by.strip(),
                        "Exact workspace, asset, recipe and Wazuh agent approved.",
                        Json({"recipe_id": recipe.recipe_id}),
                    ),
                )
                return execution_id
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def list_remediation_executions(client_name: str) -> list[dict[str, Any]]:
    """List remediation executions for exactly one workspace.

    Args:
        client_name: Exact workspace name.

    Returns:
        Newest execution rows first.

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
                    SELECT id, execution_uuid::text, plan_id, finding_id,
                           recipe_id, recipe_version, execution_level, status,
                           asset_identity, asset_ip::text, asset_tag,
                           wazuh_agent_id, requested_by, requested_at,
                           approved_by, approved_at, started_at, completed_at,
                           restart_required, sanitized_log, exit_code,
                           verification_engine, verification_not_before,
                           verification_batch_id,
                           verification_reference, failure_reason,
                           rollback_reference, updated_at
                    FROM securescope_remediation_executions
                    WHERE client_id = %s
                    ORDER BY requested_at DESC, id DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def claim_approved_execution() -> dict[str, Any] | None:
    """Claim one globally queued execution with PostgreSQL row locking.

    Returns:
        Claimed execution with workspace name, or ``None``.

    Raises:
        ExposureRepositoryError: If the transactional claim fails.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT execution.*, client.name AS client_name
                    FROM securescope_remediation_executions execution
                    JOIN securescope_clients client ON client.id = execution.client_id
                    WHERE execution.status = 'Approved'
                    ORDER BY execution.requested_at, execution.id
                    FOR UPDATE OF execution SKIP LOCKED
                    LIMIT 1;
                    """
                )
                row = cursor.fetchone()
                if not row:
                    return None
                cursor.execute(
                    """
                    UPDATE securescope_remediation_executions
                    SET status = 'Running', started_at = NOW(), updated_at = NOW(),
                        version = version + 1
                    WHERE client_id = %s AND id = %s AND status = 'Approved';
                    """,
                    (int(row["client_id"]), int(row["id"])),
                )
                if cursor.rowcount != 1:
                    return None
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_execution_events (
                        client_id, execution_id, from_status, to_status,
                        actor, reason
                    )
                    VALUES (%s, %s, 'Approved', 'Running', %s, %s);
                    """,
                    (
                        int(row["client_id"]),
                        int(row["id"]),
                        "remediation-worker",
                        "Worker claimed the explicitly approved request.",
                    ),
                )
                result = dict(row)
                result["status"] = "Running"
                return result
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def update_execution_status(
    client_name: str,
    execution_id: int,
    target_status: str,
    *,
    actor: str,
    reason: str,
    values: Mapping[str, Any] | None = None,
) -> None:
    """Update one execution inside its exact workspace and append an event.

    Args:
        client_name: Exact workspace name.
        execution_id: Claimed execution identifier.
        target_status: Valid execution status.
        actor: Worker or analyst identity.
        reason: Audit rationale.
        values: Optional bounded dispatch/verification fields.

    Returns:
        None.

    Raises:
        ExposureRepositoryError: If status, identity, or persistence is invalid.
    """

    if target_status not in REMEDIATION_EXECUTION_STATUSES:
        raise ExposureRepositoryError("Unsupported remediation execution status.")
    if not actor.strip() or not reason.strip():
        raise ExposureRepositoryError("Execution status change requires actor and reason.")
    payload = dict(values or {})
    event_payload = {
        key: value.isoformat() if hasattr(value, "isoformat") else value
        for key, value in payload.items()
    }
    allowed = {
        "dispatch_result",
        "sanitized_log",
        "exit_code",
        "restart_required",
        "verification_batch_id",
        "verification_not_before",
        "verification_reference",
        "failure_reason",
        "rollback_reference",
    }
    unknown = set(payload).difference(allowed)
    if unknown:
        raise ExposureRepositoryError(
            "Unsupported execution update fields: " + ", ".join(sorted(unknown))
        )
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT status FROM securescope_remediation_executions
                    WHERE client_id = %s AND id = %s FOR UPDATE;
                    """,
                    (client_id, int(execution_id)),
                )
                row = cursor.fetchone()
                if not row:
                    raise ExposureRepositoryError(
                        "Remediation execution is outside the selected workspace."
                    )
                previous_status = str(row["status"])
                cursor.execute(
                    """
                    UPDATE securescope_remediation_executions
                    SET status = %s,
                        dispatch_result = COALESCE(%s, dispatch_result),
                        sanitized_log = COALESCE(%s, sanitized_log),
                        exit_code = COALESCE(%s, exit_code),
                        restart_required = COALESCE(%s, restart_required),
                        verification_not_before = COALESCE(
                            %s,
                            verification_not_before
                        ),
                        verification_batch_id = COALESCE(%s, verification_batch_id),
                        verification_reference = COALESCE(%s, verification_reference),
                        failure_reason = COALESCE(%s, failure_reason),
                        rollback_reference = COALESCE(%s, rollback_reference),
                        completed_at = CASE
                            WHEN %s IN ('Verified', 'Failed', 'Rolled back') THEN NOW()
                            ELSE completed_at
                        END,
                        updated_at = NOW(), version = version + 1
                    WHERE client_id = %s AND id = %s;
                    """,
                    (
                        target_status,
                        Json(payload["dispatch_result"]) if "dispatch_result" in payload else None,
                        payload.get("sanitized_log"),
                        payload.get("exit_code"),
                        payload.get("restart_required"),
                        payload.get("verification_not_before"),
                        payload.get("verification_batch_id"),
                        payload.get("verification_reference"),
                        payload.get("failure_reason"),
                        payload.get("rollback_reference"),
                        target_status,
                        client_id,
                        int(execution_id),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_remediation_execution_events (
                        client_id, execution_id, from_status, to_status,
                        actor, reason, event_payload
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_id,
                        int(execution_id),
                        previous_status,
                        target_status,
                        actor.strip(),
                        reason.strip(),
                        Json(event_payload),
                    ),
                )
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc


def claim_due_verification() -> dict[str, Any] | None:
    """Claim one dispatched execution whose verification window is due.

    Returns:
        Workspace-scoped execution row, or ``None`` when none is due.

    Raises:
        ExposureRepositoryError: If PostgreSQL cannot claim a row.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT execution.*, client.name AS client_name
                    FROM securescope_remediation_executions execution
                    JOIN securescope_clients client ON client.id = execution.client_id
                    WHERE execution.status = 'Running'
                      AND execution.verification_batch_id IS NULL
                      AND execution.verification_not_before IS NOT NULL
                      AND execution.verification_not_before <= NOW()
                      AND COALESCE(
                          (execution.dispatch_result ->> 'accepted')::boolean,
                          FALSE
                      )
                    ORDER BY execution.verification_not_before, execution.id
                    FOR UPDATE OF execution SKIP LOCKED
                    LIMIT 1;
                    """
                )
                row = cursor.fetchone()
                if not row:
                    return None
                cursor.execute(
                    """
                    UPDATE securescope_remediation_executions
                    SET verification_not_before = NOW() + INTERVAL '10 minutes',
                        updated_at = NOW(), version = version + 1
                    WHERE client_id = %s AND id = %s AND status = 'Running';
                    """,
                    (int(row["client_id"]), int(row["id"])),
                )
                return dict(row) if cursor.rowcount == 1 else None
    except DatabaseError as exc:
        raise ExposureRepositoryError(str(exc)) from exc
