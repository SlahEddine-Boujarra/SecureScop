"""PostgreSQL repository for the SecureScope GRC workspace foundation."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import date
from typing import Any, Mapping, Sequence

from psycopg2.extras import Json, RealDictCursor

from securescope.grc.engagement_models import (
    ENGAGEMENT_ROLES,
    ClimateDeterminationDraft,
    ContextIssueDraft,
    EngagementDraft,
    InterestedPartyDraft,
    MilestoneDraft,
    OrganizationalUnitDraft,
    PartyRequirementDraft,
    RaciAssignmentDraft,
    ScopeDraft,
    choice,
    required_text,
)
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)
DEFAULT_ORGANIZATION_NAME = "Default Consulting Organization"
APPROVER_WORKSPACE_ROLES = frozenset({"Administrator", "Consultant"})


class GrcWorkspaceRepositoryError(RuntimeError):
    """Raised when engagement, context or scope persistence fails."""


def _row_id(row: Mapping[str, Any] | Sequence[Any] | None) -> int:
    """Extract a positive database identifier from one cursor row.

    Args:
        row: Mapping or tuple returned by PostgreSQL.

    Returns:
        Positive integer identifier.

    Raises:
        GrcWorkspaceRepositoryError: If PostgreSQL returned no row.
    """

    if not row:
        raise GrcWorkspaceRepositoryError("PostgreSQL did not return an ID.")
    value = row["id"] if isinstance(row, Mapping) else row[0]
    return int(value)


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve one existing client workspace inside the current transaction.

    Args:
        cursor: Active PostgreSQL cursor.
        client_name: Exact client workspace name.

    Returns:
        Positive client identifier.

    Raises:
        GrcWorkspaceRepositoryError: If the client does not exist.
    """

    name = str(client_name or "").strip()
    if not name:
        raise GrcWorkspaceRepositoryError("Client workspace name is required.")
    cursor.execute(
        "SELECT id FROM securescope_clients WHERE name = %s;",
        (name,),
    )
    row = cursor.fetchone()
    if not row:
        raise GrcWorkspaceRepositoryError(f"Client workspace not found: {name}")
    return _row_id(row)


def _engagement(
    cursor: Any,
    client_id: int,
    engagement_id: int,
    *,
    for_update: bool = False,
) -> dict[str, Any]:
    """Resolve a tenant-owned engagement.

    Args:
        cursor: Active PostgreSQL cursor.
        client_id: Authorized client identifier.
        engagement_id: Candidate engagement identifier.
        for_update: Whether to acquire a row lock.

    Returns:
        Engagement row as a dictionary.

    Raises:
        GrcWorkspaceRepositoryError: If the engagement is outside the client.
    """

    lock_clause = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT *
        FROM securescope_engagements
        WHERE client_id = %s AND id = %s
        """ + lock_clause + ";",
        (client_id, int(engagement_id)),
    )
    row = cursor.fetchone()
    if not row:
        raise GrcWorkspaceRepositoryError(
            "Engagement does not belong to the active client workspace."
        )
    return dict(row)


def _scope(
    cursor: Any,
    client_id: int,
    engagement_id: int,
    scope_id: int,
    *,
    for_update: bool = False,
) -> dict[str, Any]:
    """Resolve a scope definition owned by the selected engagement.

    Args:
        cursor: Active PostgreSQL cursor.
        client_id: Authorized client identifier.
        engagement_id: Authorized engagement identifier.
        scope_id: Candidate scope identifier.
        for_update: Whether to acquire a row lock.

    Returns:
        Scope-definition row.

    Raises:
        GrcWorkspaceRepositoryError: If the scope is outside the context.
    """

    lock_clause = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT *
        FROM securescope_scope_definitions
        WHERE client_id = %s AND engagement_id = %s AND id = %s
        """ + lock_clause + ";",
        (client_id, int(engagement_id), int(scope_id)),
    )
    row = cursor.fetchone()
    if not row:
        raise GrcWorkspaceRepositoryError("ISMS scope does not belong to the selected engagement.")
    return dict(row)


def _workspace_member(
    cursor: Any,
    client_id: int,
    *,
    user_id: int | None = None,
    email: str | None = None,
) -> dict[str, Any]:
    """Resolve one active, database-backed workspace member.

    Args:
        cursor: Active PostgreSQL cursor.
        client_id: Authorized client identifier.
        user_id: Optional user identifier.
        email: Optional normalized user email.

    Returns:
        User and workspace-role fields.

    Raises:
        GrcWorkspaceRepositoryError: If identity is missing or unauthorized.
    """

    if user_id is None and not str(email or "").strip():
        raise GrcWorkspaceRepositoryError("A member ID or email is required.")
    conditions = ["membership.client_id = %s", "membership.active"]
    parameters: list[Any] = [client_id]
    if user_id is not None:
        conditions.append("membership.user_id = %s")
        parameters.append(int(user_id))
    else:
        conditions.append("user_account.email = %s")
        parameters.append(str(email or "").strip().lower())
    cursor.execute(
        f"""
        SELECT
            user_account.id AS user_id,
            user_account.email,
            user_account.display_name,
            membership.role AS workspace_role
        FROM securescope_workspace_memberships AS membership
        JOIN securescope_users AS user_account
          ON user_account.id = membership.user_id
        WHERE {' AND '.join(conditions)}
        LIMIT 1;
        """,
        tuple(parameters),
    )
    row = cursor.fetchone()
    if not row:
        raise GrcWorkspaceRepositoryError(
            "The selected person is not an active member of this client workspace."
        )
    return dict(row)


def _append_audit_event(
    cursor: Any,
    client_id: int,
    engagement_id: int | None,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor: str,
    summary: str,
    payload: Mapping[str, Any] | None = None,
) -> None:
    """Append one immutable hash-chained GRC audit event.

    Args:
        cursor: Active PostgreSQL cursor.
        client_id: Authorized client identifier.
        engagement_id: Optional engagement context.
        event_type: Stable event vocabulary.
        entity_type: Stable entity vocabulary.
        entity_id: Entity identifier serialized as text.
        actor: Human or service principal responsible for the event.
        summary: Human-readable event summary.
        payload: Optional JSON-safe event details.

    Returns:
        None.

    Raises:
        GrcWorkspaceRepositoryError: If required audit fields are empty.
    """

    required = (event_type, entity_type, entity_id, actor, summary)
    if not all(str(value or "").strip() for value in required):
        raise GrcWorkspaceRepositoryError(
            "GRC audit events require type, entity, actor and summary."
        )
    # Serialize the per-client chain even when this is its first event and no
    # existing row is available for ``FOR UPDATE`` to lock.
    cursor.execute(
        "SELECT pg_advisory_xact_lock(%s);",
        (741090050000000000 + int(client_id),),
    )
    cursor.execute(
        """
        SELECT event_hash
        FROM securescope_grc_audit_events
        WHERE client_id = %s
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE;
        """,
        (client_id,),
    )
    previous_row = cursor.fetchone()
    previous_hash = (
        str(previous_row["event_hash"])
        if isinstance(previous_row, Mapping)
        else str(previous_row[0]) if previous_row else ""
    )
    event_payload = json.loads(json.dumps(dict(payload or {}), default=str, sort_keys=True))
    canonical = json.dumps(
        {
            "previous": previous_hash,
            "client_id": client_id,
            "engagement_id": engagement_id,
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
        INSERT INTO securescope_grc_audit_events (
            client_id,
            engagement_id,
            event_uuid,
            event_type,
            entity_type,
            entity_id,
            actor,
            summary,
            event_payload,
            previous_event_hash,
            event_hash
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (
            client_id,
            engagement_id,
            str(uuid.uuid4()),
            event_type,
            entity_type,
            entity_id,
            actor.strip(),
            summary.strip(),
            Json(event_payload),
            previous_hash or None,
            event_hash,
        ),
    )


def ensure_workspace_foundation(
    client_name: str,
    *,
    actor: str = "securescope-bootstrap",
) -> dict[str, Any]:
    """Ensure a client has a consulting organization, engagement and draft scope.

    Args:
        client_name: Exact existing client workspace name.
        actor: Human or service principal recorded in new rows.

    Returns:
        IDs and labels for the default engagement and scope.

    Raises:
        GrcWorkspaceRepositoryError: If PostgreSQL cannot build the foundation.
    """

    run_pending_migrations()
    principal = str(actor or "securescope-bootstrap").strip()
    created_entities: list[str] = []
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT organization_id
                    FROM securescope_client_consulting_organizations
                    WHERE client_id = %s
                      AND is_primary
                      AND relationship_status = 'Active'
                    LIMIT 1;
                    """,
                    (client_id,),
                )
                relationship = cursor.fetchone()
                if relationship:
                    organization_id = int(relationship["organization_id"])
                else:
                    cursor.execute(
                        """
                        INSERT INTO securescope_consulting_organizations (
                            organization_uuid,
                            name,
                            legal_name,
                            status,
                            created_by
                        )
                        VALUES (%s, %s, '', 'Active', %s)
                        ON CONFLICT (name) DO UPDATE
                            SET updated_at = securescope_consulting_organizations.updated_at
                        RETURNING id;
                        """,
                        (
                            str(
                                uuid.uuid5(
                                    uuid.NAMESPACE_URL,
                                    "securescope:default-consulting-organization",
                                )
                            ),
                            DEFAULT_ORGANIZATION_NAME,
                            principal,
                        ),
                    )
                    organization_id = _row_id(cursor.fetchone())
                    cursor.execute(
                        """
                        INSERT INTO securescope_client_consulting_organizations (
                            client_id,
                            organization_id,
                            relationship_status,
                            is_primary,
                            started_on,
                            created_by
                        )
                        VALUES (%s, %s, 'Active', TRUE, CURRENT_DATE, %s)
                        ON CONFLICT (client_id, organization_id) DO UPDATE
                            SET relationship_status = 'Active',
                                is_primary = TRUE,
                                updated_at = NOW();
                        """,
                        (client_id, organization_id, principal),
                    )
                    created_entities.append("consulting relationship")

                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_engagements
                    WHERE client_id = %s
                      AND is_default
                      AND status NOT IN ('Completed', 'Cancelled')
                    ORDER BY id
                    LIMIT 1;
                    """,
                    (client_id,),
                )
                engagement_row = cursor.fetchone()
                if not engagement_row:
                    reference = f"LEGACY-ISO-{client_id}"
                    cursor.execute(
                        """
                        INSERT INTO securescope_engagements (
                            client_id,
                            consulting_organization_id,
                            engagement_uuid,
                            reference,
                            name,
                            engagement_type,
                            objective,
                            target_standard,
                            cycle_year,
                            status,
                            planned_start_date,
                            is_default,
                            created_by,
                            updated_by
                        )
                        VALUES (
                            %s, %s, %s, %s, %s,
                            'ISO 27001 implementation', %s,
                            'ISO/IEC 27001:2022', %s, 'Active',
                            CURRENT_DATE, TRUE, %s, %s
                        )
                        RETURNING *;
                        """,
                        (
                            client_id,
                            organization_id,
                            str(uuid.uuid4()),
                            reference,
                            "Existing ISO 27001 Programme",
                            ("Continue the existing SecureScope ISO/IEC 27001 " "programme."),
                            date.today().year,
                            principal,
                            principal,
                        ),
                    )
                    engagement_row = cursor.fetchone()
                    created_entities.append("engagement")
                engagement_id = int(engagement_row["id"])

                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_scope_definitions
                    WHERE client_id = %s AND engagement_id = %s
                    ORDER BY id
                    LIMIT 1;
                    """,
                    (client_id, engagement_id),
                )
                scope_row = cursor.fetchone()
                if not scope_row:
                    cursor.execute(
                        """
                        INSERT INTO securescope_scope_definitions (
                            client_id,
                            engagement_id,
                            scope_uuid,
                            scope_code,
                            name,
                            created_by
                        )
                        VALUES (%s, %s, %s, 'DEFAULT-SCOPE', %s, %s)
                        RETURNING *;
                        """,
                        (
                            client_id,
                            engagement_id,
                            str(uuid.uuid4()),
                            "Existing ISMS Scope",
                            principal,
                        ),
                    )
                    scope_row = cursor.fetchone()
                    created_entities.append("scope")
                scope_id = int(scope_row["id"])

                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_scope_versions
                    WHERE client_id = %s AND scope_id = %s
                    ORDER BY version_number DESC
                    LIMIT 1;
                    """,
                    (client_id, scope_id),
                )
                version_row = cursor.fetchone()
                if not version_row:
                    cursor.execute(
                        """
                        INSERT INTO securescope_scope_versions (
                            client_id,
                            engagement_id,
                            scope_id,
                            version_number,
                            status,
                            scope_statement,
                            prepared_by
                        )
                        VALUES (%s, %s, %s, 1, 'Draft', %s, %s)
                        RETURNING *;
                        """,
                        (
                            client_id,
                            engagement_id,
                            scope_id,
                            (
                                "Define and approve the ISMS scope for this "
                                "existing client workspace."
                            ),
                            principal,
                        ),
                    )
                    version_row = cursor.fetchone()
                    created_entities.append("scope version")
                if created_entities:
                    _append_audit_event(
                        cursor,
                        client_id,
                        engagement_id,
                        event_type="grc.foundation.created",
                        entity_type="engagement",
                        entity_id=str(engagement_id),
                        actor=principal,
                        summary="Created the default GRC workspace foundation.",
                        payload={"created_entities": created_entities},
                    )
                return {
                    "client_id": client_id,
                    "consulting_organization_id": organization_id,
                    "engagement_id": engagement_id,
                    "engagement_name": str(engagement_row["name"]),
                    "scope_id": scope_id,
                    "scope_name": str(scope_row["name"]),
                    "scope_version_id": int(version_row["id"]),
                    "scope_version": int(version_row["version_number"]),
                    "scope_status": str(version_row["status"]),
                }
    except DatabaseError as exc:
        LOGGER.error("GRC foundation failed for %s: %s", client_name, exc)
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_engagements(client_name: str) -> list[dict[str, Any]]:
    """List engagement cards strictly inside one client workspace.

    Args:
        client_name: Exact client workspace name.

    Returns:
        Engagement rows with scope, milestone and readiness counts.

    Raises:
        GrcWorkspaceRepositoryError: If PostgreSQL cannot load the rows.
    """

    ensure_workspace_foundation(client_name)
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        engagement.*,
                        organization.name AS consulting_organization,
                        (
                            SELECT COUNT(*)
                            FROM securescope_scope_definitions AS scope
                            WHERE scope.client_id = engagement.client_id
                              AND scope.engagement_id = engagement.id
                              AND NOT scope.archived
                        )::integer AS scope_count,
                        (
                            SELECT COUNT(*)
                            FROM securescope_engagement_milestones AS milestone
                            WHERE milestone.client_id = engagement.client_id
                              AND milestone.engagement_id = engagement.id
                              AND milestone.status NOT IN ('Completed', 'Cancelled')
                        )::integer AS open_milestones,
                        (
                            SELECT COUNT(*)
                            FROM securescope_context_issues AS issue
                            WHERE issue.client_id = engagement.client_id
                              AND issue.engagement_id = engagement.id
                              AND issue.status <> 'Closed'
                        )::integer AS open_context_issues
                    FROM securescope_engagements AS engagement
                    JOIN securescope_consulting_organizations AS organization
                      ON organization.id = engagement.consulting_organization_id
                    WHERE engagement.client_id = %s
                    ORDER BY
                        CASE engagement.status
                            WHEN 'Active' THEN 0
                            WHEN 'Planned' THEN 1
                            WHEN 'Draft' THEN 2
                            ELSE 3
                        END,
                        engagement.planned_start_date DESC NULLS LAST,
                        engagement.id DESC;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_engagement(
    client_name: str,
    draft: EngagementDraft,
    *,
    actor: str,
) -> dict[str, int]:
    """Create an engagement and its first draft scope atomically.

    Args:
        client_name: Exact client workspace name.
        draft: Validated engagement input.
        actor: Human or service principal creating the engagement.

    Returns:
        New engagement, scope and scope-version identifiers.

    Raises:
        GrcWorkspaceRepositoryError: If the reference conflicts or persistence fails.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = str(actor or "").strip()
    if not principal:
        raise GrcWorkspaceRepositoryError("Engagement creator is required.")
    foundation = ensure_workspace_foundation(client_name, actor=principal)
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                organization_id = int(foundation["consulting_organization_id"])
                cursor.execute(
                    """
                    INSERT INTO securescope_engagements (
                        client_id,
                        consulting_organization_id,
                        engagement_uuid,
                        reference,
                        name,
                        engagement_type,
                        objective,
                        target_standard,
                        cycle_year,
                        status,
                        planned_start_date,
                        planned_end_date,
                        certification_target_date,
                        client_sponsor,
                        is_default,
                        created_by,
                        updated_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, FALSE, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        organization_id,
                        str(uuid.uuid4()),
                        validated.reference,
                        validated.name,
                        validated.engagement_type,
                        validated.objective,
                        validated.target_standard,
                        validated.cycle_year,
                        validated.status,
                        validated.planned_start_date,
                        validated.planned_end_date,
                        validated.certification_target_date,
                        validated.client_sponsor,
                        principal,
                        principal,
                    ),
                )
                engagement_id = _row_id(cursor.fetchone())
                scope_code = f"{validated.reference}-SCOPE"[:80].rstrip("-./")
                cursor.execute(
                    """
                    INSERT INTO securescope_scope_definitions (
                        client_id,
                        engagement_id,
                        scope_uuid,
                        scope_code,
                        name,
                        created_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        engagement_id,
                        str(uuid.uuid4()),
                        scope_code,
                        f"{validated.name} ISMS Scope",
                        principal,
                    ),
                )
                scope_id = _row_id(cursor.fetchone())
                cursor.execute(
                    """
                    INSERT INTO securescope_scope_versions (
                        client_id,
                        engagement_id,
                        scope_id,
                        version_number,
                        status,
                        scope_statement,
                        prepared_by
                    )
                    VALUES (%s, %s, %s, 1, 'Draft', %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        engagement_id,
                        scope_id,
                        "Define and approve the ISMS scope for this engagement.",
                        principal,
                    ),
                )
                version_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    engagement_id,
                    event_type="engagement.created",
                    entity_type="engagement",
                    entity_id=str(engagement_id),
                    actor=principal,
                    summary=f"Created engagement {validated.reference}.",
                    payload={
                        "name": validated.name,
                        "type": validated.engagement_type,
                        "scope_id": scope_id,
                    },
                )
                return {
                    "engagement_id": engagement_id,
                    "scope_id": scope_id,
                    "scope_version_id": version_id,
                }
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_scopes(client_name: str, engagement_id: int) -> list[dict[str, Any]]:
    """List scope definitions and latest immutable versions for an engagement.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Scope rows with latest and current-approved version metadata.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                cursor.execute(
                    """
                    SELECT
                        scope.*,
                        latest.id AS latest_version_id,
                        latest.version_number AS latest_version_number,
                        latest.status AS latest_status,
                        latest.scope_statement,
                        latest.boundaries,
                        latest.exclusions,
                        latest.interfaces_and_dependencies,
                        latest.locations,
                        latest.organizational_units,
                        latest.products_and_services,
                        latest.technologies,
                        latest.assumptions,
                        latest.prepared_by,
                        latest.reviewed_by,
                        latest.reviewed_at,
                        latest.review_rationale,
                        latest.approved_by,
                        latest.approved_at,
                        latest.effective_from,
                        latest.effective_to,
                        approved.version_number AS approved_version_number
                    FROM securescope_scope_definitions AS scope
                    LEFT JOIN LATERAL (
                        SELECT *
                        FROM securescope_scope_versions AS version
                        WHERE version.client_id = scope.client_id
                          AND version.scope_id = scope.id
                        ORDER BY version.version_number DESC
                        LIMIT 1
                    ) AS latest ON TRUE
                    LEFT JOIN securescope_scope_versions AS approved
                      ON approved.client_id = scope.client_id
                     AND approved.id = scope.current_approved_version_id
                    WHERE scope.client_id = %s
                      AND scope.engagement_id = %s
                      AND NOT scope.archived
                    ORDER BY lower(scope.name), scope.id;
                    """,
                    (client_id, int(engagement_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_scope_version(
    client_name: str,
    engagement_id: int,
    draft: ScopeDraft,
    *,
    actor: str,
    scope_id: int | None = None,
) -> dict[str, int]:
    """Create a new draft version without changing prior approved versions.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated scope content.
        actor: Person preparing the version.
        scope_id: Existing scope definition, or ``None`` for a new definition.

    Returns:
        Scope ID, version ID and monotonically increasing version number.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = str(actor or "").strip()
    if not principal:
        raise GrcWorkspaceRepositoryError("Scope preparer is required.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                if scope_id is None:
                    cursor.execute(
                        """
                        INSERT INTO securescope_scope_definitions (
                            client_id,
                            engagement_id,
                            scope_uuid,
                            scope_code,
                            name,
                            created_by
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (
                            client_id,
                            int(engagement_id),
                            str(uuid.uuid4()),
                            validated.scope_code,
                            validated.name,
                            principal,
                        ),
                    )
                    resolved_scope_id = _row_id(cursor.fetchone())
                    version_number = 1
                else:
                    resolved_scope_id = int(scope_id)
                    scope_row = _scope(
                        cursor,
                        client_id,
                        engagement_id,
                        resolved_scope_id,
                        for_update=True,
                    )
                    if str(scope_row["scope_code"]) != validated.scope_code:
                        raise GrcWorkspaceRepositoryError(
                            "The stable scope code cannot change between versions."
                        )
                    from dataclasses import asdict

                    from securescope.grc.scope_workflow import scope_content_matches

                    cursor.execute(
                        "SELECT * FROM securescope_scope_versions WHERE client_id=%s AND s"
                        "cope_id=%s ORDER BY version_number DESC LIMIT 1 FOR UPDATE",
                        (client_id, resolved_scope_id),
                    )
                    latest = cursor.fetchone()
                    if latest and scope_content_matches(
                        dict(latest, name=scope_row.get("name")), asdict(validated)
                    ):
                        return {
                            "scope_id": resolved_scope_id,
                            "scope_version_id": latest["id"],
                            "version_number": latest["version_number"],
                            "unchanged": True,
                        }
                    cursor.execute(
                        """
                        UPDATE securescope_scope_definitions
                        SET name = %s, updated_at = NOW()
                        WHERE client_id = %s AND id = %s;
                        """,
                        (validated.name, client_id, resolved_scope_id),
                    )
                    cursor.execute(
                        """
                        SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
                        FROM securescope_scope_versions
                        WHERE client_id = %s AND scope_id = %s;
                        """,
                        (client_id, resolved_scope_id),
                    )
                    version_number = int(cursor.fetchone()["next_version"])
                cursor.execute(
                    """
                    INSERT INTO securescope_scope_versions (
                        client_id,
                        engagement_id,
                        scope_id,
                        version_number,
                        status,
                        scope_statement,
                        boundaries,
                        exclusions,
                        interfaces_and_dependencies,
                        locations,
                        organizational_units,
                        products_and_services,
                        technologies,
                        assumptions,
                        prepared_by,
                        effective_from,
                        effective_to
                    )
                    VALUES (
                        %s, %s, %s, %s, 'Draft', %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        resolved_scope_id,
                        version_number,
                        validated.scope_statement,
                        validated.boundaries,
                        validated.exclusions,
                        validated.interfaces_and_dependencies,
                        Json(list(validated.locations)),
                        Json(list(validated.organizational_units)),
                        Json(list(validated.products_and_services)),
                        Json(list(validated.technologies)),
                        Json(list(validated.assumptions)),
                        principal,
                        validated.effective_from,
                        validated.effective_to,
                    ),
                )
                version_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="scope.version_created",
                    entity_type="scope_version",
                    entity_id=str(version_id),
                    actor=principal,
                    summary=(f"Created scope {validated.scope_code} version " f"{version_number}."),
                    payload={
                        "scope_id": resolved_scope_id,
                        "version_number": version_number,
                        "status": "Draft",
                    },
                )
                return {
                    "scope_id": resolved_scope_id,
                    "scope_version_id": version_id,
                    "version_number": version_number,
                }
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def approve_scope_version(
    client_name: str,
    engagement_id: int,
    scope_id: int,
    version_id: int,
    *,
    approver_email: str,
    comment: str,
) -> dict[str, Any]:
    """Approve one draft scope and preserve it as an immutable version.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Selected scope definition.
        version_id: Draft scope-version identifier.
        approver_email: Active Administrator or Consultant membership email.
        comment: Approval rationale retained in the immutable decision record.

    Returns:
        Approved version metadata.

    Raises:
        GrcWorkspaceRepositoryError: If authorization, state or ownership fails.
    """

    rationale = str(comment or "").strip()
    if not rationale:
        raise GrcWorkspaceRepositoryError("Scope approval comment is required.")
    normalized_email = str(approver_email or "").strip().lower()
    if not normalized_email:
        raise GrcWorkspaceRepositoryError("Approver email is required.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                _scope(
                    cursor,
                    client_id,
                    engagement_id,
                    scope_id,
                    for_update=True,
                )
                approver = _workspace_member(
                    cursor,
                    client_id,
                    email=normalized_email,
                )
                if approver["workspace_role"] not in APPROVER_WORKSPACE_ROLES:
                    raise GrcWorkspaceRepositoryError(
                        "Only an Administrator or Consultant may approve an ISMS scope."
                    )
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_scope_versions
                    WHERE client_id = %s
                      AND engagement_id = %s
                      AND scope_id = %s
                      ORDER BY version_number DESC
                    LIMIT 1 FOR UPDATE;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        int(scope_id),
                    ),
                )
                version = cursor.fetchone()
                if not version or int(version["id"]) != int(version_id):
                    raise GrcWorkspaceRepositoryError(
                        "Scope changed. Reload the latest version before approval."
                    )
                if version["status"] == "Approved":
                    return dict(version)
                if (
                    version["status"] != "Reviewed"
                    or not version.get("reviewed_at")
                    or not version.get("review_rationale")
                ):
                    raise GrcWorkspaceRepositoryError(
                        f"A {version['status']} scope version cannot be approved."
                    )
                cursor.execute(
                    """
                    UPDATE securescope_scope_versions
                    SET status = 'Approved',
                        approved_by = %s,
                        approved_at = NOW(),
                        approval_comment = %s
                    WHERE client_id = %s AND id = %s
                    RETURNING *;
                    """,
                    (
                        normalized_email,
                        rationale,
                        client_id,
                        int(version_id),
                    ),
                )
                approved = dict(cursor.fetchone())
                cursor.execute(
                    """
                    UPDATE securescope_scope_definitions
                    SET current_approved_version_id = %s, updated_at = NOW()
                    WHERE client_id = %s
                      AND engagement_id = %s
                      AND id = %s;
                    """,
                    (
                        int(version_id),
                        client_id,
                        int(engagement_id),
                        int(scope_id),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_grc_approvals (
                        client_id,
                        engagement_id,
                        scope_id,
                        subject_type,
                        subject_id,
                        subject_version,
                        decision,
                        decision_by_user_id,
                        comment
                    )
                    VALUES (
                        %s, %s, %s, 'scope_version', %s, %s,
                        'Approved', %s, %s
                    );
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        int(scope_id),
                        int(version_id),
                        int(approved["version_number"]),
                        int(approver["user_id"]),
                        rationale,
                    ),
                )
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="scope.version_approved",
                    entity_type="scope_version",
                    entity_id=str(version_id),
                    actor=normalized_email,
                    summary=(f"Approved scope version {approved['version_number']}."),
                    payload={
                        "scope_id": int(scope_id),
                        "version_number": int(approved["version_number"]),
                    },
                )
                return approved
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def workspace_overview(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
) -> dict[str, Any]:
    """Aggregate the selected client, engagement and scope context.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope definition.

    Returns:
        Engagement metadata and conservative record counts.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                engagement = _engagement(cursor, client_id, engagement_id)
                scope_row = (
                    _scope(cursor, client_id, engagement_id, scope_id)
                    if scope_id is not None
                    else None
                )
                cursor.execute(
                    """
                    SELECT
                        (
                            SELECT COUNT(*) FROM securescope_organizational_units
                            WHERE client_id = %s AND engagement_id = %s
                              AND in_scope AND status = 'Active'
                        )::integer AS organizational_units,
                        (
                            SELECT COUNT(*) FROM securescope_context_issues
                            WHERE client_id = %s AND engagement_id = %s
                              AND status <> 'Closed'
                        )::integer AS context_issues,
                        (
                            SELECT COUNT(*) FROM securescope_interested_parties
                            WHERE client_id = %s AND engagement_id = %s
                              AND status = 'Active'
                        )::integer AS interested_parties,
                        (
                            SELECT COUNT(*)
                            FROM securescope_interested_party_requirements
                            WHERE client_id = %s AND engagement_id = %s
                              AND applicability = 'Applicable'
                        )::integer AS applicable_requirements,
                        (
                            SELECT COUNT(*) FROM securescope_isms_role_assignments
                            WHERE client_id = %s AND engagement_id = %s
                              AND status = 'Active'
                        )::integer AS role_assignments,
                        (
                            SELECT COUNT(*) FROM securescope_engagement_milestones
                            WHERE client_id = %s AND engagement_id = %s
                              AND status NOT IN ('Completed', 'Cancelled')
                        )::integer AS open_milestones;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        client_id,
                        int(engagement_id),
                        client_id,
                        int(engagement_id),
                        client_id,
                        int(engagement_id),
                        client_id,
                        int(engagement_id),
                        client_id,
                        int(engagement_id),
                    ),
                )
                summary = dict(cursor.fetchone())
                summary["engagement"] = engagement
                summary["scope"] = scope_row
                if scope_row and scope_row.get("current_approved_version_id"):
                    cursor.execute(
                        """
                        SELECT *
                        FROM securescope_scope_versions
                        WHERE client_id = %s AND id = %s;
                        """,
                        (client_id, int(scope_row["current_approved_version_id"])),
                    )
                    summary["approved_scope_version"] = dict(cursor.fetchone())
                else:
                    summary["approved_scope_version"] = None
                return summary
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_context_issues(
    client_name: str,
    engagement_id: int,
    scope_id: int | None = None,
) -> list[dict[str, Any]]:
    """List context issues visible in the selected engagement and scope.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope; engagement-wide issues remain visible.

    Returns:
        Context issues ordered by lifecycle and review date.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_context_issues
                    WHERE client_id = %s
                      AND engagement_id = %s
                      AND (%s IS NULL OR scope_id IS NULL OR scope_id = %s)
                    ORDER BY
                        CASE status WHEN 'Open' THEN 0 WHEN 'Monitoring' THEN 1 ELSE 2 END,
                        review_date NULLS LAST,
                        id DESC;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        scope_id,
                    ),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_context_issue(
    client_name: str,
    engagement_id: int,
    draft: ContextIssueDraft,
    *,
    actor: str,
    scope_id: int | None = None,
    reuse_existing: bool = False,
) -> int:
    """Create one internal or external issue in a tenant-owned engagement.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated context issue.
        actor: Person recording the issue.
        scope_id: Optional related scope definition.
        reuse_existing: Reuse matching reviewed Discovery suggestions without overwriting them.

    Returns:
        New context issue identifier.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Issue creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                if reuse_existing:
                    cursor.execute(
                        "SELECT id FROM securescope_context_issues "
                        "WHERE client_id=%s AND engagement_id=%s "
                        "AND scope_id IS NOT DISTINCT FROM %s "
                        "AND lower(btrim(title))=lower(btrim(%s)) "
                        "ORDER BY id LIMIT 1",
                        (client_id, int(engagement_id), scope_id, validated.title),
                    )
                    existing = cursor.fetchone()
                    if existing:
                        return _row_id(existing)
                cursor.execute(
                    """
                    INSERT INTO securescope_context_issues (
                        client_id,
                        engagement_id,
                        scope_id,
                        issue_uuid,
                        issue_type,
                        category,
                        title,
                        description,
                        effect_on_isms,
                        relevance,
                        owner,
                        review_date,
                        status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, 'Open', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        str(uuid.uuid4()),
                        validated.issue_type,
                        validated.category,
                        validated.title,
                        validated.description,
                        validated.effect_on_isms,
                        validated.relevance,
                        validated.owner,
                        validated.review_date,
                        principal,
                    ),
                )
                issue_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="context.issue_created",
                    entity_type="context_issue",
                    entity_id=str(issue_id),
                    actor=principal,
                    summary=f"Created {validated.issue_type.lower()} context issue.",
                    payload={
                        "scope_id": scope_id,
                        "title": validated.title,
                        "relevance": validated.relevance,
                    },
                )
                return issue_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_climate_determinations(
    client_name: str,
    engagement_id: int,
) -> list[dict[str, Any]]:
    """List versioned climate relevance determinations for an engagement.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Determinations newest first.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_climate_determinations
                    WHERE client_id = %s AND engagement_id = %s
                    ORDER BY version_number DESC;
                    """,
                    (client_id, int(engagement_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_climate_determination(
    client_name: str,
    engagement_id: int,
    draft: ClimateDeterminationDraft,
    *,
    actor: str,
    scope_id: int | None = None,
) -> dict[str, int]:
    """Append a new climate relevance determination version.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated climate determination.
        actor: Person recording the determination.
        scope_id: Optional related scope definition.

    Returns:
        New determination ID and version number.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Climate determination creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
                    FROM securescope_climate_determinations
                    WHERE client_id = %s AND engagement_id = %s;
                    """,
                    (client_id, int(engagement_id)),
                )
                version_number = int(cursor.fetchone()["next_version"])
                cursor.execute(
                    """
                    INSERT INTO securescope_climate_determinations (
                        client_id,
                        engagement_id,
                        scope_id,
                        version_number,
                        determination,
                        rationale,
                        identified_impacts,
                        determined_by,
                        determination_date,
                        next_review_date
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        version_number,
                        validated.determination,
                        validated.rationale,
                        validated.identified_impacts,
                        validated.determined_by,
                        validated.determination_date,
                        validated.next_review_date,
                    ),
                )
                determination_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="context.climate_determination_created",
                    entity_type="climate_determination",
                    entity_id=str(determination_id),
                    actor=principal,
                    summary=(f"Recorded climate determination version {version_number}."),
                    payload={
                        "scope_id": scope_id,
                        "determination": validated.determination,
                    },
                )
                return {
                    "determination_id": determination_id,
                    "version_number": version_number,
                }
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_interested_parties(
    client_name: str,
    engagement_id: int,
    scope_id: int | None = None,
) -> list[dict[str, Any]]:
    """List interested parties and requirement counts in the active context.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope; engagement-wide parties remain visible.

    Returns:
        Interested-party rows with applicable and total requirement counts.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT
                        party.*,
                        (
                            SELECT COUNT(*)
                            FROM securescope_interested_party_requirements AS requirement
                            WHERE requirement.client_id = party.client_id
                              AND requirement.party_id = party.id
                        )::integer AS requirement_count,
                        (
                            SELECT COUNT(*)
                            FROM securescope_interested_party_requirements AS requirement
                            WHERE requirement.client_id = party.client_id
                              AND requirement.party_id = party.id
                              AND requirement.applicability = 'Applicable'
                        )::integer AS applicable_requirement_count
                    FROM securescope_interested_parties AS party
                    WHERE party.client_id = %s
                      AND party.engagement_id = %s
                      AND (%s IS NULL OR party.scope_id IS NULL OR party.scope_id = %s)
                    ORDER BY
                        CASE party.status WHEN 'Active' THEN 0 ELSE 1 END,
                        lower(party.name);
                    """,
                    (client_id, int(engagement_id), scope_id, scope_id),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_party_requirements(
    client_name: str,
    engagement_id: int,
    party_id: int,
) -> list[dict[str, Any]]:
    """List requirements belonging to one interested party.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        party_id: Interested-party identifier.

    Returns:
        Requirements ordered by applicability and review date.

    Raises:
        GrcWorkspaceRepositoryError: If party ownership or persistence fails.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                cursor.execute(
                    """
                    SELECT id
                    FROM securescope_interested_parties
                    WHERE client_id = %s AND engagement_id = %s AND id = %s;
                    """,
                    (client_id, int(engagement_id), int(party_id)),
                )
                if not cursor.fetchone():
                    raise GrcWorkspaceRepositoryError(
                        "Interested party does not belong to the selected engagement."
                    )
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_interested_party_requirements
                    WHERE client_id = %s
                      AND engagement_id = %s
                      AND party_id = %s
                    ORDER BY
                        CASE applicability
                            WHEN 'Applicable' THEN 0
                            WHEN 'Under review' THEN 1
                            ELSE 2
                        END,
                        review_date NULLS LAST,
                        id DESC;
                    """,
                    (client_id, int(engagement_id), int(party_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_interested_party(
    client_name: str,
    engagement_id: int,
    draft: InterestedPartyDraft,
    *,
    actor: str,
    scope_id: int | None = None,
    reuse_existing: bool = False,
) -> int:
    """Create an interested-party register entry.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated interested-party input.
        actor: Person recording the party.
        scope_id: Optional related scope definition.
        reuse_existing: Reuse matching reviewed Discovery suggestions without overwriting them.

    Returns:
        New interested-party identifier.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Interested party creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                if reuse_existing:
                    cursor.execute(
                        "SELECT id FROM securescope_interested_parties "
                        "WHERE client_id=%s AND engagement_id=%s "
                        "AND scope_id IS NOT DISTINCT FROM %s "
                        "AND lower(btrim(name))=lower(btrim(%s)) "
                        "ORDER BY id LIMIT 1",
                        (client_id, int(engagement_id), scope_id, validated.name),
                    )
                    existing = cursor.fetchone()
                    if existing:
                        return _row_id(existing)
                cursor.execute(
                    """
                    INSERT INTO securescope_interested_parties (
                        client_id,
                        engagement_id,
                        scope_id,
                        party_uuid,
                        name,
                        party_type,
                        relationship_description,
                        needs_and_expectations,
                        communication_method,
                        owner,
                        status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, 'Active', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        str(uuid.uuid4()),
                        validated.name,
                        validated.party_type,
                        validated.relationship_description,
                        validated.needs_and_expectations,
                        validated.communication_method,
                        validated.owner,
                        principal,
                    ),
                )
                party_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="interested_party.created",
                    entity_type="interested_party",
                    entity_id=str(party_id),
                    actor=principal,
                    summary=f"Created interested party {validated.name}.",
                    payload={"scope_id": scope_id, "party_type": validated.party_type},
                )
                return party_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_party_requirement(
    client_name: str,
    engagement_id: int,
    party_id: int,
    draft: PartyRequirementDraft,
    *,
    actor: str,
    scope_id: int | None = None,
    reuse_existing: bool = False,
) -> int:
    """Attach a legal, contractual or stakeholder requirement to a party.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        party_id: Parent interested-party identifier.
        draft: Validated requirement input.
        actor: Person recording the requirement.
        scope_id: Optional related scope definition.
        reuse_existing: Reuse matching reviewed Discovery suggestions without overwriting them.

    Returns:
        New requirement identifier.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Requirement creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT id
                    FROM securescope_interested_parties
                    WHERE client_id = %s AND engagement_id = %s AND id = %s;
                    """,
                    (client_id, int(engagement_id), int(party_id)),
                )
                if not cursor.fetchone():
                    raise GrcWorkspaceRepositoryError(
                        "Interested party does not belong to the selected engagement."
                    )
                if reuse_existing:
                    cursor.execute(
                        "SELECT id FROM securescope_interested_party_requirements "
                        "WHERE client_id=%s AND engagement_id=%s "
                        "AND scope_id IS NOT DISTINCT FROM %s "
                        "AND lower(btrim(requirement))=lower(btrim(%s)) AND party_id=%s "
                        "ORDER BY id LIMIT 1",
                        (
                            client_id,
                            int(engagement_id),
                            scope_id,
                            validated.requirement,
                            int(party_id),
                        ),
                    )
                    existing = cursor.fetchone()
                    if existing:
                        return _row_id(existing)
                cursor.execute(
                    """
                    INSERT INTO securescope_interested_party_requirements (
                        client_id,
                        engagement_id,
                        scope_id,
                        party_id,
                        requirement_type,
                        requirement,
                        source_reference,
                        applicability,
                        mandatory,
                        owner,
                        review_date,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        int(party_id),
                        validated.requirement_type,
                        validated.requirement,
                        validated.source_reference,
                        validated.applicability,
                        validated.mandatory,
                        validated.owner,
                        validated.review_date,
                        principal,
                    ),
                )
                requirement_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="interested_party.requirement_created",
                    entity_type="interested_party_requirement",
                    entity_id=str(requirement_id),
                    actor=principal,
                    summary="Created an interested-party requirement.",
                    payload={
                        "party_id": int(party_id),
                        "requirement_type": validated.requirement_type,
                        "applicability": validated.applicability,
                    },
                )
                return requirement_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_organizational_units(
    client_name: str,
    engagement_id: int,
    scope_id: int | None = None,
) -> list[dict[str, Any]]:
    """List sites and organizational units in the selected context.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope; engagement-wide units remain visible.

    Returns:
        Organizational units with optional parent names.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT unit.*, parent.name AS parent_name
                    FROM securescope_organizational_units AS unit
                    LEFT JOIN securescope_organizational_units AS parent
                      ON parent.client_id = unit.client_id
                     AND parent.id = unit.parent_unit_id
                    WHERE unit.client_id = %s
                      AND unit.engagement_id = %s
                      AND (%s IS NULL OR unit.scope_id IS NULL OR unit.scope_id = %s)
                    ORDER BY
                        CASE unit.status WHEN 'Active' THEN 0 ELSE 1 END,
                        CASE unit.unit_type
                            WHEN 'Legal entity' THEN 0
                            WHEN 'Site' THEN 1
                            WHEN 'Business unit' THEN 2
                            WHEN 'Department' THEN 3
                            ELSE 4
                        END,
                        lower(unit.name);
                    """,
                    (client_id, int(engagement_id), scope_id, scope_id),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_organizational_unit(
    client_name: str,
    engagement_id: int,
    draft: OrganizationalUnitDraft,
    *,
    actor: str,
    scope_id: int | None = None,
) -> int:
    """Create one site, department or organizational unit.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated organizational-unit input.
        actor: Person recording the unit.
        scope_id: Optional related scope definition.

    Returns:
        New organizational-unit identifier.

    Raises:
        GrcWorkspaceRepositoryError: If ownership or persistence checks fail.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Organizational unit creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                if validated.parent_unit_id is not None:
                    cursor.execute(
                        """
                        SELECT id
                        FROM securescope_organizational_units
                        WHERE client_id = %s
                          AND engagement_id = %s
                          AND id = %s;
                        """,
                        (
                            client_id,
                            int(engagement_id),
                            validated.parent_unit_id,
                        ),
                    )
                    if not cursor.fetchone():
                        raise GrcWorkspaceRepositoryError(
                            "Parent unit does not belong to the selected engagement."
                        )
                cursor.execute(
                    """
                    INSERT INTO securescope_organizational_units (
                        client_id,
                        engagement_id,
                        scope_id,
                        unit_uuid,
                        parent_unit_id,
                        unit_type,
                        name,
                        description,
                        address,
                        in_scope,
                        owner,
                        status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, 'Active', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        str(uuid.uuid4()),
                        validated.parent_unit_id,
                        validated.unit_type,
                        validated.name,
                        validated.description,
                        validated.address,
                        validated.in_scope,
                        validated.owner,
                        principal,
                    ),
                )
                unit_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="organization.unit_created",
                    entity_type="organizational_unit",
                    entity_id=str(unit_id),
                    actor=principal,
                    summary=f"Created {validated.unit_type.lower()} {validated.name}.",
                    payload={
                        "scope_id": scope_id,
                        "in_scope": validated.in_scope,
                        "parent_unit_id": validated.parent_unit_id,
                    },
                )
                return unit_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_workspace_members(client_name: str) -> list[dict[str, Any]]:
    """List active database-backed members of one client workspace.

    Args:
        client_name: Exact client workspace name.

    Returns:
        User IDs, emails, names and workspace roles.

    Raises:
        GrcWorkspaceRepositoryError: If PostgreSQL cannot load memberships.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT
                        user_account.id AS user_id,
                        user_account.email,
                        user_account.display_name,
                        membership.role AS workspace_role
                    FROM securescope_workspace_memberships AS membership
                    JOIN securescope_users AS user_account
                      ON user_account.id = membership.user_id
                    WHERE membership.client_id = %s
                      AND membership.active
                      AND user_account.active
                    ORDER BY lower(user_account.display_name), user_account.email;
                    """,
                    (client_id,),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_engagement_members(
    client_name: str,
    engagement_id: int,
) -> list[dict[str, Any]]:
    """List real user memberships assigned to an engagement.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Engagement-role assignments with user identity.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                cursor.execute(
                    """
                    SELECT
                        member.*,
                        user_account.email,
                        user_account.display_name,
                        workspace_member.role AS workspace_role
                    FROM securescope_engagement_members AS member
                    JOIN securescope_users AS user_account
                      ON user_account.id = member.user_id
                    JOIN securescope_workspace_memberships AS workspace_member
                      ON workspace_member.client_id = member.client_id
                     AND workspace_member.user_id = member.user_id
                    WHERE member.client_id = %s
                      AND member.engagement_id = %s
                      AND member.active
                    ORDER BY member.engagement_role, lower(user_account.display_name);
                    """,
                    (client_id, int(engagement_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def assign_engagement_member(
    client_name: str,
    engagement_id: int,
    user_id: int,
    engagement_role: str,
    *,
    actor: str,
) -> int:
    """Assign an existing workspace user to a real engagement role.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        user_id: Existing active workspace user identifier.
        engagement_role: Allowlisted consulting or client role.
        actor: Person recording the assignment.

    Returns:
        Engagement membership identifier.

    Raises:
        GrcWorkspaceRepositoryError: If identity, ownership or persistence fails.
        GrcValidationError: If the role vocabulary is invalid.
    """

    resolved_role = choice(engagement_role, "engagement role", ENGAGEMENT_ROLES)
    principal = required_text(actor, "Role assigner", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                member = _workspace_member(cursor, client_id, user_id=int(user_id))
                cursor.execute(
                    """
                    INSERT INTO securescope_engagement_members (
                        client_id,
                        engagement_id,
                        user_id,
                        engagement_role,
                        active,
                        assigned_by
                    )
                    VALUES (%s, %s, %s, %s, TRUE, %s)
                    ON CONFLICT (
                        client_id,
                        engagement_id,
                        user_id,
                        engagement_role
                    ) DO UPDATE
                        SET active = TRUE,
                            assigned_by = EXCLUDED.assigned_by,
                            updated_at = NOW()
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        int(user_id),
                        resolved_role,
                        principal,
                    ),
                )
                membership_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="engagement.member_assigned",
                    entity_type="engagement_member",
                    entity_id=str(membership_id),
                    actor=principal,
                    summary=(f"Assigned {member['email']} as {resolved_role}."),
                    payload={"user_id": int(user_id), "role": resolved_role},
                )
                return membership_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_role_assignments(
    client_name: str,
    engagement_id: int,
    scope_id: int | None = None,
) -> list[dict[str, Any]]:
    """List user-backed ISMS RACI assignments in the active context.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope; engagement-wide roles remain visible.

    Returns:
        Active and historical RACI assignments with user identity.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    """
                    SELECT
                        assignment.*,
                        user_account.email,
                        user_account.display_name
                    FROM securescope_isms_role_assignments AS assignment
                    JOIN securescope_users AS user_account
                      ON user_account.id = assignment.user_id
                    WHERE assignment.client_id = %s
                      AND assignment.engagement_id = %s
                      AND (
                          %s IS NULL
                          OR assignment.scope_id IS NULL
                          OR assignment.scope_id = %s
                      )
                    ORDER BY
                        CASE assignment.status WHEN 'Active' THEN 0 ELSE 1 END,
                        assignment.role_name,
                        assignment.raci_type,
                        lower(user_account.display_name);
                    """,
                    (client_id, int(engagement_id), scope_id, scope_id),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def assign_raci_role(
    client_name: str,
    engagement_id: int,
    draft: RaciAssignmentDraft,
    *,
    actor: str,
    scope_id: int | None = None,
) -> int:
    """Create a real user-backed ISMS role and RACI assignment.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated user, responsibility and RACI input.
        actor: Person recording the assignment.
        scope_id: Optional scope-specific assignment.

    Returns:
        New RACI assignment identifier.

    Raises:
        GrcWorkspaceRepositoryError: If identity, ownership or persistence fails.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "RACI assigner", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    _scope(cursor, client_id, engagement_id, scope_id)
                member = _workspace_member(
                    cursor,
                    client_id,
                    user_id=validated.user_id,
                )
                cursor.execute(
                    """
                    INSERT INTO securescope_isms_role_assignments (
                        client_id,
                        engagement_id,
                        scope_id,
                        user_id,
                        role_name,
                        responsibility,
                        raci_type,
                        authority,
                        effective_from,
                        effective_to,
                        status,
                        assigned_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, 'Active', %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        scope_id,
                        validated.user_id,
                        validated.role_name,
                        validated.responsibility,
                        validated.raci_type,
                        validated.authority,
                        validated.effective_from,
                        validated.effective_to,
                        principal,
                    ),
                )
                assignment_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="isms.raci_assigned",
                    entity_type="isms_role_assignment",
                    entity_id=str(assignment_id),
                    actor=principal,
                    summary=(
                        f"Assigned {member['email']} as {validated.raci_type} "
                        f"for {validated.role_name}."
                    ),
                    payload={
                        "scope_id": scope_id,
                        "user_id": validated.user_id,
                        "role_name": validated.role_name,
                        "raci_type": validated.raci_type,
                    },
                )
                return assignment_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_milestones(
    client_name: str,
    engagement_id: int,
) -> list[dict[str, Any]]:
    """List engagement milestones with optional owner identity.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Milestones ordered by open status and due date.

    Raises:
        GrcWorkspaceRepositoryError: If the context is invalid or unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                cursor.execute(
                    """
                    SELECT
                        milestone.*,
                        user_account.email AS owner_email,
                        user_account.display_name AS owner_name
                    FROM securescope_engagement_milestones AS milestone
                    LEFT JOIN securescope_users AS user_account
                      ON user_account.id = milestone.owner_user_id
                    WHERE milestone.client_id = %s
                      AND milestone.engagement_id = %s
                    ORDER BY
                        CASE milestone.status
                            WHEN 'Blocked' THEN 0
                            WHEN 'In progress' THEN 1
                            WHEN 'Planned' THEN 2
                            ELSE 3
                        END,
                        milestone.due_date,
                        milestone.id;
                    """,
                    (client_id, int(engagement_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def create_milestone(
    client_name: str,
    engagement_id: int,
    draft: MilestoneDraft,
    *,
    actor: str,
) -> int:
    """Create a certification-cycle or consulting milestone.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Selected engagement identifier.
        draft: Validated milestone input.
        actor: Person recording the milestone.

    Returns:
        New milestone identifier.

    Raises:
        GrcWorkspaceRepositoryError: If identity, ownership or persistence fails.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = required_text(actor, "Milestone creator", max_length=250)
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                if validated.owner_user_id is not None:
                    _workspace_member(
                        cursor,
                        client_id,
                        user_id=validated.owner_user_id,
                    )
                cursor.execute(
                    """
                    INSERT INTO securescope_engagement_milestones (
                        client_id,
                        engagement_id,
                        title,
                        milestone_type,
                        description,
                        owner_user_id,
                        due_date,
                        status,
                        acceptance_criteria,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, 'Planned', %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id),
                        validated.title,
                        validated.milestone_type,
                        validated.description,
                        validated.owner_user_id,
                        validated.due_date,
                        validated.acceptance_criteria,
                        principal,
                    ),
                )
                milestone_id = _row_id(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="engagement.milestone_created",
                    entity_type="engagement_milestone",
                    entity_id=str(milestone_id),
                    actor=principal,
                    summary=f"Created milestone {validated.title}.",
                    payload={
                        "milestone_type": validated.milestone_type,
                        "due_date": validated.due_date,
                        "owner_user_id": validated.owner_user_id,
                    },
                )
                return milestone_id
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def list_scope_versions(
    client_name: str, engagement_id: int, scope_id: int
) -> list[dict[str, Any]]:
    """Return historical versions only for the selected tenant, engagement and scope.

    Args:
        client_name: str: Exact active client workspace name.
        engagement_id: int: Selected engagement identifier.
        scope_id: int | None: Selected ISMS scope identifier.

    Returns:
        list[dict[str, Any]]: Historical versions, newest first.

    Raises:
        GrcWorkspaceRepositoryError: Ownership, state or persistence validation failed.
    """
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id)
                _scope(cursor, client_id, engagement_id, scope_id)
                cursor.execute(
                    "SELECT * FROM securescope_scope_versions WHERE client_id = %s "
                    "AND engagement_id = %s AND scope_id = %s ORDER BY version_number DESC",
                    (client_id, int(engagement_id), int(scope_id)),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def submit_scope_review(
    client_name: str, engagement_id: int, scope_id: int, version_id: int, *, actor: str, note: str
) -> None:
    """Submit the latest draft for review with tenant checks, locking and an audit event.

    Args:
        client_name: str: Exact active client workspace name.
        engagement_id: int: Selected engagement identifier.
        scope_id: int | None: Selected ISMS scope identifier.
        version_id: int: Expected latest draft scope-version identifier.
        actor: str: Trusted current workspace identity.
        note: str: Human review rationale retained in the audit trail.

    Returns:
        None.

    Raises:
        GrcWorkspaceRepositoryError: Ownership, state or persistence validation failed.
    """
    if not note.strip():
        raise GrcWorkspaceRepositoryError("A review rationale is required.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                _scope(cursor, client_id, engagement_id, scope_id, for_update=True)
                member = _workspace_member(cursor, client_id, email=actor.strip().lower())
                if member["workspace_role"] not in {
                    "Administrator",
                    "Consultant",
                    "Client contributor",
                }:
                    raise GrcWorkspaceRepositoryError("Contributor membership is required.")
                cursor.execute(
                    "SELECT id, status FROM securescope_scope_versions WHERE client_id=%s "
                    "AND engagement_id=%s AND scope_id=%s "
                    "ORDER BY version_number DESC LIMIT 1 FOR UPDATE",
                    (client_id, int(engagement_id), int(scope_id)),
                )
                version = cursor.fetchone()
                if (
                    not version
                    or int(version["id"]) != int(version_id)
                    or version["status"] != "Draft"
                ):
                    raise GrcWorkspaceRepositoryError(
                        "Scope changed. Review the latest draft before submitting."
                    )
                cursor.execute(
                    "UPDATE securescope_scope_versions SET status='Under review', submitted_by=%s, "
                    "submitted_at=NOW(), submission_rationale=%s WHERE client_id=%s AND id=%s",
                    (actor.strip().lower(), note.strip(), client_id, int(version_id)),
                )
                _append_audit_event(
                    cursor,
                    client_id,
                    int(engagement_id),
                    event_type="scope.review_requested",
                    entity_type="scope_version",
                    entity_id=str(version_id),
                    actor=actor,
                    summary="Scope submitted for human review.",
                    payload={"scope_id": int(scope_id), "rationale": note.strip()},
                )
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def record_scope_review(
    client_name: str,
    engagement_id: int,
    scope_id: int,
    version_id: int,
    *,
    actor: str,
    note: str,
    decision: str,
) -> None:
    """Record a review decision on the latest submitted scope version.

    Args:
        client_name: Active tenant name.
        engagement_id: Selected engagement identifier.
        scope_id: Selected scope identifier.
        version_id: Observed latest version identifier.
        actor: Trusted reviewer identity.
        note: Required review rationale.
        decision: Reviewed or Changes requested.
    Returns:
        None.
    Raises:
        GrcWorkspaceRepositoryError: For unauthorized, stale or invalid transitions.
    """
    if decision not in {"Reviewed", "Changes requested"} or not note.strip():
        raise GrcWorkspaceRepositoryError("Choose a review decision and provide a rationale.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                _scope(cursor, client_id, engagement_id, scope_id, for_update=True)
                member = _workspace_member(cursor, client_id, email=actor.strip().lower())
                if member["workspace_role"] not in APPROVER_WORKSPACE_ROLES:
                    raise GrcWorkspaceRepositoryError(
                        "An Administrator or Consultant must review the scope."
                    )
                cursor.execute(
                    "SELECT id,status FROM securescope_scope_versions WHERE client_id=%s "
                    "AND engagement_id=%s AND scope_id=%s ORDER BY version_number DESC LIMIT 1 "
                    "FOR UPDATE",
                    (client_id, engagement_id, scope_id),
                )
                version = cursor.fetchone()
                allowed = (
                    {"Under review"} if decision == "Reviewed" else {"Under review", "Reviewed"}
                )
                if (
                    not version
                    or int(version["id"]) != int(version_id)
                    or version["status"] not in allowed
                ):
                    raise GrcWorkspaceRepositoryError(
                        "Scope changed or is not ready for this review decision."
                    )
                cursor.execute(
                    "UPDATE securescope_scope_versions SET status=%s,reviewed_by=%s,"
                    "reviewed_at=NOW(),review_rationale=%s WHERE client_id=%s AND id=%s",
                    (decision, actor.strip().lower(), note.strip(), client_id, version_id),
                )
                _append_audit_event(
                    cursor,
                    client_id,
                    engagement_id,
                    event_type="scope.review_recorded",
                    entity_type="scope_version",
                    entity_id=str(version_id),
                    actor=actor,
                    summary=f"Scope {decision.lower()}.",
                    payload={"scope_id": scope_id, "decision": decision, "rationale": note.strip()},
                )
    except DatabaseError as exc:
        raise GrcWorkspaceRepositoryError(str(exc)) from exc


def update_foundation_record(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    record_id: int,
    *,
    section: str,
    values: dict,
    expected_updated_at: str,
    actor: str,
    note: str,
) -> dict:
    """Update a tenant-owned Context issue or party using its existing domain model.

    Args:
        client_name: Exact workspace name.
        engagement_id: Selected engagement.
        scope_id: Selected scope; must match the record.
        record_id: Existing record identifier.
        section: Context or parties register.
        values: Editable fields and existing domain status.
        expected_updated_at: Concurrency token from the displayed record.
        actor: Trusted signed-in principal.
        note: Human change or review rationale.
    Returns:
        Updated canonical record.
    Raises:
        GrcWorkspaceRepositoryError: For invalid context, permission or stale edits.
        GrcValidationError: For invalid domain fields.
    """
    from dataclasses import asdict, fields

    from psycopg2 import sql

    models = {
        "context": (
            "securescope_context_issues",
            ContextIssueDraft,
            ("Open", "Monitoring", "Closed"),
        ),
        "parties": ("securescope_interested_parties", InterestedPartyDraft, ("Active", "Inactive")),
    }
    if section not in models:
        raise GrcWorkspaceRepositoryError("This register does not support that action.")
    table, model, statuses = models[section]
    normalized = asdict(model(**{f.name: values.get(f.name) for f in fields(model)}).validate())
    normalized["status"] = choice(values.get("status"), "status", statuses)
    rationale = required_text(note, "Change / review rationale")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _engagement(cursor, client_id, engagement_id, for_update=True)
                member = _workspace_member(cursor, client_id, email=actor)
                if member["workspace_role"] not in {
                    "Administrator",
                    "Consultant",
                    "Client contributor",
                }:
                    raise GrcWorkspaceRepositoryError("Contributor membership is required.")
                cursor.execute(
                    sql.SQL(
                        "SELECT * FROM {} WHERE client_id=%s AND engagement_id=%s AND id=%s "
                        "AND (%s IS NULL OR scope_id IS NULL OR scope_id=%s) FOR UPDATE"
                    ).format(sql.Identifier(table)),
                    (client_id, engagement_id, record_id, scope_id, scope_id),
                )
                current = cursor.fetchone()
                if not current or str(current["updated_at"]) != expected_updated_at:
                    raise GrcWorkspaceRepositoryError(
                        "Record changed or is outside this context. Reload before saving."
                    )
                assignments = sql.SQL(", ").join(
                    sql.SQL("{}=%s").format(sql.Identifier(k)) for k in normalized
                )
                cursor.execute(
                    sql.SQL(
                        "UPDATE {} SET {}, updated_at=NOW() WHERE client_id=%s AND id=%s "
                        "RETURNING *"
                    ).format(sql.Identifier(table), assignments),
                    (*normalized.values(), client_id, record_id),
                )
                saved = dict(cursor.fetchone())
                _append_audit_event(
                    cursor,
                    client_id,
                    engagement_id,
                    event_type=f"{section}.updated",
                    entity_type=section,
                    entity_id=record_id,
                    actor=actor,
                    summary=rationale,
                    payload={
                        "before": {k: str(current.get(k) or "") for k in normalized},
                        "after": {k: str(v or "") for k, v in normalized.items()},
                    },
                )
                return saved
    except DatabaseError as exc:
        LOGGER.warning("Foundation record update failed: %s", type(exc).__name__)
        raise GrcWorkspaceRepositoryError(str(exc)) from exc
