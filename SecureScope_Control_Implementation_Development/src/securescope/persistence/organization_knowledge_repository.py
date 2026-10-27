"""PostgreSQL persistence for organization knowledge and discovery facts."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from psycopg2.extras import Json, RealDictCursor

from securescope.grc.organization_models import (
    OrganizationFactDraft,
    OrganizationProfileDraft,
)
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.migration_service import run_pending_migrations


class OrganizationKnowledgeRepositoryError(RuntimeError):
    """Raised when organization knowledge persistence cannot be completed."""


def _row_id(row: Mapping[str, Any] | Sequence[Any] | None) -> int:
    """Extract a PostgreSQL identifier from a cursor row.

    Args:
        row: Mapping or sequence returned by PostgreSQL.

    Returns:
        Positive integer row identifier.

    Raises:
        OrganizationKnowledgeRepositoryError: If no row was returned.
    """

    if not row:
        raise OrganizationKnowledgeRepositoryError(
            "PostgreSQL did not return an organization-fact ID."
        )
    value = row["id"] if isinstance(row, Mapping) else row[0]
    return int(value)


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve one existing client workspace.

    Args:
        cursor: Active PostgreSQL cursor.
        client_name: Exact client workspace name.

    Returns:
        Client identifier.

    Raises:
        OrganizationKnowledgeRepositoryError: If the workspace does not exist.
    """

    name = str(client_name or "").strip()
    if not name:
        raise OrganizationKnowledgeRepositoryError("Client workspace name is required.")
    cursor.execute(
        "SELECT id FROM securescope_clients WHERE name = %s;",
        (name,),
    )
    row = cursor.fetchone()
    if not row:
        raise OrganizationKnowledgeRepositoryError(f"Client workspace not found: {name}")
    return _row_id(row)


def _validate_engagement(
    cursor: Any,
    client_id: int,
    engagement_id: int | None,
) -> None:
    """Validate optional engagement ownership.

    Args:
        cursor: Active PostgreSQL cursor.
        client_id: Authorized client identifier.
        engagement_id: Optional engagement identifier.

    Returns:
        None.

    Raises:
        OrganizationKnowledgeRepositoryError: If the engagement is foreign.
    """

    if engagement_id is None:
        return
    cursor.execute(
        """
        SELECT 1
        FROM securescope_engagements
        WHERE client_id = %s AND id = %s;
        """,
        (client_id, int(engagement_id)),
    )
    if not cursor.fetchone():
        raise OrganizationKnowledgeRepositoryError(
            "Engagement does not belong to the active client workspace."
        )


def get_organization_profile(client_name: str) -> dict[str, Any] | None:
    """Load the quick organization profile for a workspace.

    Args:
        client_name: Exact client workspace name.

    Returns:
        Profile row or ``None`` when discovery has not started.

    Raises:
        OrganizationKnowledgeRepositoryError: If PostgreSQL is unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    SELECT *
                    FROM securescope_organization_profiles
                    WHERE client_id = %s;
                    """,
                    (client_id,),
                )
                row = cursor.fetchone()
                return dict(row) if row else None
    except DatabaseError as exc:
        raise OrganizationKnowledgeRepositoryError(str(exc)) from exc


def upsert_organization_profile(
    client_name: str,
    draft: OrganizationProfileDraft,
    *,
    actor: str,
) -> dict[str, Any]:
    """Create or update the quick organization profile.

    Args:
        client_name: Exact client workspace name.
        draft: Validated profile input.
        actor: Human principal recording the discovery information.

    Returns:
        Persisted organization-profile row.

    Raises:
        OrganizationKnowledgeRepositoryError: If actor or persistence is invalid.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = str(actor or "").strip()
    if not principal:
        raise OrganizationKnowledgeRepositoryError(
            "An actor is required to save organization discovery."
        )
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    """
                    INSERT INTO securescope_organization_profiles (
                        client_id,
                        industry,
                        main_activity,
                        employee_band,
                        infrastructure_model,
                        locations,
                        departments,
                        products_and_services,
                        technologies,
                        customer_markets,
                        certification_drivers,
                        profile_status,
                        updated_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (client_id) DO UPDATE SET
                        industry = EXCLUDED.industry,
                        main_activity = EXCLUDED.main_activity,
                        employee_band = EXCLUDED.employee_band,
                        infrastructure_model = EXCLUDED.infrastructure_model,
                        locations = EXCLUDED.locations,
                        departments = EXCLUDED.departments,
                        products_and_services = EXCLUDED.products_and_services,
                        technologies = EXCLUDED.technologies,
                        customer_markets = EXCLUDED.customer_markets,
                        certification_drivers = EXCLUDED.certification_drivers,
                        profile_status = EXCLUDED.profile_status,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = NOW()
                    RETURNING *;
                    """,
                    (
                        client_id,
                        validated.industry,
                        validated.main_activity,
                        validated.employee_band,
                        validated.infrastructure_model,
                        Json(list(validated.locations)),
                        Json(list(validated.departments)),
                        Json(list(validated.products_and_services)),
                        Json(list(validated.technologies)),
                        Json(list(validated.customer_markets)),
                        Json(list(validated.certification_drivers)),
                        validated.profile_status,
                        principal,
                    ),
                )
                return dict(cursor.fetchone())
    except DatabaseError as exc:
        raise OrganizationKnowledgeRepositoryError(str(exc)) from exc


def upsert_organization_fact(
    client_name: str,
    draft: OrganizationFactDraft,
    *,
    actor: str,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> int:
    """Persist one normalized organization fact with provenance.

    Args:
        client_name: Exact client workspace name.
        draft: Fact input.
        actor: Human or service principal recording the fact.
        engagement_id: Optional engagement context.
        scope_id: Optional scope context.

    Returns:
        Fact identifier.

    Raises:
        OrganizationKnowledgeRepositoryError: If ownership or persistence fails.
        GrcValidationError: Propagated when ``draft`` is invalid.
    """

    validated = draft.validate()
    principal = str(actor or "").strip()
    if not principal:
        raise OrganizationKnowledgeRepositoryError(
            "An actor is required to record organization facts."
        )
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _validate_engagement(cursor, client_id, engagement_id)
                if scope_id is not None:
                    cursor.execute(
                        """
                        SELECT 1
                        FROM securescope_scope_definitions
                        WHERE client_id = %s AND id = %s;
                        """,
                        (client_id, int(scope_id)),
                    )
                    if not cursor.fetchone():
                        raise OrganizationKnowledgeRepositoryError(
                            "Scope does not belong to the active client workspace."
                        )
                verified_by = principal if validated.status == "Confirmed" else None
                cursor.execute(
                    """
                    INSERT INTO securescope_organization_facts (
                        client_id,
                        engagement_id,
                        scope_id,
                        fact_type,
                        fact_key,
                        value_text,
                        source_type,
                        source_reference,
                        confidence,
                        status,
                        verified_by,
                        verified_at,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        CASE WHEN %s = 'Confirmed' THEN NOW() ELSE NULL END,
                        %s
                    )
                    ON CONFLICT (
                        client_id, engagement_id, fact_type, fact_key, source_type
                    ) DO UPDATE SET
                        scope_id = EXCLUDED.scope_id,
                        value_text = EXCLUDED.value_text,
                        source_reference = EXCLUDED.source_reference,
                        confidence = EXCLUDED.confidence,
                        status = EXCLUDED.status,
                        verified_by = EXCLUDED.verified_by,
                        verified_at = CASE
                            WHEN EXCLUDED.status = 'Confirmed' THEN NOW()
                            ELSE NULL
                        END,
                        updated_at = NOW()
                    RETURNING id;
                    """,
                    (
                        client_id,
                        int(engagement_id) if engagement_id is not None else None,
                        int(scope_id) if scope_id is not None else None,
                        validated.fact_type,
                        validated.fact_key,
                        validated.value_text,
                        validated.source_type,
                        validated.source_reference,
                        validated.confidence,
                        validated.status,
                        verified_by,
                        validated.status,
                        principal,
                    ),
                )
                return _row_id(cursor.fetchone())
    except DatabaseError as exc:
        raise OrganizationKnowledgeRepositoryError(str(exc)) from exc


def list_organization_facts(
    client_name: str,
    *,
    engagement_id: int | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """List organization facts visible in a workspace/engagement.

    Args:
        client_name: Exact client workspace name.
        engagement_id: Optional engagement filter. Workspace-wide facts remain visible.
        status: Optional exact fact status filter.

    Returns:
        Facts ordered by type and value.

    Raises:
        OrganizationKnowledgeRepositoryError: If the context is unavailable.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                _validate_engagement(cursor, client_id, engagement_id)
                conditions = ["client_id = %s"]
                parameters: list[Any] = [client_id]
                if engagement_id is not None:
                    conditions.append("(engagement_id IS NULL OR engagement_id = %s)")
                    parameters.append(int(engagement_id))
                if status is not None:
                    conditions.append("status = %s")
                    parameters.append(str(status))
                cursor.execute(
                    f"""
                    SELECT *
                    FROM securescope_organization_facts
                    WHERE {' AND '.join(conditions)}
                    ORDER BY fact_type, value_text, id;
                    """,
                    tuple(parameters),
                )
                return [dict(row) for row in cursor.fetchall()]
    except DatabaseError as exc:
        raise OrganizationKnowledgeRepositoryError(str(exc)) from exc
