"""Client-scoped membership administration and immutable formal versions."""

from __future__ import annotations

import hmac
import logging
import os
import re
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from psycopg2.extras import Json, RealDictCursor

from securescope.grc.formal_registers import next_status, risk_signature, validate_records
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.evidence_repository import _append_audit_event
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)
ROLES = ("Administrator", "Consultant", "Client contributor", "Auditor")


class FoundationError(ValueError):
    """A Foundation operation failed validation, authorization or persistence."""


@contextmanager
def workspace_cursor(client_name: str) -> Iterator[tuple[Any, int]]:
    """Open a transaction and serialize writes for one existing client.

    Args:
        client_name: Exact client name.
    Yields:
        Cursor and client identifier.
    Raises:
        FoundationError: On missing client or database failure.
    """
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE name = %s FOR UPDATE",
                    (client_name,),
                )
                row = cursor.fetchone()
                if not row:
                    raise FoundationError("Workspace not found.")
                yield cursor, int(row["id"])
    except DatabaseError as exc:
        LOGGER.warning("Foundation database operation failed", exc_info=True)
        raise FoundationError(
            "Foundation data is unavailable. Check database connectivity and migrations."
        ) from exc


def member_role(cursor: Any, client_id: int, actor: str) -> str:
    """Resolve active tenant membership; return an empty role for nonmembers.

    Args:
        cursor: Transaction cursor.
        client_id: Selected tenant.
        actor: Trusted session/host identity, not a form-selected approver.
    Returns:
        Role string.
    Raises:
        DatabaseError: If the role query fails.
    """
    cursor.execute(
        "SELECT m.role FROM securescope_workspace_memberships m "
        "JOIN securescope_users u ON u.id = m.user_id "
        "WHERE m.client_id = %s AND u.email = %s AND m.active AND u.active",
        (client_id, actor.strip().lower()),
    )
    row = cursor.fetchone()
    return row["role"] if row else ""


def operator_proof(token: str) -> None:
    """Check the process-local host code without logging or storing it.

    Args:
        token: Secret entered in the browser by the host operator.
    Returns:
        None.
    Raises:
        FoundationError: If host setup is unavailable or proof fails.
    """
    expected = os.getenv("SECURESCOPE_LOCAL_SETUP_CODE", "")
    if len(expected) < 32 or not hmac.compare_digest(expected.encode(), token.encode()):
        raise FoundationError("Invalid local setup code. Use the code in the launcher window.")


def local_administrator(client_name: str, email: str, name: str, token: str) -> str:
    """Bootstrap once, or authenticate an existing admin using host proof.

    Args:
        client_name: Target workspace.
        email: Administrator identity.
        name: Display name for first setup.
        token: Current launcher's secret code.
    Returns:
        Verified email for this Streamlit session.
    Raises:
        FoundationError: On invalid proof, replay, or a non-admin identity.
    """
    operator_proof(token)
    email = email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not name.strip():
        raise FoundationError("Enter a valid email and display name.")
    with workspace_cursor(client_name) as (cursor, client_id):
        role = member_role(cursor, client_id, email)
        if role == "Administrator":
            return email
        cursor.execute(
            "SELECT 1 FROM securescope_workspace_memberships m "
            "JOIN securescope_users u ON u.id = m.user_id "
            "WHERE m.client_id = %s AND m.role = 'Administrator' AND m.active AND u.active",
            (client_id,),
        )
        administrator_exists = cursor.fetchone() is not None
        cursor.execute(
            "SELECT 1 FROM securescope_workspace_bootstraps WHERE client_id = %s",
            (client_id,),
        )
        if administrator_exists or cursor.fetchone():
            raise FoundationError(
                "Setup is already complete. Sign in as an existing Administrator."
            )
        _write_member(cursor, client_id, email, name, "Administrator", email)
        cursor.execute(
            (
                "INSERT INTO securescope_workspace_bootstraps (client_id, "
                "administrator_email) VALUES (%s, %s)"
            ),
            (client_id, email),
        )
    return email


def _write_member(
    cursor: Any, client_id: int, email: str, name: str, role: str, actor: str
) -> None:
    """Write membership within an already authorized transaction.

    Args:
        cursor: Transaction cursor.
        client_id: Tenant.
        email: Normalized member email.
        name: Display name.
        role: Validated role.
        actor: Authorized grantor.
    Returns:
        None.
    Raises:
        DatabaseError: If persistence fails.
    """
    cursor.execute(
        "INSERT INTO securescope_users (user_uuid, email, display_name) VALUES (%s, %s, %s) "
        "ON CONFLICT (email) DO NOTHING RETURNING id",
        (str(uuid.uuid4()), email, name.strip()),
    )
    cursor.execute("SELECT id, active FROM securescope_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if not user["active"]:
        raise FoundationError("This identity is inactive; host administration is required.")
    cursor.execute(
        "INSERT INTO securescope_workspace_memberships (client_id, user_id, role, granted_by) "
        "VALUES (%s, %s, %s, %s) ON CONFLICT (client_id, user_id) DO UPDATE "
        "SET role = EXCLUDED.role, active = TRUE, granted_by = "
        "EXCLUDED.granted_by, updated_at = NOW() RETURNING id",
        (client_id, user["id"], role, actor),
    )
    membership_id = cursor.fetchone()["id"]
    _append_audit_event(
        cursor,
        client_id,
        event_type="Membership changed",
        entity_type="Membership",
        entity_id=str(membership_id),
        actor=actor,
        summary=f"Workspace role set to {role}.",
        payload={"email": email, "role": role},
    )


def save_member(client_name: str, *, actor: str, email: str, name: str, role: str) -> None:
    """Add/change membership with server-side authorization and last-admin protection.

    Args:
        client_name: Tenant name.
        actor: Trusted current identity.
        email: Target member.
        name: New member display name.
        role: Requested workspace role.
    Returns:
        None.
    Raises:
        FoundationError: For denied grants or persistence failure.
    """
    email = email.strip().lower()
    if (
        role not in ROLES
        or not name.strip()
        or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
    ):
        raise FoundationError("Valid member email, name and role are required.")
    with workspace_cursor(client_name) as (cursor, client_id):
        if member_role(cursor, client_id, actor) != "Administrator":
            raise FoundationError("Only a workspace Administrator can manage members.")
        if member_role(cursor, client_id, email) == "Administrator" and role != "Administrator":
            cursor.execute(
                "SELECT COUNT(*) AS count FROM securescope_workspace_memberships m "
                "JOIN securescope_users u ON u.id=m.user_id "
                "WHERE m.client_id=%s AND m.role='Administrator' AND m.active AND u.active",
                (client_id,),
            )
            if cursor.fetchone()["count"] <= 1:
                raise FoundationError("Keep at least one active Administrator.")
        _write_member(cursor, client_id, email, name, role, actor)


def versions(
    client_name: str, engagement_id: int, scope_id: int, kind: str
) -> list[dict[str, Any]]:
    """Load stored versions; database errors never become an empty list.

    Args:
        client_name: Tenant.
        engagement_id: Engagement.
        scope_id: Scope definition.
        kind: Register key.
    Returns:
        Versions newest first.
    Raises:
        FoundationError: On a read failure.
    """
    with workspace_cursor(client_name) as (cursor, client_id):
        cursor.execute(
            "SELECT * FROM securescope_foundation_versions WHERE client_id=%s "
            "AND engagement_id=%s AND scope_id=%s AND register_key=%s ORDER BY version DESC",
            (client_id, engagement_id, scope_id, kind),
        )
        return [dict(row) for row in cursor.fetchall()]


def save_version(
    client_name: str,
    engagement_id: int,
    scope_id: int,
    kind: str,
    records: list[dict[str, Any]],
    *,
    actor: str,
    owner: str,
    status: str,
    expected_version: int,
    note: str = "",
) -> int:
    """Append a formal revision, enforcing review, ownership and freshness.

    Args:
        client_name: Tenant.
        engagement_id: Engagement.
        scope_id: Scope definition.
        kind: Policy, objectives or risks.
        records: Edited rows (risk snapshots are always re-read from the DB).
        actor: Trusted current principal.
        owner: Accountable document owner.
        status: Requested lifecycle transition.
        expected_version: Revision last read by the editor.
        note: Human review rationale.
    Returns:
        New revision number.
    Raises:
        FoundationError: On authorization, validation or a stale edit.
    """
    if kind not in {"policy", "objectives", "risks"} or not owner.strip():
        raise FoundationError("A valid register and owner are required.")
    with workspace_cursor(client_name) as (cursor, client_id):
        cursor.execute(
            (
                "SELECT 1 FROM securescope_scope_definitions WHERE client_id=%s "
                "AND engagement_id=%s AND id=%s"
            ),
            (client_id, engagement_id, scope_id),
        )
        if not cursor.fetchone():
            raise FoundationError("Scope does not belong to this engagement.")
        role = member_role(cursor, client_id, actor)
        cursor.execute(
            "SELECT * FROM securescope_foundation_versions WHERE client_id=%s AND engagement_id=%s "
            "AND scope_id=%s AND register_key=%s ORDER BY version DESC LIMIT 1",
            (client_id, engagement_id, scope_id, kind),
        )
        previous = cursor.fetchone()
        if (
            kind == "policy"
            and previous
            and any(row.get("policy_id") for row in previous["records"])
        ):
            raise FoundationError(
                "Use the Policy workspace to preserve individual policy review states."
            )
        actual = previous["version"] if previous else 0
        if actual != expected_version:
            raise FoundationError("Another user changed this register. Reload before saving.")
        try:
            next_status(previous["status"] if previous else "Not started", status, role, note)
        except ValueError as exc:
            raise FoundationError(str(exc)) from exc
        if status == "Approved" and owner.strip() != previous["owner"]:
            raise FoundationError("Reviewed owner changed. Save a new draft before approval.")
        if kind == "risks":
            cursor.execute(
                "SELECT * FROM securescope_risk_register WHERE client_id=%s ORDER BY risk_ref",
                (client_id,),
            )
            records = [dict(row) for row in cursor.fetchall()]
            if status == "Approved" and risk_signature(records) != risk_signature(
                previous["records"]
            ):
                raise FoundationError(
                    "Risks changed after review. Save a new draft and review again."
                )
            # Preserve only native JSON values; the canonical risk table is untouched.
            import json

            records = json.loads(json.dumps(records, default=str))
        elif status == "Approved":
            if records != previous["records"] or owner != previous["owner"]:
                raise FoundationError("Reviewed content changed. Save a new draft before approval.")
        if status in {"In review", "Approved"}:
            try:
                validate_records(kind, records)
            except (ValueError, TypeError) as exc:
                raise FoundationError(str(exc)) from exc
        cursor.execute(
            "INSERT INTO securescope_foundation_versions "
            "(client_id, engagement_id, scope_id, register_key, version, "
            "status, records, owner, recorded_by, review_note, approved_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                client_id,
                engagement_id,
                scope_id,
                kind,
                actual + 1,
                status,
                Json(records),
                owner.strip(),
                actor,
                note.strip(),
                actor if status == "Approved" else None,
            ),
        )
        return actual + 1
