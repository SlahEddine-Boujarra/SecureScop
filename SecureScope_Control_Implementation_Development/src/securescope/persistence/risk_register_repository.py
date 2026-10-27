"""Client-isolated risk register persistence with optimistic updates."""

from __future__ import annotations

from typing import Any, Mapping

from psycopg2.extras import Json, RealDictCursor

from securescope.grc.risk_register import risk_row_with_scores, starter_risks
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.migration_service import run_pending_migrations


def _client_id(cursor: Any, client_name: str) -> int:
    cursor.execute("SELECT id FROM securescope_clients WHERE name = %s;", (client_name,))
    row = cursor.fetchone()
    if not row:
        raise GrcRepositoryError(f"Client workspace not found: {client_name}")
    return int(row["id"] if isinstance(row, Mapping) else row[0])


def list_risk_register(client_name: str) -> list[dict[str, Any]]:
    """Return workspace risks with derived scores and levels."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    (
                        "SELECT r.*, d.payload AS lifecycle_payload "
                        "FROM securescope_risk_register r "
                        "LEFT JOIN securescope_workspace_records d ON d.client_id=r.client_id "
                        "AND d.kind='risk_detail' AND d.record_key=r.risk_ref::text "
                        "WHERE r.client_id = %s ORDER BY r.risk_ref;"
                    ),
                    (client_id,),
                )
                from securescope.grc.risk_lifecycle import EXTRA_FIELDS
                from securescope.persistence.workspace_planning import protect_text

                records = []
                for stored in cursor.fetchall():
                    row = dict(stored)
                    metadata = protect_text(row.pop("lifecycle_payload", None) or {}, decrypt=True)
                    row.update({key: metadata[key] for key in EXTRA_FIELDS if key in metadata})
                    records.append(risk_row_with_scores(row))
                return records
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def save_risk_record(
    client_name: str,
    record: Mapping[str, Any],
    *,
    actor: str,
    expected_revision: int = 0,
    authorize=None,
    after_save=None,
    allow_incomplete: bool = False,
) -> int:
    """Insert or update one risk record and return its new revision."""

    return save_risk_records(
        client_name,
        [dict(record)],
        actor=actor,
        expected_revisions={int(record.get("risk_ref") or 0): expected_revision},
        authorize=authorize,
        after_save=after_save,
        allow_incomplete=allow_incomplete,
    )[int(record["risk_ref"])]


def save_risk_records(
    client_name: str,
    records: list[dict[str, Any]],
    *,
    actor: str,
    expected_revisions: dict[int, int],
    authorize=None,
    after_save=None,
    allow_incomplete: bool = False,
) -> dict[int, int]:
    """Save multiple asset risks atomically with optimistic revision checks.

    Args:
        client_name: Exact client workspace.
        records: Asset risk rows to insert or update.
        actor: Recorder identity.
        expected_revisions: Reference-to-revision mapping, zero for new records.
        authorize: Optional existing permission callback inside the transaction.
        after_save: Optional related-record writer inside the same transaction.
        allow_incomplete: Preserve identified partial draft rows.
    Returns:
        New revision numbers keyed by risk reference.
    Raises:
        ValueError: If input records or recorder are invalid.
        GrcRepositoryError: On a stale revision or database error.
    """
    from securescope.grc.document_registers import (
        ASSET_FIELDS,
        CALCULATED_FIELDS,
        normalize_register_rows,
    )

    clean = normalize_register_rows("asset_risks", records, preserve_incomplete=allow_incomplete)
    if not actor.strip():
        raise ValueError("Recorded by is required.")
    columns = [key for key in ASSET_FIELDS if key not in CALCULATED_FIELDS and key != "risk_ref"]
    columns += ["revision", "updated_by"]
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE id = %s FOR UPDATE", (client_id,)
                )
                if authorize is not None:
                    authorize(cursor, client_id)
                revisions = {}
                for record in clean:
                    risk_ref = int(record["risk_ref"])
                    cursor.execute(
                        "SELECT revision FROM securescope_risk_register "
                        "WHERE client_id = %s AND risk_ref = %s FOR UPDATE",
                        (client_id, risk_ref),
                    )
                    old = cursor.fetchone()
                    actual = int(old["revision"]) if old else 0
                    if expected_revisions.get(risk_ref) != actual:
                        raise GrcRepositoryError(f"Risk {risk_ref} changed. Reload the register.")
                    record["revision"] = actual + 1
                    record["updated_by"] = actor.strip()
                    record["risk_type"] = record.get("risk_type") or "C"
                    record["treatment_option"] = record.get("treatment_option") or "Modify"
                    record["treatment_action_status"] = (
                        record.get("treatment_action_status") or "Not Started"
                    )
                    references = record.get("control_references") or []
                    if isinstance(references, str):
                        references = [
                            item.strip()
                            for item in references.replace("\n", ",").split(",")
                            if item.strip()
                        ]
                    record["control_references"] = Json(references)
                    nullable = {
                        "pre_likelihood",
                        "pre_impact",
                        "post_likelihood",
                        "post_impact",
                        "treatment_cost",
                    }
                    values = [
                        (
                            record.get(key)
                            if key in nullable
                            else (record[key] if record.get(key) is not None else "")
                        )
                        for key in columns
                    ]
                    column_sql = ", ".join(columns)
                    placeholder_sql = ", ".join(["%s"] * (len(columns) + 2))
                    cursor.execute(
                        "INSERT INTO securescope_risk_register "
                        f"(client_id, risk_ref, {column_sql}) "
                        f"VALUES ({placeholder_sql}) "
                        "ON CONFLICT (client_id, risk_ref) DO UPDATE SET "
                        + ", ".join(f"{key} = EXCLUDED.{key}" for key in columns)
                        + ", updated_at = NOW()",
                        [client_id, risk_ref, *values],
                    )
                    cursor.execute(
                        "INSERT INTO securescope_audit_events "
                        "(client_id, event_type, entity_type, entity_id, actor, summary, "
                        "before_state, after_state) "
                        "VALUES (%s, 'risk.updated', 'asset_risk', %s, %s, %s, %s, %s)",
                        (
                            client_id,
                            str(risk_ref),
                            actor.strip(),
                            "Risk register updated",
                            Json({"revision": actual}),
                            Json({"revision": actual + 1}),
                        ),
                    )
                    revisions[risk_ref] = actual + 1
                if after_save is not None:
                    after_save(cursor, client_id, revisions)
                return revisions
    except DatabaseError as exc:
        raise GrcRepositoryError(
            "No risks were saved. Check the input and PostgreSQL connection."
        ) from exc


def seed_starter_risks(client_name: str, *, actor: str = "securescope-ui") -> int:
    """Insert starter examples as one transaction when the register is empty.

    Args:
        client_name: Exact client workspace name.
        actor: Identity recording the seed operation.
    Returns:
        Number of inserted examples, or zero for an existing register.
    Raises:
        ValueError: If a starter record or recorder is invalid.
        GrcRepositoryError: If any row conflicts or persistence fails. The
            complete seed transaction is rolled back in that case.
    """

    if list_risk_register(client_name):
        return 0
    records = starter_risks()
    revisions = save_risk_records(
        client_name,
        records,
        actor=actor,
        expected_revisions={int(row["risk_ref"]): 0 for row in records},
    )
    return len(revisions)
