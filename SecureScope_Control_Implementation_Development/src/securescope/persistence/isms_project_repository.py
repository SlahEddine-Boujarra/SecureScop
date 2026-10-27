"""PostgreSQL project plans with workspace ownership and optimistic updates."""

from __future__ import annotations

import json
import logging
from typing import Any

from psycopg2.extras import Json, RealDictCursor

from securescope.grc.isms_project_plan import TASK_METADATA, ProjectTaskUpdate
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.migration_service import run_pending_migrations

LOGGER = logging.getLogger(__name__)


class ProjectPlanError(RuntimeError):
    """Signal an unavailable workspace, persistence failure or stale update."""


def _client_id(cursor: Any, client_name: str) -> int:
    """Resolve a workspace within an existing database transaction.

    Args:
        cursor: Active dictionary cursor.
        client_name: Exact workspace name.

    Returns:
        Existing client identifier.

    Raises:
        ProjectPlanError: If the workspace does not exist.
    """

    cursor.execute("SELECT id FROM securescope_clients WHERE name = %s;", (client_name,))
    row = cursor.fetchone()
    if not row:
        raise ProjectPlanError("The selected client workspace no longer exists.")
    return int(row["id"])


def load_project_plan(client_name: str) -> dict[str, list[dict[str, Any]]]:
    """Read saved task fields and recent changes for one workspace.

    Args:
        client_name: Exact active client workspace name.

    Returns:
        Saved task rows and twenty recent audit events. Unsaved defaults are
        supplied by the domain model, so viewing a plan does not create tasks.

    Raises:
        ProjectPlanError: If workspace resolution or database reads fail.
        MigrationError: If a required additive migration fails.
    """

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT * FROM securescope_isms_project_tasks "
                    "WHERE client_id = %s ORDER BY task_ref;",
                    (client_id,),
                )
                tasks = [dict(row) for row in cursor.fetchall()]
                cursor.execute(
                    "SELECT task_ref, revision, actor, created_at "
                    "FROM securescope_isms_project_events WHERE client_id = %s "
                    "ORDER BY created_at DESC, id DESC LIMIT 20;",
                    (client_id,),
                )
                return {"tasks": tasks, "events": [dict(row) for row in cursor.fetchall()]}
    except DatabaseError as exc:
        LOGGER.error("ISMS project plan read failed for %s: %s", client_name, exc)
        raise ProjectPlanError("Project plan could not be loaded. Check PostgreSQL.") from exc


def save_project_task(
    client_name: str,
    task_ref: int,
    update: ProjectTaskUpdate,
    *,
    actor: str,
    expected_revision: int,
) -> int:
    """Save one task and its audit event in a single transaction.

    Args:
        client_name: Exact active client workspace.
        task_ref: Editable template reference; task 15 is a computed summary.
        update: Validated task fields.
        actor: Name supplied by the person recording this change.
        expected_revision: Revision seen when the editing form was opened.

    Returns:
        New positive revision number.

    Raises:
        ValueError: If input fields or the task reference are invalid.
        ProjectPlanError: If ownership, concurrent revision or persistence fails.
        MigrationError: If a required migration fails.
    """

    return save_project_tasks(client_name, {task_ref: (update, expected_revision)}, actor=actor)[
        task_ref
    ]


def save_project_tasks(
    client_name: str,
    updates: dict[int, tuple[ProjectTaskUpdate, int]],
    *,
    actor: str,
) -> dict[int, int]:
    """Save a reviewed batch atomically with a revision check on every task.

    Args:
        client_name: Exact workspace name.
        updates: Task references mapped to validated fields and expected revision.
        actor: Person recording the changes.
    Returns:
        New revisions keyed by task reference.
    Raises:
        ValueError: If any task, actor or revision is invalid.
        ProjectPlanError: If a concurrent update or database failure occurs.
    """
    if not actor.strip() or len(actor) > 250:
        raise ValueError("Updated by is required (maximum 250 characters).")
    for task_ref, (update, expected_revision) in updates.items():
        update.validate()
        if task_ref not in TASK_METADATA or task_ref == 15:
            raise ValueError("Task 15 is calculated; choose an editable task.")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Task revision is invalid. Reload the plan.")
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT id FROM securescope_clients WHERE id = %s FOR UPDATE;",
                    (client_id,),
                )
                revisions = {}
                for task_ref, (update, expected_revision) in sorted(updates.items()):
                    cursor.execute(
                        "SELECT * FROM securescope_isms_project_tasks "
                        "WHERE client_id = %s AND task_ref = %s FOR UPDATE;",
                        (client_id, task_ref),
                    )
                    previous = cursor.fetchone()
                    actual_revision = int(previous["revision"]) if previous else 0
                    if actual_revision != expected_revision:
                        raise ProjectPlanError(
                            "This task changed since the form was opened. "
                            "Reload the saved task before editing again."
                        )
                    revision = actual_revision + 1
                    cursor.execute(
                        (
                            "\n                        INSERT INTO "
                            "securescope_isms_project_tasks (\n                           "
                            " client_id, task_ref, resource, start_date, work_days,\n     "
                            "                       completed_days, notes, revision, "
                            "updated_by\n                        ) VALUES (%s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s)\n                        ON CONFLICT "
                            "(client_id, task_ref) DO UPDATE SET\n                        "
                            "    resource = EXCLUDED.resource, start_date = "
                            "EXCLUDED.start_date,\n                            work_days "
                            "= EXCLUDED.work_days, completed_days = "
                            "EXCLUDED.completed_days,\n                            notes "
                            "= EXCLUDED.notes, revision = EXCLUDED.revision,\n            "
                            "                updated_by = EXCLUDED.updated_by, "
                            "updated_at = NOW()\n                        RETURNING *;\n    "
                            "                    "
                        ),
                        (
                            client_id,
                            task_ref,
                            update.resource.strip(),
                            update.start_date,
                            update.work_days,
                            update.completed_days,
                            update.notes.strip(),
                            revision,
                            actor.strip(),
                        ),
                    )
                    current = dict(cursor.fetchone())
                    before = json.loads(json.dumps(dict(previous or {}), default=str))
                    after = json.loads(json.dumps(current, default=str))
                    cursor.execute(
                        """
                        INSERT INTO securescope_isms_project_events (
                            client_id, task_ref, revision, actor, before_state, after_state
                        ) VALUES (%s, %s, %s, %s, %s, %s);
                        """,
                        (client_id, task_ref, revision, actor.strip(), Json(before), Json(after)),
                    )
                    revisions[task_ref] = revision
                return revisions
    except DatabaseError as exc:
        LOGGER.error("Project plan batch write failed for %s: %s", client_name, exc)
        raise ProjectPlanError("No tasks were saved. Check PostgreSQL and try again.") from exc
