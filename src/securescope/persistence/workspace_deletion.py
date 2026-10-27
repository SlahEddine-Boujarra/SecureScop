"""Explicit, administrator-only deletion of one client workspace."""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass

from psycopg2 import sql
from psycopg2.extras import Json

from securescope.evidence.storage import evidence_root
from securescope.persistence.foundation_repository import (
    FoundationError,
    member_role,
    workspace_cursor,
)

LOGGER = logging.getLogger(__name__)
JOB_TABLES = ("securescope_nuclei_jobs", "securescope_openvas_jobs", "securescope_evidence_jobs")
TERMINAL = (
    "Completed",
    "Done",
    "Failed",
    "Cancelled",
    "Canceled",
    "Error",
    "Stopped",
    "Archived",
    "Completed with errors",
    "Recovered report",
)


@dataclass(frozen=True)
class DeletionResult:
    """Committed deletion outcome and any host cleanup required."""

    remaining: list[str]
    cleanup_warning: str = ""


def delete_workspace(
    client: str, *, actor: str, expected_id: int, confirm_data: bool, confirm_permanent: bool
) -> DeletionResult:
    """Delete one authorized workspace and its local evidence directory.

    Args:
        client: Exact selected workspace name.
        actor: Trusted session principal.
        expected_id: Workspace ID shown in the confirmation UI.
        confirm_data: Confirms the selected workspace and dependent records.
        confirm_permanent: Confirms permanent loss and backup responsibility.
    Returns:
        Remaining workspace names and a visible local cleanup warning, if needed.
    Raises:
        FoundationError: If checks fail or nonterminal jobs are present.
    """
    if confirm_data is not True or confirm_permanent is not True:
        raise FoundationError("Both deletion confirmations are required.")
    with workspace_cursor(client) as (cursor, client_id):
        if client_id != expected_id:
            raise FoundationError("The selected workspace changed. Review the deletion again.")
        if member_role(cursor, client_id, actor) != "Administrator":
            raise FoundationError("Only an Administrator of this workspace can delete it.")
        for table in JOB_TABLES:
            cursor.execute("SELECT to_regclass(%s) AS relation", (table,))
            if cursor.fetchone()["relation"]:
                cursor.execute(
                    sql.SQL(
                        (
                            "SELECT 1 FROM {} WHERE client_id=%s AND (status IS NULL OR NOT "
                            "(status = ANY(%s))) LIMIT 1"
                        )
                    ).format(sql.Identifier(table)),
                    (client_id, list(TERMINAL)),
                )
                if cursor.fetchone():
                    raise FoundationError(
                        (
                            "Finish or cancel active/queued scan and evidence jobs before "
                            "deleting this workspace."
                        )
                    )
        cursor.execute(
            (
                "INSERT INTO securescope_admin_audit_events "
                "(event_type,deleted_client_id,workspace_name,actor,summary) "
                "VALUES (%s,%s,%s,%s,%s)"
            ),
            (
                "workspace.deleted",
                client_id,
                client,
                actor,
                Json({"confirm_data": True, "confirm_permanent": True}),
            ),
        )
        cursor.execute(
            "DELETE FROM securescope_clients WHERE id=%s AND name=%s", (client_id, client)
        )
        if cursor.rowcount != 1:
            raise FoundationError("Workspace was already removed.")
        cursor.execute("SELECT name FROM securescope_clients ORDER BY lower(name)")
        remaining = [row["name"] for row in cursor.fetchall()]
    warning = ""
    directory = evidence_root() / str(client_id)
    if directory.is_symlink():
        warning = (
            "Workspace records were deleted, but the host administrator must "
            "remove the linked evidence directory."
        )
        LOGGER.error(
            "Skipped unsafe evidence directory symlink for deleted workspace %s", client_id
        )
    elif directory.is_dir():
        try:
            shutil.rmtree(directory)
        except OSError:
            warning = (
                "Workspace records were deleted, but local evidence cleanup "
                "failed. Ask the host administrator to complete removal."
            )
            LOGGER.exception(
                "Database workspace %s deleted; local evidence cleanup requires host attention",
                client_id,
            )
    return DeletionResult(remaining, warning)
