"""Transactional register placement and tenant-validated impacted assets."""

from __future__ import annotations

from psycopg2.extras import Json

from securescope.grc.risk_lifecycle import workflow_fields
from securescope.persistence.foundation_repository import (
    FoundationError,
    member_role,
    workspace_cursor,
)
from securescope.persistence.risk_register_repository import save_risk_record
from securescope.persistence.workspace_planning import EDITORS, protect_text


def discovered_assets(client: str, actor: str) -> list[dict]:
    """Read the authorized client's committed discovered inventory.

    Args:
        client: Exact workspace name.
        actor: Trusted session principal.
    Returns:
        Inventory IDs, tags and IP addresses.
    Raises:
        FoundationError: When membership is missing.
    """
    with workspace_cursor(client) as (cursor, client_id):
        if not member_role(cursor, client_id, actor):
            raise FoundationError("Workspace membership is required.")
        cursor.execute(
            (
                "SELECT id,asset_tag,ip FROM securescope_assets WHERE client_id=%s"
                " ORDER BY asset_tag,ip"
            ),
            (client_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def save_assessment(
    client: str,
    record: dict,
    *,
    actor: str,
    revision: int,
    group: str,
    metadata_revision: int,
    asset_ids: list[int],
    complete: bool = False,
) -> None:
    """Save the risk and its register/asset links in the same transaction.

    Args:
        client: Active workspace.
        record: Canonical risk inputs.
        actor: Trusted principal.
        revision: Observed assessment revision.
        group: Selected register identity.
        metadata_revision: Observed supporting-record revision.
        asset_ids: IDs from the client's committed inventory.
        complete: Enforce required fields and mark this revision complete, not approved.
    Returns:
        None.
    Raises:
        FoundationError: For denied, stale or cross-client links.
        ValueError: For invalid assessment inputs.
    """
    if (
        not isinstance(asset_ids, list)
        or len(asset_ids) > 1000
        or any(type(v) is not int for v in asset_ids)
    ):
        raise FoundationError("Choose valid inventory assets.")
    scope_id = record.get("primary_scope_id")
    if scope_id is not None and (type(scope_id) is not int or scope_id <= 0):
        raise FoundationError("Select a valid ISMS scope or Unassigned scope.")
    extra = workflow_fields(record, complete=complete)
    metadata = {}
    selected_ips = []

    def authorize(cursor, client_id):
        """Validate all supporting links on the locked workspace transaction."""
        if member_role(cursor, client_id, actor) not in EDITORS:
            raise FoundationError("Contributor membership is required.")
        if scope_id is not None:
            cursor.execute(
                "SELECT s.id FROM securescope_scope_definitions s WHERE s.client_id=%s AND s.id=%s "
                "AND (NOT s.archived OR EXISTS (SELECT 1 FROM securescope_risk_register r "
                "WHERE r.client_id=s.client_id AND r.primary_scope_id=s.id AND r.risk_ref=%s))",
                (client_id, scope_id, record["risk_ref"]),
            )
            if not cursor.fetchone():
                raise FoundationError("The selected ISMS scope is outside this client or archived.")
        if record.get("treatment_action_status") == "Accepted risk":
            cursor.execute(
                "SELECT treatment_action_status FROM securescope_risk_register WHERE "
                "client_id=%s AND risk_ref=%s",
                (client_id, record["risk_ref"]),
            )
            previous = cursor.fetchone()
            if not previous or previous["treatment_action_status"] != "Accepted risk":
                raise FoundationError(
                    "Formal risk acceptance is Coming Soon. Record a treatment decision "
                    "without claiming approval."
                )
        cursor.execute(
            "SELECT control_id FROM securescope_control_assessment_profiles WHERE client_id=%s",
            (client_id,),
        )
        known = {r["control_id"] for r in cursor.fetchall()}
        refs = record.get("control_references") or []
        if isinstance(refs, str):
            refs = [r.strip() for r in refs.replace("\n", ",").split(",") if r.strip()]
        if not (set(refs) | set(extra.get("existing_control_references", []))).issubset(known):
            raise FoundationError("Select controls from this workspace.")
        if group != "default":
            cursor.execute(
                (
                    "SELECT 1 FROM securescope_workspace_records WHERE client_id=%s "
                    "AND kind='risk_group' AND record_key=%s"
                ),
                (client_id, group),
            )
            if not cursor.fetchone():
                raise FoundationError("The selected register no longer exists.")
        cursor.execute(
            "SELECT id,ip FROM securescope_assets WHERE client_id=%s AND id=ANY(%s)",
            (client_id, asset_ids),
        )
        selected = cursor.fetchall()
        selected_ips.extend(r["ip"] for r in selected)
        if {r["id"] for r in selected} != set(asset_ids):
            raise FoundationError(
                "An impacted asset does not belong to this workspace or was removed."
            )
        cursor.execute(
            (
                "SELECT revision,payload FROM securescope_workspace_records WHERE "
                "client_id=%s AND kind='risk_detail' AND record_key=%s"
            ),
            (client_id, str(record["risk_ref"])),
        )
        old = cursor.fetchone()
        if int(old["revision"] if old else 0) != metadata_revision:
            raise FoundationError("Risk links changed in another session. Reload before saving.")
        metadata.update(protect_text(old["payload"], decrypt=True) if old else {})
        cursor.execute("SELECT ip FROM securescope_assets WHERE client_id=%s", (client_id,))
        current_ips = {r["ip"] for r in cursor.fetchall()}
        selected_ips.extend(ip for ip in metadata.get("asset_ips", []) if ip not in current_ips)

    def after_save(cursor, client_id, revisions):
        """Persist links only after the canonical write, before transaction commit."""
        if "primary_scope_id" in record:
            cursor.execute(
                "SELECT primary_scope_id FROM securescope_risk_register WHERE client_id=%s AND "
                "risk_ref=%s",
                (client_id, record["risk_ref"]),
            )
            previous_scope = cursor.fetchone()["primary_scope_id"]
            cursor.execute(
                "UPDATE securescope_risk_register SET primary_scope_id=%s WHERE client_id=%s "
                "AND risk_ref=%s",
                (scope_id, client_id, record["risk_ref"]),
            )
            if previous_scope != scope_id:
                cursor.execute(
                    "INSERT INTO securescope_audit_events "
                    "(client_id,event_type,entity_type,entity_id,actor,summary,before_state,aft"
                    "er_state) "
                    "VALUES (%s,'risk.scope_changed','asset_risk',%s,%s,%s,%s,%s)",
                    (
                        client_id,
                        str(record["risk_ref"]),
                        actor,
                        "Risk ISMS scope changed",
                        Json({"primary_scope_id": previous_scope}),
                        Json({"primary_scope_id": scope_id}),
                    ),
                )
        metadata.update(extra)
        metadata.update(
            completion_state="Completed" if complete else "Draft",
            completed_revision=revisions[record["risk_ref"]] if complete else None,
            risk_ref=record["risk_ref"],
            group=group,
            asset_ids=list(dict.fromkeys(asset_ids)),
            asset_ips=list(dict.fromkeys(selected_ips)),
            review_state="Draft",
            reviewed_revision=revisions[record["risk_ref"]],
        )
        cursor.execute(
            (
                (
                    "INSERT INTO securescope_workspace_records "
                    "(client_id,kind,record_key,payload,updated_by) VALUES "
                    "(%s,'risk_detail',%s,%s,%s) ON "
                    "CONFLICT(client_id,kind,record_key) DO UPDATE SET "
                    "payload=EXCLUDED.payload,revision=securescope_workspace_reco"
                    "rds.revision+1,updated_by=EXCLUDED.updated_by,updated_at=NOW"
                    "()"
                )
            ),
            (client_id, str(record["risk_ref"]), Json(protect_text(metadata)), actor),
        )

    clean = dict(record, residual_verified=False, residual_evidence="", residual_verified_by="")
    save_risk_record(
        client,
        clean,
        actor=actor,
        expected_revision=revision,
        authorize=authorize,
        after_save=after_save,
        allow_incomplete=not complete,
    )


def risk_scope_options(client: str, actor: str) -> list[dict]:
    """Load selectable scope relationships owned by this client.

    Args:
        client: Active workspace name.
        actor: Trusted session identity.
    Returns:
        list[dict]: Stable scope IDs and readable engagement/scope labels.
    Raises:
        FoundationError: When workspace membership is absent.
    """
    with workspace_cursor(client) as (cursor, client_id):
        if not member_role(cursor, client_id, actor):
            raise FoundationError("Workspace membership is required.")
        cursor.execute(
            "SELECT s.id,s.name,s.archived,e.name AS engagement_name FROM "
            "securescope_scope_definitions s "
            "JOIN securescope_engagements e ON e.client_id=s.client_id AND e.id=s.engagement_id "
            "WHERE s.client_id=%s ORDER BY e.name,s.name,s.id",
            (client_id,),
        )
        return [dict(row) for row in cursor.fetchall()]
