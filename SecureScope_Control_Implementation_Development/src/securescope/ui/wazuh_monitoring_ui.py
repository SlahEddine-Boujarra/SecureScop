"""Small existing-app surfaces for approved Wazuh bindings and source inspection."""

import streamlit as st

from securescope.integrations.wazuh_service import WazuhClient, WazuhError, require_connector_admin
from securescope.persistence.db_wazuh_service import (
    WazuhDatabaseError,
    approve_monitoring_binding,
    list_monitoring_bindings,
    load_latest_wazuh_status,
    revoke_monitoring_binding,
)


def render_monitoring_bindings(client_name: str, actor: str) -> None:
    """Render an administrator-only identity/policy editor without scope inference.

    Args:
        client_name: Active workspace; actor: existing server identity.
    Returns:
        None; explicit submitted forms call authorized repository methods.
    Raises:
        No expected connector/repository exceptions escape the UI boundary.
    """
    try:
        require_connector_admin(client_name, actor)
    except WazuhError:
        st.caption("A connector administrator must approve exact asset/agent bindings.")
        return
    try:
        client = WazuhClient()
        assets = load_latest_wazuh_status(client_name)
        bindings = list_monitoring_bindings(client_name, client.connector_id)
        if not assets:
            st.info("Admit an inventory asset before linking an agent.")
            return
        st.caption(
            "Confirm ownership using your Wazuh inventory. Linking an agent "
            "does not assign ISMS scope."
        )
        labels = {
            r["asset_id"]: f"{r.get('asset_tag') or r['asset_id']} · {r['asset_ip']}"
            for r in assets
        }
        with st.form(f"wazuh_binding::{client_name}"):
            asset_id = st.selectbox("Inventory asset", list(labels), format_func=labels.get)
            manager_name = st.text_input("Exact Wazuh manager name")
            agent_id = st.text_input("Exact agent ID", placeholder="007")
            heartbeat_age = st.number_input(
                "Heartbeat / collection freshness (seconds)", 1, 604800, 300
            )
            telemetry_age = st.number_input("Telemetry freshness (seconds)", 1, 31536000, 3600)
            st.caption(
                "Choose and approve these policy windows for this asset; the "
                "shown values are suggestions."
            )
            rationale = st.text_area("Identity and policy approval rationale")
            confirmed = st.checkbox(
                "I verified this manager and agent belong to the selected workspace asset."
            )
            submitted = st.form_submit_button("Approve agent binding")
        if submitted:
            if not confirmed:
                st.warning("Confirm the exact asset/agent identity before approving.")
            else:
                approve_monitoring_binding(
                    client_name,
                    actor,
                    asset_id=asset_id,
                    connector_id=client.connector_id,
                    manager_name=manager_name,
                    agent_id=agent_id,
                    heartbeat_max_age_seconds=int(heartbeat_age),
                    telemetry_max_age_seconds=int(telemetry_age),
                    rationale=rationale,
                )
                st.success("Binding approved. Collect evidence to verify telemetry.")
                st.rerun()
        if bindings:
            st.dataframe(
                [
                    {
                        k: row[k]
                        for k in (
                            "id",
                            "asset_id",
                            "manager_name",
                            "agent_id",
                            "approved_by",
                            "approved_at",
                        )
                    }
                    for row in bindings
                ],
                hide_index=True,
            )
            with st.form(f"wazuh_revoke::{client_name}"):
                binding_id = st.selectbox("Binding to revoke", [b["id"] for b in bindings])
                reason = st.text_input("Revocation reason")
                revoke = st.form_submit_button("Revoke binding")
            if revoke:
                revoke_monitoring_binding(client_name, actor, binding_id, reason)
                st.success("Binding revoked. Source history and human assessments were preserved.")
                st.rerun()
    except (WazuhError, WazuhDatabaseError) as exc:
        st.error(str(exc))


def render_monitoring_detail(rows: list[dict], client_name: str) -> None:
    """Show a selected asset's factual source state and provenance.

    Args:
        rows: Workspace-scoped monitoring facts; client_name: UI key namespace.
    Returns:
        None.
    Raises:
        No expected exceptions for repository-generated rows.
    """
    if not rows:
        return
    with st.expander("Inspect monitoring evidence"):
        selected = st.selectbox(
            "Asset",
            range(len(rows)),
            key=f"wazuh_detail::{client_name}",
            format_func=lambda i: str(rows[i].get("asset_tag") or rows[i]["asset_ip"]),
        )
        row = rows[selected]
        st.write(row["monitoring_status"])
        st.caption(row["monitoring_reason"])
        keys = (
            "asset_id",
            "binding_id",
            "manager_name",
            "wazuh_agent_id",
            "wazuh_status",
            "source_health",
            "collected_at",
            "wazuh_last_keep_alive",
            "last_verified_at",
            "verified_until",
            "heartbeat_max_age_seconds",
            "telemetry_max_age_seconds",
            "payload_sha256",
            "source_key",
        )
        st.table(
            [
                {"Field": key.replace("_", " "), "Value": str(row.get(key) or "Not available")}
                for key in keys
            ]
        )
        telemetry = row.get("telemetry") or {}
        st.caption(f"Source event: {telemetry.get('source_event_id') or 'Not available'}")
        st.caption(
            "This is source verification. ISO implementation and "
            "effectiveness require human assessment."
        )


def render_collection_schedules(client_name: str, actor: str) -> None:
    """Render small schedule approval and operational controls in the existing Wazuh screen.

    Args:
        client_name, actor: Existing server-side context.
    Returns:
        None. Changes use shared authorized repository methods.
    Raises:
        Expected permission/database failures are displayed without source data.
    """
    from securescope.integrations.wazuh_service import configured_connector_id
    from securescope.persistence import evidence_schedule_repository as schedules
    from securescope.persistence.db_service import DatabaseError

    with st.expander("Recurring evidence collection"):
        st.caption(
            "Development opt-in only. Production collection remains disabled pending security gates."
        )
        try:
            rows = schedules.list_schedules(client_name, actor)
            if rows:
                chosen = st.selectbox(
                    "Collection schedule",
                    [r["id"] for r in rows],
                    format_func=lambda i: next(
                        r["name"] + f" · revision {r['revision']}" for r in rows if r["id"] == i
                    ),
                )
                row = next(r for r in rows if r["id"] == chosen)
                st.write(
                    "Enabled"
                    if row["enabled"]
                    else "Paused: " + (row["pause_reason"] or "Awaiting enablement")
                )
                st.caption(
                    f"Next due: {row['next_run_at']} · missed polls: {row['missed_occurrences']}"
                )
                st.caption(
                    f"Last attempt: {row['last_attempt']} · last successful collection: {row['last_success']} · "
                    f"queue delay: {row['queue_lag_seconds']} seconds · failed jobs since success: {row['failed_since_success']}"
                )
                if st.button("Run now", disabled=not row["enabled"]):
                    st.success(
                        f"Queued collection {schedules.queue_now(client_name, actor, chosen)}"
                    )
                if st.button("Pause schedule" if row["enabled"] else "Enable schedule"):
                    schedules.set_enabled(client_name, actor, chosen, not row["enabled"])
                    st.rerun()
                st.dataframe(row["jobs"], hide_index=True)
                if row["jobs"]:
                    history_job = st.selectbox("Collection history", [j["id"] for j in row["jobs"]])
                    history = schedules.job_history(client_name, actor, history_job)
                    st.dataframe(history["attempts"], hide_index=True)
                    st.dataframe(history["targets"], hide_index=True)
                    if history["results"]:
                        st.write("Canonical evidence", history["results"])
                pending = [j["id"] for j in row["jobs"] if j["status"] in {"Queued", "Running"}]
                if pending:
                    cancel = st.selectbox("Collection to cancel", pending)
                    if st.button("Cancel collection"):
                        schedules.cancel_job(client_name, actor, cancel)
                        st.rerun()
            try:
                require_connector_admin(client_name, actor)
            except WazuhError:
                return
            candidates = schedules.schedule_candidates(client_name, actor)
            if not candidates:
                st.info(
                    "Review an A.8.15 or A.8.16 Control Profile with explicit bound assets in an approved scope first."
                )
                return
            replaces = (
                chosen
                if rows
                and st.checkbox("Replace the selected schedule with a new reviewed revision")
                else None
            )
            selected = st.multiselect(
                "Approved requirements and assets",
                range(len(candidates)),
                format_func=lambda i: candidates[i]["label"],
            )
            name = st.text_input("Schedule name", "Wazuh evidence collection")
            interval = st.number_input("Collection interval (seconds)", 30, 604800, 60)
            attempts = st.number_input("Maximum attempts per collection", 1, 5, 3)
            allow_health = st.checkbox(
                "Use approved collection-health proof for quiet agents",
                help="Each selected requirement must explicitly allow collection-health proof.",
            )
            policy = {}
            if allow_health:
                mode = st.selectbox("Health source", ["canary", "archive"])
                index = st.text_input("Approved archive index pattern", "wazuh-archives-*")
                channel = st.text_input("Exact approved source channel")
                age = st.number_input("Maximum health proof age (seconds)", 1, 86400, 120)
                policy = dict(
                    schema_version=1,
                    mode=mode,
                    index_pattern=index,
                    channel=channel,
                    max_age_seconds=int(age),
                )
            approved = st.checkbox(
                "I approve these exact assets, scope and profile versions, source policy and collection cadence."
            )
            if st.button("Create approved schedule", disabled=not approved or not selected):
                targets = [
                    dict(candidates[i], accept_health=allow_health, health_policy=policy)
                    for i in selected
                ]
                schedules.create_schedule(
                    client_name,
                    actor,
                    name=name,
                    connector_id=configured_connector_id(),
                    targets=targets,
                    interval_seconds=int(interval),
                    max_attempts=int(attempts),
                    replaces=replaces,
                )
                st.success("Schedule created disabled. Review it, then enable collection.")
                st.rerun()
        except (schedules.ScheduleError, DatabaseError, WazuhError, ValueError) as exc:
            st.error(str(exc))
