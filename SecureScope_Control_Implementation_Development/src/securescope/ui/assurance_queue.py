"""Consultant work queue over canonical improvement actions and scoped profiles."""

import logging

import streamlit as st

from securescope.persistence.assurance_workspace_repository import (
    requirement_actions,
    load_workspace,
    update_requirement_action,
)
from securescope.persistence.foundation_repository import FoundationError
from securescope.ui.control_workspace import open_control_workspace
from securescope.ui.grc_workspace.context import current_actor, selected_context_ids

LOGGER = logging.getLogger(__name__)


def render_requirement_queue(client: str) -> None:
    """Show and update existing requirement remediation with context-preserving links.

    Args:
        client: Current workspace name.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; repository errors are logged and displayed.
    """
    engagement, scope = selected_context_ids(client)
    if not engagement or not scope:
        return
    key = f"control_work::{client}::{engagement}::{scope}"
    try:
        rows = requirement_actions(client, current_actor(), engagement, scope)
        st.subheader("Control Requirement Remediation")
        if key + "::notice" in st.session_state:
            st.success(st.session_state.pop(key + "::notice"))
        only_mine = st.checkbox("Assigned to me", key=key + "::mine")
        active = [
            r
            for r in rows
            if r["status"] not in {"Completed", "Cancelled"}
            and (not only_mine or r["action_owner"].lower() == current_actor().lower())
        ]
        if not active:
            st.caption("No open requirement remediation matches this view.")
            return
        for row in active:
            with st.container(border=True):
                text, action = st.columns([4, 1])
                text.write(
                    f"**{row['priority']} · {row['control_id']} · {row['recommended_action']}**"
                )
                text.caption(f"{row['action_owner']} · Due {row['due_date']} · {row['status']}")
                if action.button("Open Control", key=key + f"::control::{row['id']}"):
                    open_control_workspace(client, row["control_id"])
        from securescope.ui.evidence_hub_ui import _identity

        if _identity(client)[1] not in {"Administrator", "Consultant"}:
            return
        with st.expander(
            "Update Remediation Progress",
            expanded=bool(
                st.session_state.get(
                    f"requirement_remediation_selected::{client}::{engagement}::{scope}"
                )
            ),
        ):
            identities = {r["id"]: r for r in active}
            selected = st.session_state.pop(
                f"requirement_remediation_selected::{client}::{engagement}::{scope}", None
            )
            if selected in identities:
                st.session_state[key + "::selected"] = selected
            identity = st.selectbox(
                "Remediation",
                list(identities),
                key=key + "::selected",
                format_func=lambda i: f"#{i} · {identities[i]['recommended_action']}",
            )
            view = load_workspace(
                client, identities[identity]["control_id"], current_actor(), engagement, scope
            )
            evidence = {e["id"]: e for e in view["bundle"]["requirement_evidence"]}
            with st.form(key + "::progress"):
                evidence_id = st.selectbox(
                    "Verification evidence",
                    [None, *evidence],
                    format_func=lambda i: (
                        "Select evidence for completion"
                        if i is None
                        else f"EV-{i} · {evidence[i]['title']}"
                    ),
                )
                status = st.selectbox(
                    "Status",
                    [
                        "Open",
                        "In progress",
                        "Blocked",
                        "Ready for verification",
                        "Completed",
                        "Cancelled",
                    ],
                )
                note = st.text_area(
                    "Progress / verification rationale",
                    help=(
                        "Completing work does not pass the control; evidence is "
                        "re-evaluated separately."
                    ),
                )
                if st.form_submit_button("Update Remediation"):
                    update_requirement_action(
                        client,
                        current_actor(),
                        engagement,
                        scope,
                        identity,
                        status,
                        note,
                        evidence_id=evidence_id,
                    )
                    st.session_state[key + "::notice"] = (
                        "Requirement remediation updated. Control requirements are "
                        "re-evaluated when opened."
                    )
                    st.rerun()
    except FoundationError as exc:
        LOGGER.warning("Control work queue unavailable: %s", type(exc).__name__)
        st.error(f"Control work queue could not be loaded or updated: {exc}")


def render_asset_assurance(client: str, asset_ip: str) -> None:
    """Show current scoped evidence health and affected control backlinks for one asset.

    Args:
        client: Active workspace name.
        asset_ip: Canonical selected inventory IP.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected read errors are displayed.
    """
    from datetime import datetime, timezone

    from securescope.grc.assurance_requirements import evidence_freshness
    from securescope.persistence.assurance_workspace_repository import (
        _context,
        _evidence,
        configured_profiles,
    )
    from securescope.persistence.foundation_repository import workspace_cursor

    engagement, scope = selected_context_ids(client)
    if not engagement or not scope:
        return
    try:
        profiles = configured_profiles(client, current_actor(), engagement, scope)
        with workspace_cursor(client) as (cursor, client_id):
            _context(cursor, client_id, current_actor(), engagement, scope)
            cursor.execute(
                "SELECT id FROM securescope_assets WHERE client_id=%s AND ip=%s",
                (client_id, asset_ip),
            )
            asset = cursor.fetchone()
            if not asset:
                return
            evidence = _evidence(cursor, client_id, "", engagement, scope)
        relevant = [
            p
            for p in profiles
            if any(
                asset["id"] in r.get("asset_ids", [])
                for r in p["assessment_scope"]
                .get("implementation_requirements", {})
                .get("requirements", [])
            )
        ]
        st.subheader("Asset Evidence Health")
        st.caption(
            f"ISMS Scope #{scope} · Evidence freshness does not by itself prove effectiveness."
        )
        providers = [
            ("Nmap", "nmap"),
            ("Nuclei", "nuclei"),
            ("SIEM", "wazuh"),
            ("Classification", "classification"),
            ("Asset Inventory", "asset_inventory"),
            ("Manual Evidence", "manual"),
        ]
        rows = []
        for label, provider in providers:
            linked = [
                e
                for e in evidence
                if e["tool_id"] == provider
                and (
                    e.get("source_asset_or_system") == asset_ip
                    or asset["id"]
                    in (
                        (
                            (e.get("normalized_payload") or {}).get("metadata", {}).get("assurance")
                            or {}
                        ).get("asset_ids")
                        or []
                    )
                )
            ]
            rows.append(
                {
                    "Source": label,
                    "Freshness": (
                        evidence_freshness(linked[0], 90, datetime.now(timezone.utc))
                        if linked
                        else "Missing"
                    ),
                    "Validation": linked[0]["validation_status"] if linked else "No Evidence",
                }
            )
        st.table(rows)
        st.caption(
            f"{sum(r['Freshness'] != 'Missing' for r in rows)} / {len(rows)} "
            "sources recorded for this scope and asset."
        )
        for profile in relevant:
            if st.button(
                f"View {profile['control_id']} — {profile['control_name']}",
                key=f"asset_control::{client}::{scope}::{asset['id']}::{profile['control_id']}",
            ):
                open_control_workspace(client, profile["control_id"])
        if st.button("Collect Evidence", key=f'asset_collect::{client}::{scope}::{asset["id"]}'):
            from securescope.ui.navigation_runtime import navigate_to

            navigate_to("ISO Evidence Hub")
    except FoundationError as exc:
        LOGGER.warning("Asset assurance unavailable: %s", type(exc).__name__)
        st.warning(f"Asset evidence health unavailable: {exc}")
