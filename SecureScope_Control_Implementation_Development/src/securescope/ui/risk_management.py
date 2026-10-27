"""Risk lifecycle navigation over existing authorized services."""

import streamlit as st

from securescope.ui.components.navigation import section_navigation

from securescope.grc.status_labels import status_label
from securescope.persistence.workspace_planning import put_record
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role
from securescope.ui.navigation_runtime import navigate_to

STAGES = {
    "Registers & assessment": "Identify scenarios and owners, then assess likelihood and impact.",
    "Treatment plan": "Choose a treatment and track controls, actions and delivery dates.",
    "Residual assessment": "Review risk after treatment. Planned scores are not verified outcomes.",
    "Risk acceptance": "Record an authorized risk-owner decision and its review date.",
    "Monitoring & review": "Review saved assessments, treatment progress and review dates.",
    "Methodology": "Agree scope, criteria and acceptance rules before assessment.",
}


def open_risk_management(
    client,
    create=False,
    *,
    stage="Registers & assessment",
    risk_ref=None,
    risk_view="Current ISMS Scope",
):
    """Open the canonical risk workflow with the current workspace scope filter."""
    st.session_state[f"risk_management::{client}::pending"] = stage
    st.session_state.pop(f"risk::{client}::selected", None)
    st.session_state.pop(f"risk::{client}:group", None)
    if create:
        st.session_state[f"risk_register_create::{client}"] = True
    if risk_view not in {"Current ISMS Scope", "All client risks", "Unassigned scope"}:
        raise ValueError("Choose a supported risk view.")
    st.session_state[f"risk_scope_filter::{client}::pending"] = risk_view
    if stage != "Registers & assessment":
        st.session_state[f"risk::{client}:group"] = "all"
    if risk_ref is not None:
        st.session_state[f"risk::{client}::selected"] = risk_ref
    navigate_to("Risk")


def risk_entry_actions(client, can_create):
    if st.button("Open Risk Management", key=f"risk_entry::{client}"):
        open_risk_management(client)


def _change_stage(client):
    st.session_state.pop(f"risk::{client}::selected", None)
    st.session_state.pop(f"risk::{client}:owned", None)


def render_risk_management(client):
    from securescope.ui.assurance_workbench import render_risk_workbench

    actor = current_actor()
    try:
        role = get_workspace_role(client, actor)
    except ERRORS as exc:
        st.error(str(exc))
        return
    if not role:
        st.info("Sign in or complete Administrator setup in Client Workspace to access Risk.")
        return
    from securescope.ui.grc_workspace.context import workspace_state_keys

    _, scope_key = workspace_state_keys(client)
    scope_id = st.session_state.get(scope_key)
    filter_key = f"risk_scope_filter::{client}"
    if filter_key + "::pending" in st.session_state:
        st.session_state[filter_key] = st.session_state.pop(filter_key + "::pending")
    st.title("Risk Management")
    scope_filter = (
        st.selectbox(
            "Risk view",
            ["Current ISMS Scope", "All client risks", "Unassigned scope"],
            index=0 if scope_id is not None else 1,
            format_func=lambda value: {
                "Current ISMS Scope": f"Current ISMS Scope #{scope_id}",
                "All client risks": "All Client Risks",
                "Unassigned scope": "Unassigned Risks",
            }[value],
            key=filter_key,
            on_change=_change_stage,
            args=(client,),
        )
        or "All client risks"
    )
    if scope_filter == "Current ISMS Scope" and scope_id is None:
        st.info("Select an ISMS scope in the workspace context, or choose All client risks.")
    st.caption("A guided lifecycle from assessment to treatment and review.")
    key = f"risk_management::{client}"
    if key + "::pending" in st.session_state:
        st.session_state[key] = st.session_state.pop(key + "::pending")
    stage = section_navigation(
        "Risk lifecycle",
        list(STAGES),
        format_func=status_label,
        default="Registers & assessment",
        selection_mode="single",
        key=key,
        on_change=_change_stage,
        args=(client,),
    )
    with stage.panel:
        stage = stage or "Registers & assessment"
        st.caption(STAGES[stage])
        create = f"risk_register_create::{client}"
        if (
            stage == "Registers & assessment"
            and st.session_state.get(create)
            and role == "Administrator"
        ):
            with st.form(create + "::form"):
                name = st.text_input("Register name", max_chars=200)
                description = st.text_area("Purpose and scope", max_chars=10000)
                save = st.form_submit_button("Save risk register", type="primary")
                cancel = st.form_submit_button("Cancel")
            if cancel:
                st.session_state.pop(create, None)
                st.rerun()
            if save:
                try:
                    if not name.strip():
                        raise ValueError("Enter a register name.")
                    saved = put_record(
                        client,
                        "risk_group",
                        "",
                        {"name": name.strip(), "description": description.strip()},
                        actor=actor,
                    )
                except (*ERRORS, ValueError) as exc:
                    st.error(str(exc))
                else:
                    st.session_state[f"risk::{client}:group"] = saved
                    st.session_state.pop(f"risk::{client}::selected", None)
                    st.session_state.pop(create, None)
                    st.session_state[create + "::notice"] = (
                        "Risk register saved. New scenarios will use this register."
                    )
                    st.rerun()
        if create + "::notice" in st.session_state:
            st.success(st.session_state.pop(create + "::notice"))
        if stage == "Methodology":
            st.warning(
                "Coming Soon — configurable, versioned risk methodology. Current "
                "scoring uses the application's 1–5 likelihood and impact defaults; "
                "these are not prescribed ISO thresholds."
            )
            st.button("Configure methodology · Coming Soon", disabled=True)
        else:
            if stage == "Risk acceptance":
                st.warning(
                    "Coming Soon — formal scenario acceptance by the risk owner. Selecting "
                    "Accept or approving an assessment does not record formal acceptance."
                )
                st.button("Record formal acceptance · Coming Soon", disabled=True)
            elif stage == "Residual assessment":
                st.caption(
                    "Planned estimates are available. A dedicated residual verification and "
                    "sign-off workflow is Coming Soon."
                )
            elif stage == "Monitoring & review":
                st.caption(
                    "Saved review dates and history are available. Automated reminders and "
                    "review campaigns are Coming Soon."
                )
            render_risk_workbench(
                client, lifecycle=stage, scope_filter=scope_filter, scope_id=scope_id
            )
