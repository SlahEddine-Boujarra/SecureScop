"""Read-only Foundation summaries and links to authoritative workspaces."""

from __future__ import annotations

import logging

import streamlit as st
from securescope.ui.components.primitives import identity_context

from securescope.persistence.grc_repository import list_risk_treatment_plans
from securescope.persistence.risk_register_repository import list_risk_register
from securescope.policies.repository import load_policies
from securescope.ui.grc_workspace.formal import ERRORS
from securescope.ui.navigation_runtime import navigate_to
from securescope.ui.risk_management import open_risk_management

LOGGER = logging.getLogger(__name__)


def render_risk_readiness(client: str, context: dict) -> None:
    """Summarize canonical client-wide risks without introducing another editor.

    Args:
        client: str: Exact active client workspace name.
        context: dict: Resolved client, engagement and scope context.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    st.subheader("Risk Assessment — Clause 6.1.2")
    from securescope.grc.scope_workflow import filter_scope_risks

    scope_id = context.get("selected_scope_id")
    selected_scope = next((r for r in context.get("scopes", []) if r["id"] == scope_id), {})
    st.caption("Scope: " + str(selected_scope.get("name") or "No scope selected"))
    try:
        risks = filter_scope_risks(list_risk_register(client), "Current ISMS Scope", scope_id)
    except ERRORS as exc:
        LOGGER.warning("Linked module read failed: %s", type(exc).__name__)
        st.error(f"Risk readiness is unavailable: {exc}")
        return
    metrics = (
        ("Recorded risks", len(risks)),
        ("High / Critical", sum((r.get("pre_risk_score") or 0) >= 10 for r in risks)),
        ("Treatment pending", sum(r.get("treatment_action_status") != "Completed" for r in risks)),
        ("Residual ratings pending", sum(r.get("post_risk_score") is None for r in risks)),
    )
    for column, (label, count) in zip(st.columns(4), metrics):
        column.metric(label, count)
    if st.button("Open Risk Management", key=f"foundation_risk_link::{client}", type="primary"):
        open_risk_management(client)
    st.caption(
        "Assessment completion, residual verification and risk-owner acceptance are separate "
        "decisions."
    )


def render_policy_readiness(client: str, context: dict) -> None:
    """Read policy states from the same scoped repository used by Policies.

    Args:
        client: str: Exact active client workspace name.
        context: dict: Resolved client, engagement and scope context.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    st.subheader("Information Security Policy — Clause 5.2")
    scope = context.get("selected_scope_id")
    if scope is None:
        st.info("Select an ISMS scope to view policy readiness.")
        return
    try:
        policies, _ = load_policies(client, int(context["selected_engagement_id"]), int(scope))
    except ERRORS as exc:
        LOGGER.warning("Linked module read failed: %s", type(exc).__name__)
        st.error(f"Policy readiness is unavailable: {exc}")
        return
    if policies:
        st.dataframe(
            [
                {
                    "Policy": r.get("title"),
                    "Status": r.get("status"),
                    "Owner": r.get("owner"),
                    "Version": r.get("policy_version"),
                    "Approved by": r.get("approved_by"),
                }
                for r in policies
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Review the policy content and management commitments in Policies; record counts "
            "alone do not establish clause readiness."
        )
    else:
        st.info("No policies recorded for this scope. Prepare and review a policy in Policies.")
    if st.button("Open Policies", key=f"foundation_policy_link::{client}", type="primary"):
        navigate_to("Policies")


def render_treatment_links(client: str) -> None:
    """Show canonical treatments and preserve historical plans read-only.

    Args:
        client: str: Exact active client workspace name.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    import json

    from securescope.grc.scope_workflow import display_date, display_person, filter_scope_risks
    from securescope.grc.status_labels import status_label
    from securescope.ui.assurance_workbench import _event
    from securescope.ui.components_v2.assurance_workbench import assurance_workbench
    from securescope.ui.grc_workspace.context import current_actor, selected_context_ids
    from securescope.ui.grc_workspace.formal import get_workspace_role

    engagement, scope = selected_context_ids(client)
    st.subheader("Related Risk Treatments")
    st.caption(
        "Read-only canonical treatments. Risk Management owns treatment decisions and actions."
    )
    view = (
        st.selectbox(
            "Risk view",
            ["Current ISMS Scope", "All client risks", "Unassigned scope"],
            format_func=lambda v: {
                "All client risks": "All Client Risks",
                "Unassigned scope": "Unassigned Risks",
            }.get(v, v),
            key=f"related_treatments::{client}::{engagement}::{scope}",
        )
        or "Current ISMS Scope"
    )
    st.caption(
        "Scope: "
        + (
            st.session_state.get(f"scope_label::{client}::{scope}", "Selected ISMS Scope")
            if scope
            else "No ISMS scope selected"
        )
    )
    if st.button("Open treatment plan", key=f"canonical_treatment::{client}", type="primary"):
        open_risk_management(client, stage="Treatment plan", risk_view=view)
    try:
        risks = filter_scope_risks(list_risk_register(client), view, scope)
        legacy = list_risk_treatment_plans(client)
        rows = [r for r in risks if r.get("treatment_option") or r.get("control_references")]
        key = f"related_treatment_rows::{client}::{engagement}::{scope}::{view}"
        if rows:
            action = _event(
                assurance_workbench(
                    json.loads(json.dumps(dict(mode="related_treatments", rows=rows), default=str)),
                    key=key,
                ),
                key,
            )
            if action and action["action"] == "open_risk":
                selected = action.get("payload", {}).get("id")
                if any(r["risk_ref"] == selected for r in rows):
                    open_risk_management(
                        client, stage="Treatment plan", risk_ref=selected, risk_view=view
                    )
        else:
            st.caption(
                "No treatments recorded in this scope. Add a treatment to an exist"
                "ing risk in Risk Management."
            )
        if legacy:
            with st.expander(f"Historical treatment plans ({len(legacy)})"):
                st.caption(
                    "Legacy client-wide records; scope ownership is not inferred. Thes"
                    "e are preserved audit records, not a second treatment editor."
                )
                is_admin = get_workspace_role(client, current_actor()) == "Administrator"
                for plan in legacy:
                    with st.container(border=True):
                        st.markdown(
                            "**" + str(plan.get("title") or "Historical Treatment Plan") + "**"
                        )
                        st.caption(
                            f"{status_label(plan.get('status'))} · "
                            f"Created: {display_date(plan.get('created_at'))}"
                        )
                        identity_context(display_person(plan.get("owner")), "Owner")
                        st.write(
                            "Risk reference: " + str(plan.get("risk_reference") or "Not recorded")
                        )
                        st.write(
                            "Treatment: " + str(plan.get("treatment_option") or "Not recorded")
                        )
                        st.caption("Source: Historical treatment register")
                        with st.expander("View audit details"):
                            for field, value in plan.items():
                                if field in {"id", "client_id"} or value is None:
                                    continue
                                if isinstance(value, (dict, list)):
                                    st.write(field.replace("_", " ").title())
                                    st.dataframe(
                                        (
                                            value
                                            if isinstance(value, list)
                                            and all(isinstance(x, dict) for x in value)
                                            else (
                                                [{"Value": str(v)} for v in value]
                                                if isinstance(value, list)
                                                else [
                                                    {"Field": k, "Value": str(v)}
                                                    for k, v in value.items()
                                                ]
                                            )
                                        ),
                                        hide_index=True,
                                    )
                                else:
                                    st.write(field.replace("_", " ").title() + ": " + str(value))
                        if is_admin:
                            with st.expander("Administrator / Technical Audit"):
                                st.json(plan, expanded=False)
    except ERRORS as exc:
        LOGGER.warning("Related treatment read failed: %s", type(exc).__name__)
        st.error(f"Related treatments could not be loaded: {exc}")
