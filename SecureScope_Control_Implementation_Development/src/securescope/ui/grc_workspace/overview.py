"""One visual card pattern for Foundation records and linked canonical modules."""

from html import escape

import streamlit as st

from securescope.grc.scope_workflow import filter_scope_risks
from securescope.grc.status_labels import status_label
from securescope.persistence.grc_repository import latest_statement_of_applicability
from securescope.persistence.risk_register_repository import list_risk_register
from securescope.policies.repository import load_policies
from securescope.ui.components.primitives import status_pill
from securescope.ui.navigation_runtime import navigate_to
from securescope.ui.risk_management import open_risk_management


def overview_card(*, key, title, clause, status, metrics, summary, actions):
    """Render the shared Overview card including its native navigation actions.

    Args:
        key: Unique card identity.
        title: Domain title.
        clause: Clause subtitle.
        status: Existing state, never a compliance conclusion.
        metrics: Label/value pairs from canonical records.
        summary: Short explanatory text.
        actions: Pairs of button labels and navigation callbacks.
    Returns:
        None.
    Raises:
        Callback failures propagate to the calling page.
    """
    with st.container(border=True, key="overview_card_" + key, height="stretch"):
        st.markdown(f"### {title}")
        st.caption("Clause " + clause)
        st.markdown(status_pill(status_label(status)), unsafe_allow_html=True)
        st.caption(summary)
        lines = "".join(
            f'<div class="overview-metric"><span>{escape(str(label))}</span>'
            f"<strong>{escape(str(value))}</strong></div>"
            for label, value in metrics
        )
        st.markdown('<div class="overview-metrics">' + lines + "</div>", unsafe_allow_html=True)
        with st.container(key="overview_actions_" + key):
            for index, (label, callback) in enumerate(actions):
                if st.button(label, key=f"overview_action::{key}::{index}", width="stretch"):
                    callback()
                    st.rerun()


def render_overview(client, context, on_section):
    """Read canonical summaries and render all eight cards with one component.

    Args:
        client: Selected client.
        context: Existing engagement/scope context.
        on_section: Existing local navigation callback.
    Returns:
        None.
    Raises:
        Known repository errors become unavailable card states, never zero counts.
    """
    from securescope.ui.grc_workspace.formal import ERRORS, SERVICE, versions

    engagement, scope_id = int(context["selected_engagement_id"]), context.get("selected_scope_id")
    selected_scope = next((s for s in context.get("scopes", []) if s["id"] == scope_id), {})
    st.markdown(
        """<style>
    [class*="st-key-overview_card_"] {
        height:100%;min-height:220px;background:var(--ss-surface);
        border-radius:var(--ss-radius);padding:var(--ss-space-4);gap:var(--ss-space-2);}
    [class*="st-key-overview_card_"] h3 {font-size:1rem;line-height:1.35;padding:0;}
    [class*="st-key-overview_card_"] > div:last-child {margin-top:auto;}
    .overview-metrics {margin:4px 0;}
    .overview-metric {display:flex;justify-content:space-between;
        gap:12px;padding:3px 0;font-size:var(--ss-font-sm);}
    .overview-metric strong {text-align:right;}
    @media(max-width:720px){[class*="st-key-overview_card_"]{min-height:0;height:auto;}}
    </style>""",
        unsafe_allow_html=True,
    )
    cards = []
    for kind, title, clause, field, action in (
        ("context", "Context", "4.1", "context_issues", "Open Context"),
        ("parties", "Interested Parties", "4.2", "interested_parties", "Open Interested Parties"),
        ("scope", "ISMS Scope", "4.3", "organizational_units", "Open ISMS Scope"),
        ("roles", "Roles & RACI", "5.3", "role_assignments", "Open Governance"),
        ("objectives", "Objectives", "6.2", None, "Open Objectives"),
    ):
        state, metrics, summary = (
            "Not Started",
            [],
            "Review the saved records and their supporting information.",
        )
        try:
            if kind == "scope":
                state = selected_scope.get("latest_status", "Not Started")
                metrics = [
                    ("Version", selected_scope.get("latest_version_number") or "Not Started"),
                    ("Organizational units", len(selected_scope.get("organizational_units") or [])),
                    ("Locations", len(selected_scope.get("locations") or [])),
                    ("Technologies", len(selected_scope.get("technologies") or [])),
                ]
            elif field:
                rows = SERVICE.load_section(client, engagement, scope_id, kind)[field]
                metrics = [("Records", len(rows))]
                state = "Needs review" if rows else "Not Started"
            else:
                history = versions(client, engagement, scope_id, kind) if scope_id else []
                latest = history[0] if history else {}
                metrics = [
                    (
                        "Objectives",
                        len([r for r in latest.get("records", []) if not r.get("archived")]),
                    )
                ]
                state = latest.get("status", "Not Started")
        except ERRORS as exc:
            state, summary = "Unavailable", str(exc)
        cards.append(
            dict(
                key=client + "::" + kind,
                title=title,
                clause=clause,
                status=state,
                metrics=metrics,
                summary=summary,
                actions=[(action, lambda value=kind: on_section(value))],
            )
        )
    st.subheader("Foundation Records")
    for offset in range(0, len(cards), 3):
        for column, card in zip(st.columns(3), cards[offset : offset + 3]):
            with column:
                overview_card(**card)
    linked = []
    try:
        policies, _ = load_policies(client, engagement, scope_id) if scope_id else ([], [])
        policy_state = (
            "Approved"
            if policies and all(p.get("status") == "Approved" for p in policies)
            else "In Progress" if policies else "Not Started"
        )
        policy_metrics = [
            ("Policies", len(policies)),
            ("Approved", sum(p.get("status") == "Approved" for p in policies)),
        ]
        policy_summary = "Canonical policies for the selected ISMS scope."
    except ERRORS as exc:
        policy_state, policy_metrics, policy_summary = "Unavailable", [], str(exc)
    linked.append(
        dict(
            key=client + "::policies",
            title="Information Security Policy",
            clause="5.2",
            status=policy_state,
            metrics=policy_metrics,
            summary=policy_summary,
            actions=[("Open Policies", lambda: navigate_to("Policies"))],
        )
    )
    try:
        risks = filter_scope_risks(list_risk_register(client), "Current ISMS Scope", scope_id)
        pending = sum(r.get("treatment_action_status") != "Completed" for r in risks)
        risk_state = "In Progress" if risks else "Not Started"
        risk_metrics = [
            ("Recorded risks", len(risks)),
            ("High / Critical", sum((r.get("pre_risk_score") or 0) >= 10 for r in risks)),
            ("Treatment pending", pending),
            ("Residual pending", sum(r.get("post_risk_score") is None for r in risks)),
        ]
        risk_summary = "Selected scope: " + str(selected_scope.get("name") or "None selected")
        treatment_metrics = [
            ("Treatment pending", pending),
            (
                "Linked controls",
                len({c for r in risks for c in (r.get("control_references") or [])}),
            ),
        ]
    except ERRORS as exc:
        risk_state, risk_metrics, risk_summary = "Unavailable", [], str(exc)
        treatment_metrics = [("Treatments", "Unavailable"), ("Linked controls", "Unavailable")]
    linked.append(
        dict(
            key=client + "::risks",
            title="Risk Assessment",
            clause="6.1.2",
            status=risk_state,
            metrics=risk_metrics,
            summary=risk_summary,
            actions=[("Open Risk Management", lambda: open_risk_management(client))],
        )
    )
    try:
        soa = (
            latest_statement_of_applicability(client, engagement_id=engagement, scope_id=scope_id)
            if scope_id
            else None
        )
        soa_state = status_label(soa.get("status")) if soa else "Not Started"
    except ERRORS:
        soa_state = "Unavailable"
    treatment_metrics.append(("SoA status", soa_state))
    linked.append(
        dict(
            key=client + "::treatment",
            title="Risk Treatment & Control Applicability",
            clause="6.1.3",
            status=(
                "Unavailable"
                if risk_state == "Unavailable" or soa_state == "Unavailable"
                else (
                    "In Progress"
                    if risk_state != "Not Started" or soa_state != "Not Started"
                    else "Not Started"
                )
            ),
            metrics=treatment_metrics,
            summary="Risk Management: treatment decisions and actions. Control Assuran"
            "ce: applicability, implementation, evidence and SoA.",
            actions=[
                (
                    "Open Risk Management",
                    lambda: open_risk_management(client, stage="Treatment plan"),
                ),
                ("Open Control Assurance", lambda: navigate_to("Gap Assessment")),
            ],
        )
    )
    st.subheader("Linked Modules")
    for column, card in zip(st.columns(3), linked):
        with column:
            overview_card(**card)
