"""On-demand governance tools for the existing Foundation records."""

from __future__ import annotations

import logging

import streamlit as st
from securescope.ui.components.primitives import identity_context

from securescope.grc.engagement_models import GrcValidationError
from securescope.grc.scope_workflow import display_person
from securescope.persistence.foundation_repository import save_version, versions
from securescope.persistence.grc_workspace_repository import (
    GrcWorkspaceRepositoryError,
    list_scope_versions,
    record_scope_review,
    submit_scope_review,
)
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role
from securescope.ui.grc_workspace.sections import SERVICE, render_climate_details

LOGGER = logging.getLogger(__name__)


def render_record_tools(client, context, section, registers, tool, selected_id=None):
    """Display only the requested history, approval or selected-party requirements.

    Args:
        client: str: Exact active client workspace name.
        context: dict: Resolved client, engagement and scope context.
        section: str: Existing Foundation register identifier.
        registers: dict: Section-specific canonical repository rows.
        tool: str: Requested history or review view.
        selected_id: str | None: Selected canonical row identifier.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    engagement = int(context["selected_engagement_id"])
    scope = context.get("selected_scope_id")
    actor = current_actor()
    try:
        role = get_workspace_role(client, actor)
        if not role:
            st.warning("Workspace membership is required.")
            return
        if tool == "edit" and section in {"context", "parties"}:
            from securescope.ui.grc_workspace.record_edit import render_record_edit

            collection = "context_issues" if section == "context" else "interested_parties"
            record = next(
                (r for r in registers.get(collection, []) if str(r["id"]) == str(selected_id)), None
            )
            if record is None:
                st.warning("Record is no longer available in this context.")
                return
            render_record_edit(
                client,
                engagement,
                scope,
                section,
                record,
                actor,
                role in {"Administrator", "Consultant", "Client contributor"},
            )
        elif section == "scope":
            _scope_tools(client, engagement, scope, actor, role, tool)
        elif section == "objectives":
            _objective_tools(client, engagement, scope, actor, role, tool)
        elif section == "context":
            render_climate_details(client, engagement, scope, registers, actor=actor)
        elif section == "parties":
            _party_tools(client, engagement, scope, actor, registers, selected_id)
        elif section == "roles":
            st.caption(
                "Application permissions are managed in Client Workspace. Delivery roles are "
                "managed in Engagement."
            )
    except (*ERRORS, GrcWorkspaceRepositoryError, GrcValidationError) as exc:
        LOGGER.warning("Foundation workflow failed: %s", type(exc).__name__)
        st.error(str(exc))


def _scope_tools(client, engagement, scope, actor, role, tool):
    """Reuse controlled scope approval and display real version history.

    Args:
        client: str: Exact active client workspace name.
        engagement: int: Selected engagement identifier.
        scope: int | None: Selected ISMS scope identifier.
        actor: str: Trusted current workspace identity.
        role: str: Current authorized membership role.
        tool: str: Requested history or review view.

    Returns:
        None.

    Raises:
        Known persistence failures are displayed by the parent workflow.
    """
    if scope is None:
        st.info("Prepare a draft scope first.")
        return
    history = list_scope_versions(client, engagement, int(scope))
    if not history:
        st.info("No scope versions recorded.")
        return
    if tool == "history":
        from securescope.ui.grc_workspace.scope_history import render_scope_history

        render_scope_history(
            history, key=f"scope_history::{client}::{scope}", is_admin=role == "Administrator"
        )
        return
    version = history[0]
    st.subheader(f"Review scope · version {version['version_number']}")
    st.write(version.get("scope_statement") or "No statement recorded.")
    for label, field in (
        ("Organizational boundary", "organizational_units"),
        ("Locations", "locations"),
        ("Technology boundary", "technologies"),
        ("Products and services", "products_and_services"),
        ("Boundaries", "boundaries"),
        ("Dependencies and interfaces", "interfaces_and_dependencies"),
        ("Exclusions and justification", "exclusions"),
    ):
        st.markdown(f"**{label}**")
        st.write(version.get(field) or "Not recorded")
    st.caption(
        f"Status: {version['status']} · "
        f"Prepared by: {display_person(version.get('prepared_by'))} · "
        f"Reviewer: {display_person(version.get('reviewed_by'))}"
    )
    feedback_key = f"scope_decision::{client}::{scope}"
    if message := st.session_state.pop(feedback_key, None):
        st.success(message)
    state = version["status"]
    st.caption("Draft → Submitted for Review → Reviewed → Approved")
    if state in {"Approved", "Changes requested", "Rejected", "Superseded"}:
        st.info(
            "This approved version is immutable. Edit scope to prepare a new draft."
            if state == "Approved"
            else "Open Edit scope to prepare a revised draft."
        )
        return
    is_submit = state == "Draft"
    is_review = state == "Under review"
    label = (
        "Submission rationale"
        if is_submit
        else "Review rationale" if is_review else "Approval rationale"
    )
    allowed = role in (
        {"Administrator", "Consultant", "Client contributor"}
        if is_submit
        else {"Administrator", "Consultant"}
    )
    with st.form(f"scope_review::{client}::{scope}::{version['id']}::{state}"):
        note = st.text_area(label)
        acknowledged = (
            True
            if is_submit
            else st.checkbox(
                "I reviewed this scope version and its boundaries."
                if is_review
                else "I authorize approval of this reviewed scope version."
            )
        )
        action_label = (
            "Submit for Review" if is_submit else "Mark Reviewed" if is_review else "Approve Scope"
        )
        proceed = st.form_submit_button(action_label, disabled=not allowed, type="primary")
        changes = (
            False if is_submit else st.form_submit_button("Request Changes", disabled=not allowed)
        )
    if not (proceed or changes):
        return
    if not note.strip() or (proceed and not acknowledged):
        st.error(f"{action_label} requires a rationale and the displayed confirmation.")
        return
    if is_submit:
        submit_scope_review(
            client, engagement, int(scope), int(version["id"]), actor=actor, note=note
        )
        message = "Scope submitted for review."
    elif changes or is_review:
        record_scope_review(
            client,
            engagement,
            int(scope),
            int(version["id"]),
            actor=actor,
            note=note,
            decision="Changes requested" if changes else "Reviewed",
        )
        message = "Scope changes requested." if changes else "Scope marked as reviewed."
    else:
        SERVICE.approve_scope_version(
            client, engagement, int(scope), int(version["id"]), approver_email=actor, comment=note
        )
        message = "Scope approved."
    st.session_state[feedback_key] = message
    st.rerun()


def _objective_tools(client, engagement, scope, actor, role, tool):
    """Transition the saved register revision without a second objective editor.

    Args:
        client: str: Exact active client workspace name.
        engagement: int: Selected engagement identifier.
        scope: int | None: Selected ISMS scope identifier.
        actor: str: Trusted current workspace identity.
        role: str: Current authorized membership role.
        tool: str: Requested history or review view.

    Returns:
        None.

    Raises:
        Known persistence failures are displayed by the parent workflow.
    """
    if scope is None:
        st.info("Select an ISMS scope first.")
        return
    history = versions(client, engagement, int(scope), "objectives")
    if tool == "history":
        st.subheader("Objectives version history")
        for version in history:
            with st.container(border=True):
                st.markdown(f"**Version {version['version']} · {version['status']}**")
                identity_context(version.get('owner') or 'Unassigned', 'Owner')
                st.dataframe(version.get("records", []), hide_index=True, width="stretch")
                st.write(version.get("note") or "No review rationale recorded.")
        return
    if not history:
        st.info("Add an objective and save its draft before requesting review.")
        return
    latest = history[0]
    st.subheader(f"Review objectives · version {latest['version']}")
    st.dataframe(latest["records"], hide_index=True, width="stretch")
    with st.form(f"objectives_review::{client}::{scope}::{latest['version']}"):
        note = st.text_area("Review / approval rationale")
        reviewed = st.checkbox("I reviewed this saved version and its supporting references.")
        submit = st.form_submit_button(
            "Submit reviewed version",
            disabled=role not in {"Administrator", "Consultant", "Client contributor"}
            or latest["status"] not in {"Draft", "Suggested"},
        )
        approve = st.form_submit_button(
            "Approve reviewed version",
            disabled=role != "Administrator" or latest["status"] != "In review",
        )
    if submit or approve:
        if not reviewed or not note.strip():
            st.error("Review the saved version and add a rationale first.")
            return
        save_version(
            client,
            engagement,
            int(scope),
            "objectives",
            latest["records"],
            actor=actor,
            owner=latest.get("owner") or actor,
            status="Approved" if approve else "In review",
            expected_version=latest["version"],
            note=note,
        )
        st.rerun()


def _party_tools(client, engagement, scope, actor, registers, selected_id):
    """Display requirements for the selected canonical interested party.

    Args:
        client: str: Exact active client workspace name.
        engagement: int: Selected engagement identifier.
        scope: int | None: Selected ISMS scope identifier.
        actor: str: Trusted current workspace identity.
        registers: dict: Section-specific canonical repository rows.
        selected_id: str | None: Selected canonical row identifier.

    Returns:
        None.

    Raises:
        Known persistence failures are displayed by the parent workflow.
    """
    from securescope.ui.grc_workspace.dialogs import render_requirement_dialog

    party = next(
        (r for r in registers.get("interested_parties", []) if str(r["id"]) == str(selected_id)),
        None,
    )
    if party is None:
        st.info("Select an interested party to inspect its requirements.")
        return
    st.subheader(f"Requirements · {party['name']}")
    rows = SERVICE.load_party_requirements(client, engagement, int(party["id"]))
    if rows:
        st.dataframe(
            [
                {
                    k.replace("_", " ").title(): r.get(k)
                    for k in (
                        "requirement",
                        "requirement_type",
                        "source_reference",
                        "applicability",
                        "mandatory",
                        "owner",
                        "review_date",
                    )
                }
                for r in rows
            ],
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No requirements recorded for this party.")
    if st.button("Add requirement", key=f"party_requirement::{client}::{party['id']}"):
        render_requirement_dialog(
            client, engagement, scope, int(party["id"]), str(party["name"]), actor
        )
