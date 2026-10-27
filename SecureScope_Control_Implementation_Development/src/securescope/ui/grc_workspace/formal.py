"""Shared Foundation register screens and local-operator membership setup."""

from __future__ import annotations

import hashlib
import os
from typing import Any, Callable

import streamlit as st

from securescope.grc.engagement_service import GrcWorkspaceServiceError
from securescope.grc.formal_registers import FIELDS, risk_signature
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.evidence_repository import EvidenceRepositoryError, get_workspace_role
from securescope.persistence.foundation_repository import (
    ROLES,
    FoundationError,
    local_administrator,
    save_member,
    save_version,
    versions,
)
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.migration_service import MigrationError
from securescope.persistence.risk_register_repository import list_risk_register
from securescope.ui.components.primitives import identity_context, readable_table, status_pill
from securescope.ui.grc_workspace.context import SERVICE  # noqa: F401 - Overview service export
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.risk_register_table import render_risk_register_table
from securescope.ui.workflow_sections import workflow_section

ERRORS = (
    FoundationError,
    DatabaseConfigurationError,
    MigrationError,
    EvidenceRepositoryError,
    GrcRepositoryError,
    GrcWorkspaceServiceError,
)
TITLES = {
    "policy": "Information security policy",
    "objectives": "Security objectives",
    "risks": "Risk assessment",
}
CLAUSES = {"policy": "5.2", "objectives": "6.2", "risks": "6.1.2"}
TONES = {
    "Not started": "neutral",
    "Suggested": "neutral",
    "Draft": "neutral",
    "In review": "warning",
    "Approved": "success",
    "Needs update": "warning",
}


def render_operator_access(client_name: str) -> None:
    """Offer host-proven first setup/sign-in without exposing the local code.

    Args:
        client_name: Active workspace.
    Returns:
        None.
    Raises:
        Unexpected Streamlit programming errors propagate.
    """
    if st.session_state.get("_foundation_identity") and current_actor() != "local-consultant":
        identity_context(current_actor(), "Signed in")
        if st.button("Sign out", key=f"foundation_signout::{client_name}", type="tertiary"):
            st.session_state.pop("_foundation_identity", None)
            st.rerun()
        return
    with st.expander("Administrator setup / local sign-in"):
        st.caption(
            "For the operator running this installation. Enter the private code "
            "shown in its PowerShell launcher. The code never appears on this page."
        )
        if not os.getenv("SECURESCOPE_LOCAL_SETUP_CODE"):
            st.info("Restart using start_securescope.ps1 to obtain the local setup code.")
            return
        st.caption(
            (
                "First setup creates one Administrator. Later sign-ins require an "
                "existing Administrator email."
            )
        )
        with st.form(f"foundation_access::{client_name}", clear_on_submit=True):
            email = st.text_input("Administrator email")
            name = st.text_input("Display name")
            code = st.text_input("Local setup code", type="password")
            confirmed = st.checkbox(
                "I operate this installation and authorize this workspace setup or sign-in."
            )
            submitted = st.form_submit_button("Verify local access", type="primary")
        if submitted:
            if not confirmed:
                st.error("Confirm the local access request first.")
                return
            try:
                with st.spinner("Verifying local access…"):
                    verified = local_administrator(client_name, email, name, code)
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.session_state["_foundation_identity"] = {
                    "email": verified,
                    "proof": hashlib.sha256(
                        os.environ["SECURESCOPE_LOCAL_SETUP_CODE"].encode()
                    ).hexdigest(),
                }
                st.rerun()


def render_membership_manager(client_name: str, actor: str) -> None:
    """Render authorized application-access management in Client Workspace.

    Args:
        client_name: Tenant.
        actor: Trusted current principal.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate.
    """
    try:
        role = get_workspace_role(client_name, actor)
    except ERRORS as exc:
        st.error(f"Membership is unavailable: {exc}")
        return
    st.markdown("### Workspace membership")
    st.caption(
        "Manage application access for this client. ISMS responsibilities are maintained in "
        "Programme Foundation."
    )
    if role != "Administrator":
        st.info(
            (
                "Only a workspace Administrator can add members. Use Administrator"
                " setup / local sign-in above."
            )
        )
        return
    with st.form(f"foundation_member::{client_name}"):
        email = st.text_input("Member email")
        name = st.text_input("Display name")
        requested = st.selectbox("Workspace access role", ROLES)
        st.caption(
            (
                "Access permissions are separate from Accountable / Responsible / "
                "Consulted / Informed assignments."
            )
        )
        confirm = st.checkbox("Confirm adding or updating this person's workspace permissions.")
        submit = st.form_submit_button("Save membership", type="primary")
    if submit:
        if not confirm:
            st.error("Confirm the membership change.")
            return
        try:
            with st.spinner("Saving membership…"):
                save_member(client_name, actor=actor, email=email, name=name, role=requested)
        except ERRORS as exc:
            st.error(str(exc))
        else:
            st.rerun()


def _suggestion(kind: str, owner: str) -> list[dict[str, Any]]:
    """Build clearly marked starter content, never an approved assessment.

    Args:
        kind: Policy or objectives.
        owner: Proposed owner.
    Returns:
        One editable starter row.
    Raises:
        KeyError: For an unsupported key.
    """
    row = {field: "" for field in FIELDS[kind]}
    row["owner"] = owner
    if kind == "policy":
        row.update(
            title="Information security policy — draft",
            policy_text="Define the organization's commitment to protecting information, "
            "meeting applicable requirements and continually improving its ISMS. "
            "Tailor the policy to the agreed scope and communicate it to relevant people.",
        )
    else:
        row.update(
            title="Improve evidence coverage — draft",
            measure="Percentage of applicable controls with current validated evidence",
            action_plan="Assign evidence owners, collect supporting records and review coverage.",
            resources="Identify the people, budget and tools required.",
        )
    return [row]


# Legacy compatibility only; canonical module routes must not call this editor.
def legacy_render_formal_register(client_name: str, context: dict[str, Any], kind: str) -> None:
    """Render one searchable register with draft/detail/history/approval actions.

    Args:
        client_name: Tenant.
        context: Selected engagement and scope.
        kind: Policy, objectives or existing risk-review snapshot.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected failures are visible.
    """
    st.subheader(TITLES[kind])
    st.caption(
        (
            "Clause "
            f"{CLAUSES[kind]}"
            " · Discover → Suggest → Review → Approve. Approval records "
            "a human decision."
        )
    )
    scope = context.get("selected_scope_id")
    if scope is None:
        st.info("Create an ISMS scope before recording formal versions.")
        return
    engagement = int(context["selected_engagement_id"])
    actor = current_actor()
    try:
        history = versions(client_name, engagement, int(scope), kind)
        role = get_workspace_role(client_name, actor)
        canonical = list_risk_register(client_name) if kind == "risks" else []
    except ERRORS as exc:
        st.error(f"This register is unavailable: {exc}")
        return
    latest = history[0] if history else {}
    revision = int(latest.get("version", 0))
    status = latest.get("status", "Not started")
    stale = (
        kind == "risks"
        and bool(latest)
        and risk_signature(canonical) != risk_signature(latest["records"])
    )
    st.markdown(status_pill("Needs update" if stale else status), unsafe_allow_html=True)
    st.caption(f"Version {revision or '—'}")
    identity_context(latest.get("owner") or "Unassigned", "Owner")
    key = f"formal::{client_name}::{engagement}::{scope}::{kind}::{revision}"
    can_edit = role in {"Administrator", "Consultant", "Client contributor"}
    if not can_edit:
        st.info("Read-only: an active contributor membership is required to prepare a version.")
    if not history:
        st.info(
            f"Start by discovering the agreed scope and existing {TITLES[kind].lower()} records. "
            "Use a suggestion or add your organization's content, then request review."
        )
    with workflow_section(
        "Discover: source and purpose", "Confirm the context and source records before editing."
    ):
        st.write(f"Selected scope: {scope}. Keep the document specific to this engagement.")
        st.caption(
            "Suggestions are editable starter text, not AI-verified facts or a compliance decision."
        )
        if kind == "risks":
            st.write(f"{len(canonical)} risks read from the existing workspace risk register.")
            st.caption(
                (
                    "This review covers the client-wide risk register; the underlying "
                    "risks are not yet scope-filtered."
                )
            )
        elif kind == "policy":
            st.write(
                (
                    "Record management's policy commitments, accountable owner and "
                    "communication/evidence reference."
                )
            )
        else:
            st.write("Define a measurable target, owner, delivery plan, resources and review date.")
    owner = st.text_input(
        "Register owner",
        value=latest.get("owner") or actor,
        key=key + "::owner",
        disabled=not can_edit,
    )
    draft_key = key + "::draft"
    if kind == "risks":
        from securescope.ui.risk_management import risk_entry_actions

        risk_entry_actions(client_name, role == "Administrator")
        records = canonical
        render_risk_register_table(records, key=key + "::risks")
        with workflow_section(
            "Add or edit canonical risks",
            "Update saved risk records; changes require an explicit save.",
        ):
            from securescope.ui.document_registers_ui import render_register

            if can_edit:
                render_register(client_name, "asset_risks", key_suffix="foundation")
            else:
                st.caption("Sign in with an active contributor membership to edit.")
    else:
        records = st.session_state.setdefault(
            draft_key, [dict(row) for row in latest.get("records", [])]
        )
        query = st.text_input("Search records", key=key + "::search").strip().casefold()
        visible = [
            (index, row)
            for index, row in enumerate(records)
            if not query or query in " ".join(map(str, row.values())).casefold()
        ]
        readable_table([row for _, row in visible], key=key + "::table")
        with workflow_section(
            "Add / edit record", "Choose a record, enter its details and save the draft."
        ):
            options = [-1] + [index for index, _ in visible]
            selected = st.selectbox(
                "Record",
                options,
                format_func=lambda index: (
                    "Add a record"
                    if index == -1
                    else str(records[index].get("title") or f"Record {index+1}")
                ),
                key=key + "::record",
            )
            source = records[selected] if selected >= 0 else {}
            with st.form(key + f"::edit::{selected}"):
                edited = {}
                for field in FIELDS[kind]:
                    label = field.replace("_", " ").capitalize()
                    if field == "due_date":
                        label += " (YYYY-MM-DD)"
                    edited[field] = st.text_area(
                        label, value=str(source.get(field) or ""), disabled=not can_edit
                    )
                change = st.form_submit_button(
                    "Keep record in draft", type="primary", disabled=not can_edit
                )
            if change:
                if selected == -1:
                    records.append(edited)
                else:
                    records[selected] = edited
                st.session_state[draft_key] = records
                st.rerun()
        st.caption("Record edits stay in this browser until you save a version below.")
    note = st.text_area("Review / approval rationale", key=key + "::note", disabled=not can_edit)
    acknowledge = st.checkbox(
        "I reviewed this version and its supporting references.", key=key + "::reviewed"
    )
    actions = st.columns(3)
    requested = None
    if not history:
        if actions[0].button(
            "Prepare suggestion",
            icon=":material/auto_awesome:",
            disabled=not can_edit,
            key=key + "::suggest",
        ):
            records = canonical if kind == "risks" else _suggestion(kind, owner)
            requested = "Suggested"
    if actions[0].button(
        "Save draft version",
        icon=":material/save:",
        type="secondary",
        disabled=not can_edit,
        key=key + "::save",
    ):
        requested = "Draft"
    review_allowed = status in {"Draft", "Suggested"} and can_edit
    if actions[1].button(
        "Submit reviewed version",
        type="primary",
        icon=":material/rate_review:",
        disabled=not review_allowed or not acknowledge or not note.strip(),
        help="Save a draft, review the content and record a rationale first.",
        key=key + "::submit",
    ):
        requested = "In review"
    approval_allowed = role == "Administrator" and status == "In review" and not stale
    with actions[2].container(key="foundation_approval"):
        if st.button(
            "Approve reviewed version",
            type="primary",
            icon=":material/verified:",
            disabled=not approval_allowed or not acknowledge or not note.strip(),
            help="Only a workspace Administrator can approve an unchanged reviewed version.",
            key=key + "::approve",
        ):
            requested = "Approved"
    if requested:
        try:
            with st.spinner("Saving formal version…"):
                save_version(
                    client_name,
                    engagement,
                    int(scope),
                    kind,
                    records,
                    actor=actor,
                    owner=owner,
                    status=requested,
                    expected_version=revision,
                    note=note,
                )
        except ERRORS as exc:
            st.error(str(exc))
        else:
            st.rerun()
    with st.expander("Version history"):
        readable_table(
            [
                {
                    field: row.get(field)
                    for field in (
                        "version",
                        "status",
                        "owner",
                        "recorded_by",
                        "approved_by",
                        "review_note",
                        "created_at",
                    )
                }
                for row in history
            ],
            key=key + "::history",
        )
        if history:
            chosen = st.selectbox(
                "Inspect version",
                list(range(len(history))),
                format_func=lambda index: str(history[index]["version"]),
                key=key + "::historical",
            )
            readable_table(history[chosen]["records"], key=key + "::history_records")


def render_foundation_overview(
    client_name: str, context: dict[str, Any], on_section: Callable[[str], None]
) -> None:
    """Show independent register states; failed reads never appear as zero.

    Args:
        client_name: Tenant.
        context: Current engagement/scope.
        on_section: Deferred local navigation callback.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate.
    """
    from securescope.ui.grc_workspace.overview import render_overview

    render_overview(client_name, context, on_section)


def render_access_notice(client_name: str) -> None:
    """Link to administration without displaying authentication forms in Foundation.

    Args:
        client_name: Active workspace name.
    Returns:
        None.
    Raises:
        Unexpected errors propagate; known membership failures are displayed.
    """
    from securescope.ui.navigation_runtime import navigate_to

    try:
        if get_workspace_role(client_name, current_actor()):
            return
    except ERRORS as exc:
        st.warning(f"Workspace access could not be checked: {exc}")
    else:
        st.warning("Local sign-in or administrator setup is required for this workspace.")
    if st.button("Open administration", key=f"foundation_admin_link::{client_name}"):
        navigate_to("Client Workspace")
