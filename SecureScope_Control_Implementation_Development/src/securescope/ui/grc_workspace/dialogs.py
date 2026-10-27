"""On-demand dialogs for short ISO Programme Setup actions."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Mapping, Sequence

import streamlit as st

from securescope.grc.engagement_models import (
    ENGAGEMENT_ROLES,
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TYPES,
    ISSUE_TYPES,
    MILESTONE_TYPES,
    PARTY_TYPES,
    RACI_TYPES,
    RELEVANCE_VALUES,
    REQUIREMENT_TYPES,
    UNIT_TYPES,
    ClimateDeterminationDraft,
    ContextIssueDraft,
    EngagementDraft,
    InterestedPartyDraft,
    MilestoneDraft,
    OrganizationalUnitDraft,
    PartyRequirementDraft,
    RaciAssignmentDraft,
)
from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)

SERVICE = GrcWorkspaceService()


def _member_label(member: Mapping[str, Any]) -> str:
    """Return one readable workspace-member selector label.

    Args:
        member: Workspace membership row.

    Returns:
        Display name, email, and workspace role.

    Raises:
        No exceptions are raised.
    """

    return (
        f"{member.get('display_name') or member.get('email')} · "
        f"{member.get('email')} · {member.get('workspace_role')}"
    )


@st.dialog("New engagement / certification cycle", width="large")
def render_create_engagement_dialog(
    client_name: str,
    actor: str,
    engagement_state_key: str,
) -> None:
    """Render an on-demand engagement creation dialog.

    Args:
        client_name: Active client workspace name.
        actor: Current audit principal.
        engagement_state_key: State key updated to the created engagement.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    st.caption(
        "Create a separate ISO 27001 implementation, audit, surveillance, or "
        "recertification cycle. An initial draft scope is created with it."
    )
    with st.form("grc_dialog_create_engagement", clear_on_submit=True):
        identity_columns = st.columns(2)
        with identity_columns[0]:
            reference = st.text_input(
                "Engagement reference",
                placeholder="ISO-2027-INITIAL",
            )
            engagement_type = st.selectbox("Engagement type", ENGAGEMENT_TYPES)
            status = st.selectbox("Initial status", ENGAGEMENT_STATUSES, index=1)
        with identity_columns[1]:
            name = st.text_input(
                "Engagement name",
                placeholder="ISO 27001 Initial Certification — 2027",
            )
            target_standard = st.text_input(
                "Target standard",
                value="ISO/IEC 27001:2022",
                disabled=True,
            )
            sponsor = st.text_input("Client sponsor")
        objective = st.text_area("Objective and deliverables", height=96)
        schedule_enabled = st.checkbox("Set planned dates", value=True)
        schedule_columns = st.columns(3)
        with schedule_columns[0]:
            start_date = st.date_input("Planned start", value=date.today())
        with schedule_columns[1]:
            end_date = st.date_input(
                "Planned end",
                value=date.today() + timedelta(days=180),
            )
        with schedule_columns[2]:
            certification_date = st.date_input(
                "Certification target",
                value=date.today() + timedelta(days=210),
            )
        submitted = st.form_submit_button(
            "Create engagement",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        created = SERVICE.create_engagement(
            client_name,
            EngagementDraft(
                reference=reference,
                name=name,
                engagement_type=engagement_type,
                objective=objective,
                status=status,
                target_standard=target_standard,
                cycle_year=(start_date.year if schedule_enabled else None),
                planned_start_date=(start_date if schedule_enabled else None),
                planned_end_date=(end_date if schedule_enabled else None),
                certification_target_date=(certification_date if schedule_enabled else None),
                client_sponsor=sponsor,
            ),
            actor=actor,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.session_state[engagement_state_key] = created["engagement_id"]
    st.toast("Engagement and initial draft scope created.", icon="✅")
    st.rerun()


@st.dialog("Add programme milestone", width="large")
def render_milestone_dialog(
    client_name: str,
    engagement_id: int,
    workspace_members: Sequence[Mapping[str, Any]],
    actor: str,
) -> None:
    """Render an on-demand engagement milestone dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        workspace_members: Active users eligible to own the milestone.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    members = list(workspace_members)
    member_by_id = {int(item["user_id"]): item for item in members}
    owner_options = [None, *member_by_id]
    with st.form("grc_dialog_add_milestone", clear_on_submit=True):
        title = st.text_input("Milestone title")
        field_columns = st.columns(3)
        with field_columns[0]:
            milestone_type = st.selectbox("Milestone type", MILESTONE_TYPES)
        with field_columns[1]:
            due_date = st.date_input(
                "Due date",
                value=date.today() + timedelta(days=30),
            )
        with field_columns[2]:
            owner_user_id = st.selectbox(
                "Owner",
                owner_options,
                format_func=lambda value: (
                    "Unassigned" if value is None else _member_label(member_by_id[int(value)])
                ),
            )
        description = st.text_area("Description", height=88)
        acceptance_criteria = st.text_area("Acceptance criteria", height=88)
        submitted = st.form_submit_button(
            "Create milestone",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_milestone(
            client_name,
            engagement_id,
            MilestoneDraft(
                title=title,
                milestone_type=milestone_type,
                description=description,
                due_date=due_date,
                acceptance_criteria=acceptance_criteria,
                owner_user_id=owner_user_id,
            ),
            actor=actor,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Programme milestone created.", icon="✅")
    st.rerun()


@st.dialog("Add context issue", width="large")
def render_context_issue_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Render an on-demand organizational-context issue dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    from securescope.ui.grc_workspace.record_edit import CONTEXT_CATEGORIES

    issue_type = st.selectbox("Issue type", ISSUE_TYPES, key="new_context_type")
    category = st.selectbox("Category", CONTEXT_CATEGORIES[issue_type], key="new_context_category")
    with st.form("grc_dialog_add_context_issue", clear_on_submit=True):
        if category == "Other":
            category = st.text_input("Other category")
        relevance = st.selectbox("Relevance", RELEVANCE_VALUES)
        title = st.text_input("Issue title")
        description_columns = st.columns(2)
        with description_columns[0]:
            description = st.text_area("Issue description", height=112)
        with description_columns[1]:
            effect_on_isms = st.text_area("Effect on the ISMS", height=112)
        owner_columns = st.columns(2)
        with owner_columns[0]:
            owner = st.text_input("Issue owner", value=actor)
        with owner_columns[1]:
            review_date = st.date_input(
                "Review date",
                value=date.today() + timedelta(days=90),
            )
        submitted = st.form_submit_button(
            "Create issue",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_context_issue(
            client_name,
            engagement_id,
            ContextIssueDraft(
                issue_type=issue_type,
                category=category,
                title=title,
                description=description,
                effect_on_isms=effect_on_isms,
                relevance=relevance,
                owner=owner,
                review_date=review_date,
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Context issue created.", icon="✅")
    st.rerun()


@st.dialog("Record climate determination", width="large")
def render_climate_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Render a versioned climate-relevance determination dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    with st.form("grc_dialog_climate_determination", clear_on_submit=True):
        determination = st.selectbox("Determination", RELEVANCE_VALUES)
        rationale = st.text_area("Rationale", height=104)
        impacts = st.text_area("Identified impacts or dependencies", height=88)
        date_columns = st.columns(3)
        with date_columns[0]:
            determined_by = st.text_input("Determined by", value=actor)
        with date_columns[1]:
            determination_date = st.date_input(
                "Determination date",
                value=date.today(),
            )
        with date_columns[2]:
            next_review_date = st.date_input(
                "Next review date",
                value=date.today() + timedelta(days=365),
            )
        submitted = st.form_submit_button(
            "Create determination version",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_climate_determination(
            client_name,
            engagement_id,
            ClimateDeterminationDraft(
                determination=determination,
                rationale=rationale,
                identified_impacts=impacts,
                determined_by=determined_by,
                determination_date=determination_date,
                next_review_date=next_review_date,
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Climate determination version created.", icon="✅")
    st.rerun()


@st.dialog("Add interested party", width="large")
def render_interested_party_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Render an on-demand interested-party creation dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    with st.form("grc_dialog_add_interested_party", clear_on_submit=True):
        st.markdown("#### Basic information")
        identity_columns = st.columns(2)
        with identity_columns[0]:
            name = st.text_input("Party name *")
            party_type = st.selectbox("Party type *", PARTY_TYPES)
        with identity_columns[1]:
            owner = st.text_input("Party owner", value=actor)
            st.caption("Status: Active")
        st.markdown("#### Relationship")
        communication_method = st.text_input("Communication method")
        relationship = st.text_area("Relationship description", height=88)
        st.markdown("#### ISMS relevance")
        needs = st.text_area("Needs and expectations", height=104)
        submitted = st.form_submit_button(
            "Create Party",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_interested_party(
            client_name,
            engagement_id,
            InterestedPartyDraft(
                name=name,
                party_type=party_type,
                relationship_description=relationship,
                needs_and_expectations=needs,
                communication_method=communication_method,
                owner=owner,
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Interested party created.", icon="✅")
    st.rerun()


@st.dialog("Add party requirement", width="large")
def render_requirement_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    party_id: int,
    party_name: str,
    actor: str,
) -> None:
    """Render an on-demand interested-party requirement dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        party_id: Tenant-owned interested-party identifier.
        party_name: Display name used in the dialog caption.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    st.caption(f"Requirement for {party_name}")
    with st.form("grc_dialog_add_party_requirement", clear_on_submit=True):
        requirement_type = st.selectbox("Requirement type", REQUIREMENT_TYPES)
        requirement = st.text_area("Requirement", height=112)
        source_reference = st.text_input("Source reference")
        control_columns = st.columns(3)
        with control_columns[0]:
            applicability = st.selectbox(
                "Applicability",
                ("Applicable", "Under review", "Not applicable"),
            )
        with control_columns[1]:
            owner = st.text_input("Requirement owner", value=actor)
        with control_columns[2]:
            review_date = st.date_input(
                "Review date",
                value=date.today() + timedelta(days=365),
            )
        mandatory = st.checkbox("Mandatory requirement", value=True)
        submitted = st.form_submit_button(
            "Create requirement",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_party_requirement(
            client_name,
            engagement_id,
            party_id,
            PartyRequirementDraft(
                requirement_type=requirement_type,
                requirement=requirement,
                source_reference=source_reference,
                applicability=applicability,
                mandatory=mandatory,
                owner=owner,
                review_date=review_date,
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Interested-party requirement created.", icon="✅")
    st.rerun()


@st.dialog("Add site or organizational unit", width="large")
def render_organizational_unit_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    units: Sequence[Mapping[str, Any]],
    actor: str,
    *,
    default_type: str | None = None,
) -> None:
    """Render an organizational-unit creation dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        units: Existing units eligible to be parents.
        actor: Current audit principal.
        default_type: Boundary type suggested by the entry action.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    unit_by_id = {int(item["id"]): item for item in units}
    parent_options = [None, *unit_by_id]
    with st.form("grc_dialog_add_organizational_unit", clear_on_submit=True):
        identity_columns = st.columns(2)
        with identity_columns[0]:
            unit_type = st.selectbox(
                "Unit type",
                UNIT_TYPES,
                index=UNIT_TYPES.index(default_type) if default_type in UNIT_TYPES else 0,
            )
            name = st.text_input("Unit name")
        with identity_columns[1]:
            owner = st.text_input("Unit owner")
            parent_id = st.selectbox(
                "Parent unit",
                parent_options,
                format_func=lambda value: (
                    "No parent"
                    if value is None
                    else f"{unit_by_id[int(value)]['name']} · "
                    f"{unit_by_id[int(value)]['unit_type']}"
                ),
            )
        description = st.text_area("Description", height=88)
        address = st.text_input("Address")
        in_scope = st.checkbox("Included in this scope", value=True)
        submitted = st.form_submit_button(
            "Create organizational unit",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.create_organizational_unit(
            client_name,
            engagement_id,
            OrganizationalUnitDraft(
                unit_type=unit_type,
                name=name,
                description=description,
                address=address,
                in_scope=in_scope,
                owner=owner,
                parent_unit_id=parent_id,
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Organizational unit created.", icon="✅")
    st.rerun()


@st.dialog("Approve immutable scope version", width="large")
def render_scope_approval_dialog(
    client_name: str,
    engagement_id: int,
    scope: Mapping[str, Any],
    actor: str,
) -> None:
    """Render the human scope approval confirmation dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope: Selected scope definition and latest-version metadata.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    st.warning(
        "Approval freezes this version. Later changes must create a new version, "
        "and the previous audit version remains reproducible."
    )
    with st.form("grc_dialog_approve_scope"):
        st.text_input("Scope", value=str(scope.get("name") or ""), disabled=True)
        st.text_input(
            "Version",
            value=str(scope.get("latest_version_number") or "—"),
            disabled=True,
        )
        approver_email = st.text_input("Approver email", value=actor, disabled=True)
        comment = st.text_area("Approval rationale", height=104)
        confirmed = st.checkbox(
            "I reviewed the boundaries, exclusions, interfaces, and dependencies."
        )
        submitted = st.form_submit_button(
            "Approve and freeze version",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    if not confirmed:
        st.error("Confirm you reviewed the scope before approving.")
        return
    try:
        SERVICE.approve_scope_version(
            client_name,
            engagement_id,
            int(scope["id"]),
            int(scope["latest_version_id"]),
            approver_email=approver_email,
            comment=comment,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Scope version approved and frozen.", icon="✅")
    st.rerun()


@st.dialog("Assign engagement role", width="large")
def render_engagement_role_dialog(
    client_name: str,
    engagement_id: int,
    workspace_members: Sequence[Mapping[str, Any]],
    actor: str,
) -> None:
    """Render an engagement-role assignment dialog.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        workspace_members: Active workspace users.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    member_by_id = {int(item["user_id"]): item for item in workspace_members}
    if not member_by_id:
        st.warning("Add an active workspace member before assigning roles.")
        return
    with st.form("grc_dialog_assign_engagement_role"):
        user_id = st.selectbox(
            "Workspace member",
            list(member_by_id),
            format_func=lambda value: _member_label(member_by_id[int(value)]),
        )
        engagement_role = st.selectbox("Engagement role", ENGAGEMENT_ROLES)
        submitted = st.form_submit_button(
            "Assign role",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.assign_engagement_member(
            client_name,
            engagement_id,
            int(user_id),
            engagement_role,
            actor=actor,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Engagement role assigned.", icon="✅")
    st.rerun()


@st.dialog("Add RACI assignment", width="large")
def render_raci_dialog(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    workspace_members: Sequence[Mapping[str, Any]],
    actor: str,
) -> None:
    """Render an ISMS RACI assignment dialog backed by real users.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        workspace_members: Active workspace users.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    member_by_id = {int(item["user_id"]): item for item in workspace_members}
    if not member_by_id:
        st.warning("Add an active workspace member before assigning RACI roles.")
        return
    with st.form("grc_dialog_add_raci"):
        identity_columns = st.columns(2)
        with identity_columns[0]:
            user_id = st.selectbox(
                "Assigned member",
                list(member_by_id),
                format_func=lambda value: _member_label(member_by_id[int(value)]),
            )
            role_name = st.text_input(
                "ISMS role",
                placeholder="ISMS Manager, Risk Owner, Control Owner...",
            )
        with identity_columns[1]:
            raci_type = st.selectbox("RACI type", RACI_TYPES)
            effective_from = st.date_input("Effective from", value=date.today())
        responsibility = st.text_area("Responsibility", height=104)
        authority = st.text_area("Authority and decision rights", height=88)
        has_end_date = st.checkbox("Set an end date")
        effective_to = st.date_input(
            "Effective to",
            value=date.today() + timedelta(days=365),
            disabled=not has_end_date,
        )
        submitted = st.form_submit_button(
            "Create RACI assignment",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        SERVICE.assign_raci_role(
            client_name,
            engagement_id,
            RaciAssignmentDraft(
                user_id=int(user_id),
                role_name=role_name,
                responsibility=responsibility,
                raci_type=raci_type,
                authority=authority,
                effective_from=effective_from,
                effective_to=(effective_to if has_end_date else None),
            ),
            actor=actor,
            scope_id=scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.toast("ISMS RACI assignment created.", icon="✅")
    st.rerun()
