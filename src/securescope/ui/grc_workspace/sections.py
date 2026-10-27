"""Record-first Programme Setup section renderers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pandas as pd
import streamlit as st

from securescope.ui.components.primitives import status_pill

from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.grc.program_progress_service import calculate_program_progress
from securescope.ui.components import (
    render_programme_workflow,
    render_register_header,
    render_register_table,
    render_status_badge,
)
from securescope.ui.grc_workspace.dialogs import (
    render_climate_dialog,
    render_context_issue_dialog,
    render_create_engagement_dialog,
    render_engagement_role_dialog,
    render_interested_party_dialog,
    render_milestone_dialog,
    render_organizational_unit_dialog,
    render_raci_dialog,
    render_requirement_dialog,
    render_scope_approval_dialog,
)
from securescope.ui.grc_workspace.discovery import select_discovery_task
from securescope.ui.grc_workspace.scope_editor import start_scope_editor
from securescope.ui.navigation_runtime import navigate_to

SERVICE = GrcWorkspaceService()


def _safe_frame(
    rows: Sequence[Mapping[str, Any]],
    columns: Mapping[str, str],
) -> pd.DataFrame:
    """Create a stable consultant-facing frame from repository rows.

    Args:
        rows: Repository rows.
        columns: Source-field to display-label mapping.

    Returns:
        Data frame containing the requested display columns.

    Raises:
        No exceptions are raised.
    """

    prepared = [
        {display_name: row.get(source_name) for source_name, display_name in columns.items()}
        for row in rows
    ]
    return pd.DataFrame(prepared, columns=list(columns.values()))


def _section_header(
    title: str,
    caption: str,
    *,
    action_label: str | None = None,
    action_icon: str = ":material/add:",
    action_key: str | None = None,
) -> bool:
    """Render one section heading and optional primary action.

    Args:
        title: Section title.
        caption: Short explanatory text.
        action_label: Optional action button label.
        action_icon: Streamlit Material icon string.
        action_key: Stable action widget key.

    Returns:
        ``True`` when the optional action was clicked.

    Raises:
        No exceptions are raised.
    """

    if not action_label:
        st.markdown(f"## {title}")
        st.caption(caption)
        return False
    copy_column, action_column = st.columns(
        [4, 1],
        gap="medium",
        vertical_alignment="center",
    )
    with copy_column:
        st.markdown(f"## {title}")
        st.caption(caption)
    with action_column:
        return st.button(
            action_label,
            icon=action_icon,
            type="primary",
            width="stretch",
            key=action_key,
        )


# Legacy compatibility only: excluded from the active Programme Foundation router.
def legacy_render_setup_overview(
    context: Mapping[str, Any],
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    on_section: Callable[[str], None],
) -> None:
    """Render the Stitch-aligned Programme Foundation overview.

    The overview is intentionally review-first. It exposes the programme state
    and the next professional decision while the complete formal registers stay
    available in their dedicated sections.

    Args:
        context: Resolved client, engagement, and scope context.
        registers: Overview-only climate and milestone rows.
        on_section: Callback that opens another setup section.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    overview = context["overview"]
    snapshot = calculate_program_progress(
        overview,
        registers.get("climate_determinations", ()),
        registers.get("milestones", ()),
    )
    item_by_key = {item.key: item for item in snapshot.items}

    incomplete = [item for item in snapshot.items if not item.complete]
    discovery_incomplete = [
        item for item in incomplete if item.key in {"context", "parties", "requirements"}
    ]
    if not incomplete:
        primary_label = "Continue to Control Assurance"
        primary_section = None
    elif discovery_incomplete:
        primary_label = "Continue Discovery"
        primary_section = "discovery"
    elif not item_by_key["scope"].complete:
        primary_label = "Review ISMS Scope"
        primary_section = "scope"
    elif not item_by_key["raci"].complete:
        primary_label = "Review Responsibilities"
        primary_section = "roles"
    else:
        primary_label = "Review Programme"
        primary_section = incomplete[0].section

    title_column, progress_column, action_column = st.columns(
        [3.5, 1.1, 1.25],
        gap="medium",
        vertical_alignment="center",
    )
    with title_column:
        st.markdown("## Programme Foundation")
        st.caption(
            "Define the organization context, interested parties, ISMS scope "
            "and responsibilities before control assurance."
        )
    with progress_column:
        st.caption("FOUNDATION PROGRESS")
        st.progress(snapshot.percentage / 100, text=f"{snapshot.percentage}%")
    with action_column:
        if st.button(
            primary_label,
            type="primary",
            width="stretch",
            key="programme_foundation_primary_action",
        ):
            if primary_section is None:
                navigate_to("Gap Assessment")
            else:
                on_section(primary_section)
            st.rerun()

    if not item_by_key["context"].complete or not item_by_key["parties"].complete:
        workflow_step = "Discover"
    elif not item_by_key["scope"].complete or not item_by_key["raci"].complete:
        workflow_step = "Review"
    elif incomplete:
        workflow_step = "Approve"
    else:
        workflow_step = "Approve"
    render_programme_workflow(workflow_step)

    review_column, information_column = st.columns([2, 1], gap="large")
    area_specs = (
        (
            "Organizational Context",
            "Internal and external issues relevant to the ISMS purpose and strategic direction.",
            "context",
            item_by_key["context"].complete and item_by_key["climate"].complete,
        ),
        (
            "Interested Parties",
            "Stakeholders relevant to the ISMS and their applicable requirements.",
            "parties",
            item_by_key["parties"].complete and item_by_key["requirements"].complete,
        ),
        (
            "ISMS Scope",
            (
                "Boundaries, organizational units, locations, technologies and "
                "approved scope statement."
            ),
            "scope",
            item_by_key["scope"].complete,
        ),
        (
            "Roles & Responsibilities",
            "Accountable and responsible workspace members for the active programme.",
            "roles",
            item_by_key["raci"].complete,
        ),
    )

    with review_column:
        st.markdown("### Foundation areas")
        st.caption(
            "Review the prepared information and keep the formal registers as the source of record."
        )
        first_row = st.columns(2, gap="medium")
        second_row = st.columns(2, gap="medium")
        for index, (title, description, section, complete) in enumerate(area_specs):
            target_column = (first_row + second_row)[index]
            with target_column:
                with st.container(border=True, key=f"foundation_area::{section}"):
                    status_label = "Complete" if complete else "Review pending"
                    tone = "green" if complete else "blue"
                    st.markdown(f"#### {title}")
                    st.markdown(f":{tone}-badge[{status_label}]")
                    st.caption(description)
                    if st.button(
                        "Review details",
                        width="stretch",
                        key=f"foundation_area_action::{section}",
                    ):
                        on_section(section)
                        st.rerun()

    with information_column:
        st.markdown("### Needs Information")
        st.caption(
            (
                "Only missing programme information is shown here; amber means "
                "input is required, not a compliance failure."
            )
        )
        if not incomplete:
            st.success("Foundation information is complete and ready for the next assurance stage.")
        else:
            for item in incomplete[:3]:
                with st.container(border=True, key=f"foundation_missing::{item.key}"):
                    st.markdown(f"#### :orange[○] {item.label}")
                    st.caption(item.action)
                    if st.button(
                        "Provide details",
                        width="stretch",
                        key=f"foundation_missing_action::{item.key}",
                    ):
                        on_section(item.section)
                        st.rerun()
            if len(incomplete) > 3:
                st.caption(f"{len(incomplete) - 3} additional foundation items remain.")

    with st.expander("Foundation register", expanded=False):
        checklist = pd.DataFrame(
            [
                {
                    "Required item": item.label,
                    "State": "Complete" if item.complete else "Needs review",
                    "Section": item.section.replace("parties", "Interested Parties").title(),
                    "Next action": "—" if item.complete else item.action,
                }
                for item in snapshot.items
            ]
        )
        render_register_table(
            checklist,
            empty_title="No foundation status available",
            empty_message="The programme foundation could not be calculated.",
            key="programme_setup_checklist",
            title="Foundation status",
            description=(
                "Only explicit ISO programme-foundation requirements contribute " "to progress."
            ),
            show_row_count=True,
        )


def render_engagement_section(
    client_name: str,
    context: Mapping[str, Any],
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
    engagement_state_key: str,
) -> None:
    """Render the active certification cycle and its milestones.

    Args:
        client_name: Active client workspace name.
        context: Resolved GRC context.
        registers: Engagement-only member and milestone rows.
        actor: Current audit principal.
        engagement_state_key: State key updated after engagement creation.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    _section_header(
        "Engagement",
        "Review the active certification cycle and maintain the milestones that "
        "drive delivery, audit, and certification readiness.",
    )

    engagement = context["overview"]["engagement"]
    with st.container(border=True):
        st.markdown("### Active certification cycle")
        details = st.columns(4, gap="small")
        values = (
            ("Reference", engagement.get("reference") or "—"),
            ("Type", engagement.get("engagement_type") or "—"),
            ("Status", engagement.get("status") or "—"),
            ("Target standard", engagement.get("target_standard") or "—"),
        )
        for column, (label, value) in zip(details, values):
            with column, st.container(border=True):
                st.caption(label)
                if label == "Status":
                    st.markdown(status_pill(str(value)), unsafe_allow_html=True)
                else:
                    st.write(str(value))
        st.markdown("**Objective**")
        st.caption(str(engagement.get("objective") or "No objective recorded."))

    milestones = list(registers.get("milestones", ()))
    add_milestone = render_register_header(
        "Milestones",
        "Workshops, reviews, internal audits, and certification dates for this cycle.",
        row_count=len(milestones),
        action_label="Add milestone",
        action_icon=":material/add_task:",
        action_type="primary",
        action_key="programme_add_milestone",
    )
    if add_milestone:
        render_milestone_dialog(
            client_name,
            int(context["selected_engagement_id"]),
            registers.get("workspace_members", ()),
            actor,
        )
    milestone_frame = _safe_frame(
        milestones,
        {
            "title": "Milestone",
            "milestone_type": "Type",
            "owner_name": "Owner",
            "due_date": "Due date",
            "status": "Status",
            "acceptance_criteria": "Acceptance criteria",
        },
    )
    render_register_table(
        milestone_frame,
        empty_title="No milestones scheduled",
        empty_message=("Add the next workshop, review, internal audit, or certification date."),
        key="programme_milestone_register",
    )

    render_engagement_team(
        client_name, int(context["selected_engagement_id"]), registers, actor=actor
    )

    with st.expander("Engagement administration", expanded=False):
        st.caption(
            "Creating another engagement starts a separate certification or consulting "
            "cycle. It does not replace the active engagement automatically."
        )
        create_clicked = st.button(
            "Create another engagement",
            icon=":material/add_business:",
            type="secondary",
            key="programme_new_engagement",
        )
        if create_clicked:
            render_create_engagement_dialog(client_name, actor, engagement_state_key)


# Legacy compatibility only: excluded from the active Programme Foundation router.
def legacy_render_context_section(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
    on_section: Callable[[str], None],
) -> None:
    """Render context and climate registers with a recommendation-first workflow.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        registers: Context-only repository rows.
        actor: Current audit principal.
        on_section: Programme Setup navigation callback.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    _section_header(
        "Organizational Context",
        "Review the formal internal and external conditions that can affect the ISMS. "
        "Use Discovery first when the organization profile can prepare likely issues.",
    )
    with st.container(border=True):
        copy, suggested, manual = st.columns([4, 1, 1], vertical_alignment="center")
        with copy:
            st.markdown("**Preferred workflow**")
            st.caption(
                "Review prepared suggestions first. Add an issue manually only when it "
                "cannot be derived from the organization profile."
            )
        with suggested:
            review_suggestions = st.button(
                "Review suggestions",
                icon=":material/auto_awesome:",
                type="primary",
                width="stretch",
                key="programme_context_review_suggestions",
            )
        with manual:
            add_issue = st.button(
                "Add manually",
                icon=":material/add:",
                type="secondary",
                width="stretch",
                key="programme_add_context_issue",
            )
    if review_suggestions:
        select_discovery_task(client_name, engagement_id, "context")
        on_section("discovery")
        st.rerun()
    if add_issue:
        render_context_issue_dialog(client_name, engagement_id, scope_id, actor)

    filter_columns = st.columns([2, 1, 1])
    with filter_columns[0]:
        search = st.text_input(
            "Search issues",
            placeholder="Search issue, category, or owner",
            key="programme_context_search",
        )
    with filter_columns[1]:
        issue_type_filter = st.selectbox(
            "Type",
            ("All", "Internal", "External"),
            key="programme_context_type_filter",
        )
    with filter_columns[2]:
        relevance_filter = st.selectbox(
            "Relevance",
            ("All", "Relevant", "Not relevant", "Under review"),
            key="programme_context_relevance_filter",
        )
    issues = list(registers.get("context_issues", ()))
    needle = search.strip().casefold()
    filtered = [
        row
        for row in issues
        if (
            not needle
            or needle
            in " ".join(
                str(row.get(field) or "") for field in ("title", "category", "owner", "description")
            ).casefold()
        )
        and (issue_type_filter == "All" or row.get("issue_type") == issue_type_filter)
        and (relevance_filter == "All" or row.get("relevance") == relevance_filter)
    ]
    render_register_table(
        _safe_frame(
            filtered,
            {
                "title": "Issue",
                "issue_type": "Type",
                "category": "Category",
                "relevance": "Relevance",
                "owner": "Owner",
                "review_date": "Review date",
                "status": "Status",
            },
        ),
        empty_title="No context issues match this view",
        empty_message=(
            "Review SecureScope suggestions, adjust the filters, or add an issue " "manually."
        ),
        key="programme_context_register",
        title="Context register",
        description=("Formal Clause 4.1 context issues for the active engagement and scope."),
        show_row_count=True,
    )

    render_climate_details(client_name, engagement_id, scope_id, registers, actor=actor)


def render_climate_details(client_name, engagement_id, scope_id, registers, *, actor):
    """Maintain the existing climate determination without duplicating Context.

    Args:
        client_name: str: Exact active client workspace name.
        engagement_id: int: Selected engagement identifier.
        scope_id: int | None: Selected ISMS scope identifier.
        registers: dict: Section-specific canonical repository rows.
        actor: str: Trusted current workspace identity.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    climate_rows = list(registers.get("climate_determinations", ()))
    climate_label = "Record determination" if not climate_rows else "Record new version"
    record_climate = render_register_header(
        "Climate-change relevance",
        "Maintain the explicit management-system determination required by the "
        "programme foundation.",
        row_count=len(climate_rows),
        action_label=climate_label,
        action_icon=":material/eco:",
        action_type="secondary",
        action_key="programme_record_climate",
    )
    if record_climate:
        render_climate_dialog(client_name, engagement_id, scope_id, actor)
    if climate_rows:
        latest = climate_rows[0]
        with st.container(border=True):
            detail_columns = st.columns(4)
            climate_values = (
                ("Version", latest.get("version_number") or "—"),
                ("Determination", latest.get("determination") or "—"),
                ("Determined by", latest.get("determined_by") or "—"),
                ("Next review", latest.get("next_review_date") or "—"),
            )
            for column, (label, value) in zip(detail_columns, climate_values):
                with column:
                    st.metric(label, value)
            st.caption(str(latest.get("rationale") or "No rationale recorded."))
    else:
        with st.container(border=True):
            st.markdown("**No climate determination recorded**")
            st.caption(
                "Record the determination when the reviewer has enough " "organizational context."
            )


# Legacy compatibility only: excluded from the active Programme Foundation router.
def legacy_render_parties_section(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
    on_section: Callable[[str], None],
) -> None:
    """Render interested parties and selected-party requirements.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        registers: Interested-party rows for the active context.
        actor: Current audit principal.
        on_section: Programme Setup navigation callback.

    Returns:
        None.

    Raises:
        No exceptions are raised; requirement-read failures become UI messages.
    """

    _section_header(
        "Interested Parties",
        "Review formal stakeholders and the requirements that become applicable to "
        "the ISO programme. Discovery can prepare a starter set from organization "
        "facts.",
    )
    with st.container(border=True):
        copy, suggested, manual = st.columns([4, 1, 1], vertical_alignment="center")
        with copy:
            st.markdown("**Preferred workflow**")
            st.caption(
                "Start with suggested parties and requirements. Use manual "
                "creation for "
                "client-specific stakeholders that SecureScope cannot infer."
            )
        with suggested:
            review_suggestions = st.button(
                "Review suggestions",
                icon=":material/auto_awesome:",
                type="primary",
                width="stretch",
                key="programme_parties_review_suggestions",
            )
        with manual:
            add_party = st.button(
                "Add manually",
                icon=":material/person_add:",
                type="secondary",
                width="stretch",
                key="programme_add_interested_party",
            )
    if review_suggestions:
        select_discovery_task(client_name, engagement_id, "parties")
        on_section("discovery")
        st.rerun()
    if add_party:
        render_interested_party_dialog(client_name, engagement_id, scope_id, actor)

    parties = list(registers.get("interested_parties", ()))
    filter_columns = st.columns([2, 1])
    with filter_columns[0]:
        search = st.text_input(
            "Search parties",
            placeholder="Search party, type, owner, or need",
            key="programme_party_search",
        )
    party_types = sorted(
        {str(row.get("party_type") or "") for row in parties if row.get("party_type")}
    )
    with filter_columns[1]:
        type_filter = st.selectbox(
            "Party type",
            ["All", *party_types],
            key="programme_party_type_filter",
        )
    needle = search.strip().casefold()
    filtered = [
        row
        for row in parties
        if (
            not needle
            or needle
            in " ".join(
                str(row.get(field) or "")
                for field in ("name", "party_type", "owner", "needs_and_expectations")
            ).casefold()
        )
        and (type_filter == "All" or row.get("party_type") == type_filter)
    ]
    render_register_table(
        _safe_frame(
            filtered,
            {
                "name": "Interested party",
                "party_type": "Type",
                "needs_and_expectations": "Needs and expectations",
                "applicable_requirement_count": "Applicable requirements",
                "owner": "Owner",
                "status": "Status",
            },
        ),
        empty_title="No interested parties match this view",
        empty_message=(
            "Review SecureScope suggestions, adjust the filters, or add a party " "manually."
        ),
        key="programme_party_register",
        title="Interested parties register",
        description="Clause 4.2 stakeholders and their needs for the active programme.",
        show_row_count=True,
    )
    if not parties:
        return

    party_by_id = {int(row["id"]): row for row in parties}
    st.markdown("### Applicable requirements")
    st.caption("Choose one interested party to review only the requirements linked to it.")
    detail_columns = st.columns([3, 1], vertical_alignment="bottom")
    with detail_columns[0]:
        selected_party_id = st.selectbox(
            "Interested party",
            list(party_by_id),
            format_func=lambda value: (
                f"{party_by_id[int(value)]['name']} · " f"{party_by_id[int(value)]['party_type']}"
            ),
            key=f"programme_requirement_party_{client_name}_{engagement_id}",
        )
    selected_party = party_by_id[int(selected_party_id)]
    with detail_columns[1]:
        add_requirement = st.button(
            "Add requirement",
            icon=":material/add_task:",
            type="secondary",
            width="stretch",
            key="programme_add_party_requirement",
        )
    if add_requirement:
        render_requirement_dialog(
            client_name,
            engagement_id,
            scope_id,
            int(selected_party_id),
            str(selected_party.get("name") or "Interested party"),
            actor,
        )
    try:
        requirements = SERVICE.load_party_requirements(
            client_name,
            engagement_id,
            int(selected_party_id),
        )
    except GrcWorkspaceServiceError as exc:
        st.error(f"Party requirements are unavailable: {exc}")
        requirements = []
    render_register_table(
        _safe_frame(
            requirements,
            {
                "requirement": "Requirement",
                "requirement_type": "Type",
                "applicability": "Applicability",
                "mandatory": "Mandatory",
                "owner": "Owner",
                "review_date": "Review date",
                "source_reference": "Source",
            },
        ),
        empty_title="No requirements recorded for this party",
        empty_message=(
            "Add only legal, regulatory, contractual, or stakeholder requirements " "that apply."
        ),
        key="programme_requirement_register",
        show_row_count=False,
    )


# Legacy compatibility only: excluded from the active Programme Foundation router.
def legacy_render_scope_section(
    client_name: str,
    context: Mapping[str, Any],
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
    on_section: Callable[[str], None],
) -> None:
    """Render the controlled ISMS scope lifecycle and supporting units.

    Args:
        client_name: Active client workspace name.
        context: Resolved GRC context.
        registers: Scope-only organizational-unit rows.
        actor: Current audit principal.
        on_section: Programme Setup navigation callback.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    _section_header(
        "ISMS Scope",
        "Review the controlled scope, edit draft versions, and keep human approval "
        "separate from automated preparation.",
    )
    engagement_id = int(context["selected_engagement_id"])
    selected_scope_id = context.get("selected_scope_id")
    scopes = list(context.get("scopes", ()))
    selected_scope = next(
        (
            row
            for row in scopes
            if selected_scope_id is not None and int(row["id"]) == int(selected_scope_id)
        ),
        None,
    )
    if selected_scope:
        state = str(selected_scope.get("latest_status") or "Draft")
        tone = "success" if state == "Approved" else "warning"
        with st.container(border=True):
            heading_columns = st.columns([3, 1], vertical_alignment="center")
            with heading_columns[0]:
                st.markdown(f"### {selected_scope.get('name') or 'ISMS scope'}")
                st.caption(
                    f"{selected_scope.get('scope_code') or 'No code'} · latest "
                    f"version {selected_scope.get('latest_version_number') or '—'}"
                )
            with heading_columns[1]:
                if tone == "success":
                    render_status_badge("Approved · immutable", tone="success", icon="verified")
                else:
                    render_status_badge(
                        f"{state} · approval required",
                        tone="warning",
                        icon="pending_actions",
                    )
            st.markdown("**Formal scope statement**")
            st.write(str(selected_scope.get("scope_statement") or "Not recorded."))
            detail_columns = st.columns(3)
            details = (
                ("Locations", len(selected_scope.get("locations") or [])),
                (
                    "Organizational units",
                    len(selected_scope.get("organizational_units") or []),
                ),
                ("Technologies", len(selected_scope.get("technologies") or [])),
            )
            for column, (label, value) in zip(detail_columns, details):
                with column:
                    st.metric(label, value)
    else:
        with st.container(border=True):
            st.markdown("**No controlled scope exists yet**")
            st.caption("Use Discovery to prepare a first draft or create a version manually.")

    action_columns = st.columns([1, 1, 2])
    with action_columns[0]:
        new_version = st.button(
            "Edit scope version" if selected_scope else "Create scope version",
            icon=":material/edit_document:",
            type="secondary",
            width="content",
            key="programme_create_scope_version",
        )
    with action_columns[1]:
        prepare_scope = st.button(
            "Prepare from Discovery",
            icon=":material/auto_awesome:",
            type="secondary",
            width="content",
            key="programme_prepare_scope_from_discovery",
        )
    if new_version:
        start_scope_editor(client_name, engagement_id, selected_scope)
        st.rerun()
    if prepare_scope:
        select_discovery_task(client_name, engagement_id, "scope")
        on_section("discovery")
        st.rerun()

    can_approve = bool(
        selected_scope and selected_scope.get("latest_status") in {"Draft", "Under review"}
    )
    if can_approve and selected_scope:
        from securescope.persistence.evidence_repository import (
            EvidenceRepositoryError,
            get_workspace_role,
        )

        try:
            approval_role = get_workspace_role(client_name, actor)
        except EvidenceRepositoryError:
            st.error("Approval permissions are unavailable. Reload after checking the database.")
            approval_role = None
        scope_reviewed = st.checkbox(
            "I have reviewed this scope version",
            key=f"programme_scope_review_confirmed::{selected_scope.get('id')}"
            f"::{selected_scope.get('latest_version_number')}",
        )
        with st.container(border=True):
            decision_copy, decision_action = st.columns([4, 1], vertical_alignment="center")
            with decision_copy:
                st.markdown("**Approval decision**")
                st.caption(
                    "Approve only after the scope statement, boundaries, exclusions, "
                    "and "
                    "dependencies have been reviewed by a human assessor."
                )
            with decision_action:
                approve_scope = st.button(
                    "Approve reviewed version",
                    icon=":material/verified:",
                    type="primary",
                    width="content",
                    disabled=approval_role != "Administrator" or not scope_reviewed,
                    help="Only a workspace Administrator can approve after reviewing this scope.",
                    key="programme_approve_scope",
                )
        if approve_scope:
            render_scope_approval_dialog(
                client_name,
                engagement_id,
                selected_scope,
                actor,
            )

    render_register_table(
        _safe_frame(
            scopes,
            {
                "name": "Scope",
                "scope_code": "Code",
                "latest_version_number": "Latest version",
                "latest_status": "Status",
                "prepared_by": "Prepared by",
                "approved_by": "Approved by",
            },
        ),
        empty_title="No scope versions",
        empty_message=(
            "Prepare a first draft in Discovery or create a controlled version " "manually."
        ),
        key="programme_scope_version_register",
        title="Scope version register",
        description=("Controlled versions and approval state for the selected ISMS scope."),
        show_row_count=True,
    )

    units = list(registers.get("organizational_units", ()))
    add_unit = render_register_header(
        "Sites and organizational units",
        "Legal entities, sites, and departments used to define the organizational " "boundary.",
        row_count=len(units),
        action_label="Add site or unit",
        action_icon=":material/add_business:",
        action_type="secondary",
        action_key="programme_add_unit",
    )
    if add_unit:
        render_organizational_unit_dialog(
            client_name,
            engagement_id,
            int(selected_scope_id) if selected_scope_id is not None else None,
            units,
            actor,
        )
    render_register_table(
        _safe_frame(
            units,
            {
                "name": "Name",
                "unit_type": "Type",
                "in_scope": "In scope",
                "owner": "Owner",
                "status": "Status",
                "address": "Address",
            },
        ),
        empty_title="No sites or units registered",
        empty_message=(
            "Add only the legal entities, sites, or departments needed to describe " "the boundary."
        ),
        key="programme_organizational_unit_register",
    )


# Legacy compatibility only: excluded from the active Programme Foundation router.
def legacy_render_roles_section(
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
) -> None:
    """Render ISMS responsibilities first, then the supporting engagement team.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        scope_id: Optional selected scope identifier.
        registers: Role-only repository rows.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    _section_header(
        "Roles & RACI",
        "Assign real workspace members to accountable, responsible, consulted, and "
        "informed ISMS responsibilities. Engagement roles are maintained separately.",
    )
    workspace_members = list(registers.get("workspace_members", ()))
    if not workspace_members:
        st.warning(
            (
                "No active members yet. Complete Administrator setup above, then "
                "add members in Client Workspace."
            )
        )
        return

    role_rows = list(registers.get("role_assignments", ()))
    add_raci = render_register_header(
        "ISMS responsibility matrix",
        "The formal responsibility model used by the active scope.",
        row_count=len(role_rows),
        action_label="Assign responsibility",
        action_icon=":material/account_tree:",
        action_type="primary",
        action_key="programme_add_raci",
    )
    if add_raci:
        render_raci_dialog(
            client_name,
            engagement_id,
            scope_id,
            workspace_members,
            actor,
        )
    render_register_table(
        _safe_frame(
            role_rows,
            {
                "role_name": "ISMS role",
                "raci_type": "RACI",
                "display_name": "Person",
                "responsibility": "Responsibility",
                "status": "Status",
                "effective_from": "Effective from",
            },
        ),
        empty_title="No ISMS responsibilities assigned",
        empty_message="Assign accountable and responsible roles for the active scope.",
        key="programme_raci_register",
    )
    if role_rows:
        matrix_source = pd.DataFrame(
            [
                {
                    "ISMS role": row.get("role_name"),
                    "RACI": row.get("raci_type"),
                    "Person": row.get("display_name") or row.get("email"),
                }
                for row in role_rows
                if row.get("status") == "Active"
            ]
        )
        if not matrix_source.empty:
            with st.expander("Matrix view", expanded=False):
                matrix = matrix_source.pivot_table(
                    index="ISMS role",
                    columns="RACI",
                    values="Person",
                    aggfunc=lambda values: ", ".join(str(value) for value in values),
                    fill_value="—",
                ).reset_index()
                st.dataframe(matrix, hide_index=True, width="stretch")

    render_engagement_team(client_name, engagement_id, registers, actor=actor)


def render_engagement_team(client_name, engagement_id, registers, *, actor):
    """Maintain delivery roles separately from ISMS responsibilities.

    Args:
        client_name: str: Exact active client workspace name.
        engagement_id: int: Selected engagement identifier.
        registers: dict: Section-specific canonical repository rows.
        actor: str: Trusted current workspace identity.

    Returns:
        None.

    Raises:
        Unexpected programming errors propagate; known service failures are displayed.
    """
    workspace_members = list(registers.get("workspace_members", ()))
    engagement_rows = list(registers.get("engagement_members", ()))
    assign_engagement = render_register_header(
        "Engagement team",
        "Delivery roles for the certification or consulting cycle; these do not "
        "replace ISMS RACI assignments.",
        row_count=len(engagement_rows),
        action_label="Assign engagement role",
        action_icon=":material/person_add:",
        action_type="secondary",
        action_key="programme_assign_engagement_role",
    )
    if assign_engagement:
        render_engagement_role_dialog(
            client_name,
            engagement_id,
            workspace_members,
            actor,
        )
    render_register_table(
        _safe_frame(
            engagement_rows,
            {
                "display_name": "Person",
                "engagement_role": "Engagement role",
                "workspace_role": "Workspace role",
                "email": "Email",
            },
        ),
        empty_title="No engagement roles assigned",
        empty_message=(
            "Assign the engagement lead, consultant, sponsor, or reviewer when " "needed."
        ),
        key="programme_engagement_team_register",
    )
