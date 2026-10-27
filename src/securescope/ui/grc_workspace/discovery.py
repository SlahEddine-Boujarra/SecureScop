"""Guided organization discovery and deterministic programme-foundation proposals."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import streamlit as st

from securescope.ui.components.navigation import section_navigation
from securescope.ui.components.primitives import status_pill

from securescope.grc.engagement_models import (
    ContextIssueDraft,
    InterestedPartyDraft,
    PartyRequirementDraft,
)
from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.grc.organization_knowledge_service import (
    ContextRecommendation,
    OrganizationKnowledgeService,
    OrganizationKnowledgeServiceError,
    PartyRecommendation,
)
from securescope.grc.organization_models import (
    EMPLOYEE_BANDS,
    INFRASTRUCTURE_MODELS,
    OrganizationProfileDraft,
)
from securescope.ui.workflow_sections import workflow_section

GRC_SERVICE = GrcWorkspaceService()
KNOWLEDGE_SERVICE = OrganizationKnowledgeService()

INDUSTRIES = (
    "Software / SaaS",
    "IT services",
    "Financial services",
    "Healthcare",
    "Manufacturing",
    "Professional services",
    "Retail / E-commerce",
    "Telecommunications",
    "Public sector",
    "Other",
)
DEPARTMENTS = (
    "Top Management",
    "IT",
    "Information Security",
    "Engineering / Development",
    "Operations",
    "Customer Support",
    "Sales",
    "Finance",
    "HR / People",
    "Legal / Compliance",
    "Procurement",
)
TECHNOLOGIES = (
    "AWS",
    "Microsoft Azure",
    "Google Cloud",
    "Microsoft 365",
    "Google Workspace",
    "GitHub",
    "GitLab",
    "Active Directory",
    "PostgreSQL",
    "MySQL",
    "Wazuh",
    "VMware",
)
CUSTOMER_MARKETS = (
    "Tunisia",
    "European Union / Europe",
    "United Kingdom",
    "North America",
    "Middle East",
    "Africa",
    "Global",
)
CERTIFICATION_DRIVERS = (
    "Customer requirement",
    "Tender / procurement requirement",
    "Regulatory expectation",
    "Internal security improvement",
    "Market trust / assurance",
    "Board / management objective",
)

DISCOVERY_TASKS = {
    "context": ":material/hub: Context suggestions",
    "parties": ":material/groups: Interested parties",
    "scope": ":material/select_all: Scope composer",
}


def discovery_task_state_key(client_name: str, engagement_id: int) -> str:
    """Return the stable discovery-work selector key.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Namespaced Streamlit session-state key.

    Raises:
        No exceptions are raised.
    """

    return f"programme_discovery_task::{client_name}::{engagement_id}"


def select_discovery_task(
    client_name: str,
    engagement_id: int,
    task: str,
) -> None:
    """Select one validated discovery task for the current programme.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        task: Stable discovery-task identifier.

    Returns:
        None.

    Raises:
        No exceptions are raised; unsupported tasks fall back to context.
    """

    resolved = task if task in DISCOVERY_TASKS else "context"
    st.session_state[discovery_task_state_key(client_name, engagement_id)] = resolved


def _csv_values(value: str) -> tuple[str, ...]:
    """Split a short comma/newline separated input into unique values.

    Args:
        value: User-entered compact list.

    Returns:
        Ordered duplicate-free tuple.

    Raises:
        No exceptions are raised.
    """

    result: list[str] = []
    seen: set[str] = set()
    normalized = str(value or "").replace("\n", ",")
    for item in normalized.split(","):
        text = item.strip()
        marker = text.casefold()
        if not text or marker in seen:
            continue
        seen.add(marker)
        result.append(text)
    return tuple(result)


def _profile_list(profile: Mapping[str, Any] | None, key: str) -> list[str]:
    """Normalize a stored JSON list for Streamlit widget defaults.

    Args:
        profile: Optional profile mapping.
        key: JSON/list field name.

    Returns:
        List of non-empty strings.

    Raises:
        No exceptions are raised.
    """

    if not profile:
        return []
    value = profile.get(key) or []
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(item) for item in value if str(item).strip()]


def _known_options(values: Sequence[str], options: Sequence[str]) -> list[str]:
    """Keep stored values that are still valid predefined options.

    Args:
        values: Stored profile values.
        options: Current widget vocabulary.

    Returns:
        Valid widget default values.

    Raises:
        No exceptions are raised.
    """

    allowed = set(options)
    return [value for value in values if value in allowed]


def _other_values(values: Sequence[str], options: Sequence[str]) -> str:
    """Serialize profile values outside the predefined vocabulary.

    Args:
        values: Stored values.
        options: Current predefined options.

    Returns:
        Comma-separated custom values.

    Raises:
        No exceptions are raised.
    """

    allowed = set(options)
    return ", ".join(value for value in values if value not in allowed)


def _render_profile_form(
    client_name: str,
    engagement_id: int,
    profile: Mapping[str, Any] | None,
    actor: str,
) -> None:
    """Render the compact organization quick-profile form.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        profile: Current persisted profile, if any.
        actor: Current audit principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service errors become UI messages.
    """

    existing_industry = str((profile or {}).get("industry") or "Software / SaaS")
    industry_default = existing_industry if existing_industry in INDUSTRIES else "Other"
    existing_departments = _profile_list(profile, "departments")
    existing_technologies = _profile_list(profile, "technologies")
    existing_markets = _profile_list(profile, "customer_markets")
    existing_drivers = _profile_list(profile, "certification_drivers")

    with st.form("organization_quick_profile"):
        st.markdown("#### 1. Tell SecureScope what you already know")
        st.caption(
            "This is a short business profile, not an ISO questionnaire. Unknown "
            "information can be added later."
        )
        first = st.columns(3, gap="medium")
        with first[0]:
            industry_choice = st.selectbox(
                "Industry",
                INDUSTRIES,
                index=INDUSTRIES.index(industry_default),
            )
        with first[1]:
            employee_band = st.selectbox(
                "Employees",
                EMPLOYEE_BANDS,
                index=EMPLOYEE_BANDS.index(
                    str((profile or {}).get("employee_band") or "Unknown")
                    if str((profile or {}).get("employee_band") or "Unknown") in EMPLOYEE_BANDS
                    else "Unknown"
                ),
            )
        with first[2]:
            infrastructure_model = st.selectbox(
                "Infrastructure",
                INFRASTRUCTURE_MODELS,
                index=INFRASTRUCTURE_MODELS.index(
                    str((profile or {}).get("infrastructure_model") or "Unknown")
                    if str((profile or {}).get("infrastructure_model") or "Unknown")
                    in INFRASTRUCTURE_MODELS
                    else "Unknown"
                ),
            )
        other_industry = st.text_input(
            "Industry name",
            value=(existing_industry if industry_default == "Other" else ""),
            placeholder="Only needed when Industry = Other",
            disabled=industry_choice != "Other",
        )
        main_activity = st.text_area(
            "What does the organization do?",
            value=str((profile or {}).get("main_activity") or ""),
            placeholder=(
                "Example: We develop and operate a B2B ERP SaaS platform for " "European customers."
            ),
            height=96,
        )

        st.markdown("#### 2. Select what applies")
        departments = st.multiselect(
            "Departments / functions",
            DEPARTMENTS,
            default=_known_options(existing_departments, DEPARTMENTS),
        )
        other_departments = st.text_input(
            "Other departments",
            value=_other_values(existing_departments, DEPARTMENTS),
            placeholder="Optional, comma-separated",
        )
        technologies = st.multiselect(
            "Important technologies / providers",
            TECHNOLOGIES,
            default=_known_options(existing_technologies, TECHNOLOGIES),
        )
        other_technologies = st.text_input(
            "Other technologies",
            value=_other_values(existing_technologies, TECHNOLOGIES),
            placeholder="Optional, comma-separated",
        )
        customer_markets = st.multiselect(
            "Customer / operating markets",
            CUSTOMER_MARKETS,
            default=_known_options(existing_markets, CUSTOMER_MARKETS),
        )
        certification_drivers = st.multiselect(
            "Why ISO 27001?",
            CERTIFICATION_DRIVERS,
            default=_known_options(existing_drivers, CERTIFICATION_DRIVERS),
        )
        compact = st.columns(2, gap="medium")
        with compact[0]:
            locations_text = st.text_input(
                "Locations",
                value=", ".join(_profile_list(profile, "locations")),
                placeholder="Tunis HQ, Remote workforce",
            )
        with compact[1]:
            services_text = st.text_input(
                "Products / services in focus",
                value=", ".join(_profile_list(profile, "products_and_services")),
                placeholder="ERP SaaS, Customer support",
            )
        submitted = st.form_submit_button(
            "Save organization profile",
            icon=":material/check_circle:",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    industry = other_industry.strip() if industry_choice == "Other" else industry_choice
    merged_departments = tuple([*departments, *_csv_values(other_departments)])
    merged_technologies = tuple([*technologies, *_csv_values(other_technologies)])
    try:
        KNOWLEDGE_SERVICE.save_profile(
            client_name,
            engagement_id,
            OrganizationProfileDraft(
                industry=industry,
                main_activity=main_activity,
                employee_band=employee_band,
                infrastructure_model=infrastructure_model,
                locations=_csv_values(locations_text),
                departments=merged_departments,
                products_and_services=_csv_values(services_text),
                technologies=merged_technologies,
                customer_markets=tuple(customer_markets),
                certification_drivers=tuple(certification_drivers),
                profile_status="Confirmed",
            ),
            actor=actor,
        )
    except OrganizationKnowledgeServiceError as exc:
        st.error(str(exc))
        return
    st.toast("Organization profile saved and converted into reusable facts.", icon="✅")
    st.rerun()


def _render_profile_summary(profile: Mapping[str, Any]) -> None:
    """Render a compact summary of current organization knowledge.

    Args:
        profile: Persisted organization profile.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    with st.container(border=True):
        header = st.columns([3, 1], vertical_alignment="center")
        with header[0]:
            st.markdown("### Organization profile")
            st.caption(str(profile.get("main_activity") or "No activity recorded."))
        with header[1]:
            st.success("Confirmed profile")
        metrics = st.columns(4, gap="small")
        values = (
            ("Industry", profile.get("industry") or "—"),
            ("Employees", profile.get("employee_band") or "Unknown"),
            ("Infrastructure", profile.get("infrastructure_model") or "Unknown"),
            ("Known technologies", len(_profile_list(profile, "technologies"))),
        )
        for column, (label, value) in zip(metrics, values):
            with column:
                st.metric(label, value)


def _add_context_recommendation(
    recommendation: ContextRecommendation,
    *,
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Persist a human-approved context recommendation.

    Args:
        recommendation: Reviewed recommendation.
        client_name: Active client workspace.
        engagement_id: Selected engagement.
        scope_id: Optional selected scope.
        actor: Human approver.

    Returns:
        None.

    Raises:
        GrcWorkspaceServiceError: If persistence fails.
    """

    GRC_SERVICE.create_context_issue(
        client_name,
        engagement_id,
        ContextIssueDraft(
            issue_type=recommendation.issue_type,
            category=recommendation.category,
            title=recommendation.title,
            description=recommendation.description,
            effect_on_isms=recommendation.effect_on_isms,
            relevance="Relevant",
            owner=actor,
        ),
        actor=actor,
        scope_id=scope_id,
        reuse_existing=True,
    )


def _add_party_recommendation(
    recommendation: PartyRecommendation,
    selected_requirements: Sequence[str],
    *,
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Persist a reviewed party and its starter requirements.

    Args:
        recommendation: Reviewed interested-party recommendation.
        selected_requirements: Requirements explicitly accepted by the reviewer.
        client_name: Active client workspace.
        engagement_id: Selected engagement.
        scope_id: Optional selected scope.
        actor: Human approver.

    Returns:
        None.

    Raises:
        GrcWorkspaceServiceError: If party or requirement persistence fails.
    """

    party_id = GRC_SERVICE.create_interested_party(
        client_name,
        engagement_id,
        InterestedPartyDraft(
            name=recommendation.name,
            party_type=recommendation.party_type,
            relationship_description=recommendation.relationship_description,
            needs_and_expectations=recommendation.needs_and_expectations,
            communication_method="To be confirmed during programme review.",
            owner=actor,
        ),
        actor=actor,
        scope_id=scope_id,
        reuse_existing=True,
    )
    for requirement in selected_requirements:
        GRC_SERVICE.create_party_requirement(
            client_name,
            engagement_id,
            party_id,
            PartyRequirementDraft(
                requirement_type="Stakeholder",
                requirement=requirement,
                source_reference="SecureScope reviewed starter recommendation",
                applicability="Applicable",
                mandatory=True,
                owner=actor,
            ),
            actor=actor,
            scope_id=scope_id,
            reuse_existing=True,
        )


def _suggestion_selection(recommendations, existing_names, *, name_field, namespace):
    """Render compact suggestions with stable context-scoped selection keys.

    Args:
        recommendations: Generated, validated recommendation objects.
        existing_names: Case-folded canonical names already recorded.
        name_field: Recommendation name attribute.
        namespace: Client, engagement, scope and recommendation kind.
    Returns:
        Selected recommendations paired with selected requirement strings.
    Raises:
        Streamlit errors propagate to the caller.
    """
    from hashlib import sha256

    keys = {
        getattr(r, name_field): namespace
        + "::"
        + sha256(getattr(r, name_field).encode()).hexdigest()[:16]
        for r in recommendations
    }

    def set_all(value):
        for name, key in keys.items():
            if name.casefold() not in existing_names:
                st.session_state[key] = value
                if value:
                    st.session_state[key + "::dismissed"] = False

    controls = st.columns(2)
    controls[0].button("Select all", key=namespace + "::all", on_click=set_all, args=(True,))
    controls[1].button(
        "Clear selection", key=namespace + "::clear", on_click=set_all, args=(False,)
    )
    selected = []
    for recommendation in recommendations:
        name = getattr(recommendation, name_field)
        key = keys[name]
        recorded = name.casefold() in existing_names
        dismissed = st.session_state.get(key + "::dismissed", False)
        with st.container(border=True):
            columns = st.columns([5, 2, 1])
            included = columns[0].checkbox(name, key=key, disabled=recorded or dismissed)
            status = (
                "Already recorded"
                if recorded
                else "Dismissed" if dismissed else "Selected" if included else "Suggested"
            )
            columns[1].markdown(status_pill(status), unsafe_allow_html=True)
            if not recorded:
                if columns[2].button("Restore" if dismissed else "Dismiss", key=key + "::dismiss"):
                    st.session_state[key + "::dismissed"] = not dismissed
                    st.rerun()
            kind = getattr(recommendation, "issue_type", getattr(recommendation, "party_type", ""))
            st.caption(kind + " · " + recommendation.rationale)
            requirements = []
            with st.expander("Supporting details", expanded=False):
                st.write(
                    getattr(
                        recommendation,
                        "description",
                        getattr(recommendation, "relationship_description", ""),
                    )
                )
                st.write(
                    getattr(
                        recommendation,
                        "effect_on_isms",
                        getattr(recommendation, "needs_and_expectations", ""),
                    )
                )
                for index, requirement in enumerate(getattr(recommendation, "requirements", ())):
                    if st.checkbox(
                        requirement,
                        value=True,
                        key=key + f"::requirement::{index}",
                        disabled=recorded,
                    ):
                        requirements.append(requirement)
            if included and not recorded and not dismissed:
                selected.append((recommendation, requirements))
    st.caption(f"{len(selected)} selected · Dismissal is retained for this session only.")
    return selected


def _render_context_recommendations(
    profile: Mapping[str, Any],
    existing_issues: Sequence[Mapping[str, Any]],
    *,
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Render batch-reviewable deterministic context recommendations.

    Args:
        profile: Confirmed organization profile.
        existing_issues: Existing context issue rows.
        client_name: Active client workspace.
        engagement_id: Selected engagement.
        scope_id: Optional scope.
        actor: Current human principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    recommendations = list(KNOWLEDGE_SERVICE.context_recommendations(profile))
    existing_titles = {str(row.get("title") or "").strip().casefold() for row in existing_issues}
    pending = [
        recommendation
        for recommendation in recommendations
        if recommendation.title.casefold() not in existing_titles
    ]

    st.markdown("### Context suggestions")
    st.caption(
        "Review a prepared shortlist from confirmed organization facts. Nothing is "
        "added to the formal Context register until you approve it."
    )
    summary = st.columns(3, gap="small")
    with summary[0]:
        st.metric("Suggested", len(recommendations))
    with summary[1]:
        st.metric("Already recorded", len(recommendations) - len(pending))
    with summary[2]:
        st.metric("Ready for review", len(pending))

    if not pending:
        st.success("All current context suggestions are already in the formal register.")
        return

    selected = [
        r
        for r, _ in _suggestion_selection(
            recommendations,
            existing_titles,
            name_field="title",
            namespace=f"discovery_context::{client_name}::{engagement_id}::{scope_id}",
        )
    ]
    submitted = st.button(
        "Add selected context issues",
        type="primary",
        key=f"discovery_context_save::{client_name}::{engagement_id}::{scope_id}",
        disabled=not selected,
    )

    if not submitted:
        return
    if not selected:
        st.warning("Select at least one context suggestion before adding it.")
        return

    added = 0
    for recommendation in selected:
        try:
            _add_context_recommendation(
                recommendation,
                client_name=client_name,
                engagement_id=engagement_id,
                scope_id=scope_id,
                actor=actor,
            )
        except GrcWorkspaceServiceError as exc:
            st.error(f"Could not add {recommendation.title}: {exc}")
            break
        added += 1
    if added:
        st.toast(f"{added} context suggestion(s) added for formal review.", icon="✅")
        st.rerun()


def _render_party_recommendations(
    profile: Mapping[str, Any],
    existing_parties: Sequence[Mapping[str, Any]],
    *,
    client_name: str,
    engagement_id: int,
    scope_id: int | None,
    actor: str,
) -> None:
    """Render batch-reviewable interested-party recommendations.

    Args:
        profile: Confirmed organization profile.
        existing_parties: Existing interested-party rows.
        client_name: Active client workspace.
        engagement_id: Selected engagement.
        scope_id: Optional scope.
        actor: Current human principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    recommendations = list(KNOWLEDGE_SERVICE.party_recommendations(profile))
    existing_names = {str(row.get("name") or "").strip().casefold() for row in existing_parties}
    pending = [
        recommendation
        for recommendation in recommendations
        if recommendation.name.casefold() not in existing_names
    ]

    st.markdown("### Interested-party suggestions")
    st.caption(
        "Review likely stakeholders and starter requirements together. Only the "
        "parties and requirements you approve are created as formal records."
    )
    summary = st.columns(3, gap="small")
    with summary[0]:
        st.metric("Suggested", len(recommendations))
    with summary[1]:
        st.metric("Already recorded", len(recommendations) - len(pending))
    with summary[2]:
        st.metric("Ready for review", len(pending))

    if not pending:
        st.success("All current interested-party suggestions are already recorded.")
        return

    selected = _suggestion_selection(
        recommendations,
        existing_names,
        name_field="name",
        namespace=f"discovery_parties::{client_name}::{engagement_id}::{scope_id}",
    )
    submitted = st.button(
        "Add selected parties",
        type="primary",
        key=f"discovery_parties_save::{client_name}::{engagement_id}::{scope_id}",
        disabled=not selected,
    )

    if not submitted:
        return
    if not selected:
        st.warning("Select at least one interested party before adding it.")
        return

    added = 0
    for recommendation, requirements in selected:
        try:
            _add_party_recommendation(
                recommendation,
                requirements,
                client_name=client_name,
                engagement_id=engagement_id,
                scope_id=scope_id,
                actor=actor,
            )
        except GrcWorkspaceServiceError as exc:
            st.error(f"Could not add {recommendation.name}: {exc}")
            break
        added += 1
    if added:
        st.toast(f"{added} interested party record(s) added for review.", icon="✅")
        st.rerun()


def _render_scope_composer(
    profile: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    client_name: str,
    engagement_id: int,
    actor: str,
) -> None:
    """Render a scope draft assembled from confirmed organization facts.

    Args:
        profile: Confirmed organization profile.
        context: Current GRC workspace context.
        client_name: Active client workspace.
        engagement_id: Selected engagement.
        actor: Current human principal.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    composition = KNOWLEDGE_SERVICE.compose_scope(profile)
    selected_scope_id = context.get("selected_scope_id")
    selected_scope = next(
        (
            row
            for row in context.get("scopes", ())
            if selected_scope_id is not None and int(row.get("id") or 0) == int(selected_scope_id)
        ),
        {},
    )
    st.markdown("### Scope composer")
    st.caption(
        "Build the first draft from confirmed organization facts, then use the "
        "formal Scope register for exclusions, dependencies, review, and approval."
    )
    with st.container(border=True):
        st.markdown("#### Proposed scope statement")
        st.write(composition.statement)
        st.markdown("**Boundary summary**")
        st.caption(composition.boundaries)
        columns = st.columns(4, gap="small")
        values = (
            ("Products / services", len(composition.products_and_services)),
            ("Departments", len(composition.departments)),
            ("Locations", len(composition.locations)),
            ("Technologies", len(composition.technologies)),
        )
        for column, (label, value) in zip(columns, values):
            with column:
                st.metric(label, value)
        if composition.assumptions:
            st.info(
                "Human confirmation still required:\n\n- " + "\n- ".join(composition.assumptions)
            )

    from securescope.grc.scope_workflow import compose_scope_proposal, scope_changes

    replace_text = replace_lists = False
    if selected_scope:
        st.caption(
            "Manual statement, exclusions, dependencies, ownership and review notes are "
            "retained. New boundary items are added to existing lists."
        )
        st.markdown("#### Update behavior")
        replace_text = (
            st.radio(
                "Scope statement",
                ["Preserve current formal statement", "Replace with proposed Discovery statement"],
                key=f"composer_text_behavior::{client_name}::{selected_scope_id}",
            )
            == "Replace with proposed Discovery statement"
        )
        replace_lists = (
            st.radio(
                "Boundary items",
                [
                    "Add newly discovered items to the current scope",
                    "Replace discovered boundary items with this proposal",
                ],
                key=f"composer_lists_behavior::{client_name}::{selected_scope_id}",
            )
            == "Replace discovered boundary items with this proposal"
        )
    generated = dict(
        scope_statement=composition.statement,
        boundaries=composition.boundaries,
        locations=composition.locations,
        organizational_units=composition.departments,
        products_and_services=composition.products_and_services,
        technologies=composition.technologies,
        assumptions=composition.assumptions,
    )
    proposal = compose_scope_proposal(
        dict(selected_scope), generated, replace_text=replace_text, replace_lists=replace_lists
    )
    changes = scope_changes(dict(selected_scope), proposal)
    st.markdown("#### Preview changes")
    if changes:
        st.caption(
            "Will preserve: exclusions, dependencies, interfaces and saved rev"
            "iewer/approver notes. Only the fields below will change."
        )
        st.dataframe(changes, hide_index=True, width="stretch")
    else:
        st.caption("No new changes detected from Discovery. The current scope remains unchanged.")
    if st.button(
        (
            "Prepare Draft Scope"
            if not selected_scope
            else "Update Draft Scope" if changes else "Open Current Scope"
        ),
        icon=":material/edit_document:",
        type="primary",
        width="stretch",
        key="discovery_create_scope_draft",
    ):
        from securescope.ui.grc_workspace.scope_editor import start_scope_editor

        if selected_scope and not changes:
            from securescope.ui.grc_workspace.router import select_programme_section

            select_programme_section(client_name, "scope")
        else:
            start_scope_editor(client_name, engagement_id, proposal)
        st.rerun()


def render_discovery_section(
    client_name: str,
    context: Mapping[str, Any],
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    actor: str,
    on_section: Callable[[str], None] | None = None,
) -> None:
    """Render the discover -> suggest -> review programme-foundation flow.

    Args:
        client_name: Active client workspace.
        context: Resolved GRC workspace context.
        registers: Existing context and interested-party records.
        actor: Current human principal.
        on_section: Optional callback used to open a formal Programme Setup register.

    Returns:
        None.

    Raises:
        No exceptions are raised; known persistence failures become safe UI states.
    """

    st.markdown("## Discovery")
    st.caption(
        "Capture the organization once, then review prepared ISO foundation "
        "suggestions instead of repeating the same information across forms."
    )
    engagement_id = int(context["selected_engagement_id"])
    scope_id = context.get("selected_scope_id")
    resolved_scope_id = int(scope_id) if scope_id is not None else None
    try:
        profile = KNOWLEDGE_SERVICE.get_profile(client_name)
    except OrganizationKnowledgeServiceError as exc:
        st.error(f"Organization discovery is unavailable: {exc}")
        return

    if profile:
        _render_profile_summary(profile)
        with workflow_section(
            "Edit organization profile", "Maintain the organization-specific context."
        ):
            _render_profile_form(
                client_name,
                engagement_id,
                profile,
                actor,
            )
    else:
        st.info(
            "Start with the short organization profile. Unknown information can be "
            "left unknown and completed later."
        )
        _render_profile_form(
            client_name,
            engagement_id,
            None,
            actor,
        )
        return

    context_recommendations = list(KNOWLEDGE_SERVICE.context_recommendations(profile))
    party_recommendations = list(KNOWLEDGE_SERVICE.party_recommendations(profile))
    existing_context = {
        str(row.get("title") or "").strip().casefold()
        for row in registers.get("context_issues", ())
    }
    existing_parties = {
        str(row.get("name") or "").strip().casefold()
        for row in registers.get("interested_parties", ())
    }
    pending_context = sum(
        recommendation.title.casefold() not in existing_context
        for recommendation in context_recommendations
    )
    pending_parties = sum(
        recommendation.name.casefold() not in existing_parties
        for recommendation in party_recommendations
    )
    scope_composition = KNOWLEDGE_SERVICE.compose_scope(profile)
    scope_inputs = sum(
        bool(value)
        for value in (
            scope_composition.products_and_services,
            scope_composition.departments,
            scope_composition.locations,
            scope_composition.technologies,
        )
    )

    st.markdown("### Foundation preparation")
    status_columns = st.columns(3, gap="small")
    with status_columns[0]:
        st.metric("Context suggestions", pending_context)
    with status_columns[1]:
        st.metric("Party suggestions", pending_parties)
    with status_columns[2]:
        st.metric("Scope input groups", f"{scope_inputs}/4")

    state_key = discovery_task_state_key(client_name, engagement_id)
    requested = str(st.session_state.get(state_key) or "context")
    if requested not in DISCOVERY_TASKS:
        requested = "context"
    selector_key = f"{state_key}::selector"
    default_args = {} if selector_key in st.session_state else {"default": requested}
    selected = section_navigation(
        "Discovery task",
        options=list(DISCOVERY_TASKS),
        format_func=lambda value: DISCOVERY_TASKS[str(value)],
        selection_mode="single",
        key=selector_key,
        **default_args,
    )
    with selected.panel:
        task = str(selected or requested)
        st.session_state[state_key] = task

        if task == "context":
            _render_context_recommendations(
                profile,
                registers.get("context_issues", ()),
                client_name=client_name,
                engagement_id=engagement_id,
                scope_id=resolved_scope_id,
                actor=actor,
            )
            if on_section is not None:
                st.button(
                    "Open Context register",
                    icon=":material/open_in_new:",
                    type="secondary",
                    key="discovery_open_context_register",
                    on_click=on_section,
                    args=("context",),
                )
        elif task == "parties":
            _render_party_recommendations(
                profile,
                registers.get("interested_parties", ()),
                client_name=client_name,
                engagement_id=engagement_id,
                scope_id=resolved_scope_id,
                actor=actor,
            )
            if on_section is not None:
                st.button(
                    "Open Interested Parties register",
                    icon=":material/open_in_new:",
                    type="secondary",
                    key="discovery_open_parties_register",
                    on_click=on_section,
                    args=("parties",),
                )
        else:
            _render_scope_composer(
                profile,
                context,
                client_name=client_name,
                engagement_id=engagement_id,
                actor=actor,
            )
            if on_section is not None:
                st.button(
                    "Open ISMS Scope register",
                    icon=":material/open_in_new:",
                    type="secondary",
                    key="discovery_open_scope_register",
                    on_click=on_section,
                    args=("scope",),
                )
