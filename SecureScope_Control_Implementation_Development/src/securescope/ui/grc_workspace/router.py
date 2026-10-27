"""Lazy section router for the ISO 27001 Programme Setup experience."""

from __future__ import annotations

from contextlib import nullcontext

import os
from collections import OrderedDict
from typing import Any, Mapping, Sequence

import streamlit as st

from securescope.ui.components.navigation import section_navigation

from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.ui.grc_workspace.context import (
    current_actor,
    render_context_or_error,
    workspace_state_keys,
)
from securescope.ui.grc_workspace.discovery import render_discovery_section
from securescope.ui.grc_workspace.formal import (
    render_access_notice,
    render_foundation_overview,
)
from securescope.ui.grc_workspace.scope_editor import (
    render_scope_editor,
    scope_editor_is_open,
)
from securescope.ui.grc_workspace.sections import (
    render_engagement_section,
)

SERVICE = GrcWorkspaceService()
PROGRAMME_SECTIONS: Mapping[str, str] = OrderedDict(
    (
        ("overview", "Overview"),
        ("discovery", "Discovery"),
        ("context", "Context"),
        ("parties", "Interested Parties"),
        ("scope", "ISMS Scope"),
        ("governance", "Governance"),
        ("engagement", "Engagement"),
        ("roles", "Roles & RACI"),
        ("risks", "Risk assessment"),
        ("policy", "Policy"),
        ("objectives", "Objectives"),
    )
)


def grc_workspace_enabled() -> bool:
    """Return whether the additive GRC workspace is enabled.

    Returns:
        ``True`` unless ``SECURESCOPE_GRC_WORKSPACE_ENABLED`` is explicitly false.

    Raises:
        No exceptions are raised.
    """

    return os.getenv("SECURESCOPE_GRC_WORKSPACE_ENABLED", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def programme_section_state_key(client_name: str) -> str:
    """Return the selected Programme Setup section key for one client.

    Args:
        client_name: Active client workspace name.

    Returns:
        Namespaced Streamlit session-state key.

    Raises:
        No exceptions are raised.
    """

    return f"programme_setup_section::{client_name}"


def programme_section_pending_key(client_name: str) -> str:
    """Return the deferred Programme Setup navigation key for one client.

    Streamlit forbids mutating a widget-backed session-state key after that
    widget has been instantiated in the current run. Programme actions are
    therefore queued and applied before the segmented control is rendered on
    the next run.

    Args:
        client_name: Active client workspace name.

    Returns:
        Namespaced session-state key used for deferred navigation.

    Raises:
        No exceptions are raised.
    """

    return f"programme_setup_pending_section::{client_name}"


def select_programme_section(client_name: str, section: str) -> None:
    """Queue a validated Programme Setup section for the next render.

    Args:
        client_name: Active client workspace name.
        section: Stable section identifier.

    Returns:
        None.

    Raises:
        No exceptions are raised; unsupported values fall back to overview.
    """

    resolved = section if section in PROGRAMME_SECTIONS else "overview"
    st.session_state[programme_section_state_key(client_name)] = resolved
    st.session_state[programme_section_pending_key(client_name)] = resolved
    st.session_state["app_navigation"] = "Programme Setup"


def _render_selected_section(
    client_name: str,
    context: Mapping[str, Any],
    section: str,
    registers: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Render exactly one selected Programme Setup section.

    Args:
        client_name: Active client workspace name.
        context: Resolved GRC context.
        section: Selected section identifier.
        registers: Section-specific register rows.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    actor = current_actor()
    engagement_state_key, _scope_state_key = workspace_state_keys(client_name)
    if section == "overview":
        render_foundation_overview(
            client_name,
            dict(context),
            on_section=lambda value: select_programme_section(client_name, value),
        )
    elif section == "policy":
        from securescope.ui.grc_workspace.linked_modules import render_policy_readiness

        render_policy_readiness(client_name, dict(context))
    elif section == "risks":
        from securescope.ui.grc_workspace.linked_modules import render_risk_readiness

        render_risk_readiness(client_name, dict(context))
    elif section == "discovery":
        render_discovery_section(
            client_name,
            context,
            registers,
            actor=actor,
            on_section=lambda value: select_programme_section(client_name, value),
        )
    elif section == "engagement":
        render_engagement_section(
            client_name,
            context,
            registers,
            actor=actor,
            engagement_state_key=engagement_state_key,
        )


def render_programme_setup(client_name: str) -> None:
    """Render the record-first, lazily queried Programme Setup workspace.

    Args:
        client_name: Exact active client workspace selected in the sidebar.

    Returns:
        None.

    Raises:
        No exceptions are raised; known service failures become safe UI states.
    """

    st.markdown('<span class="ss-foundation-page"></span>', unsafe_allow_html=True)
    st.markdown("# Programme Foundation")
    render_access_notice(client_name)
    st.caption(
        "Discover what is known, review SecureScope recommendations, then maintain "
        "the formal ISO registers. Scanner results remain supporting evidence."
    )
    if not grc_workspace_enabled():
        st.info("Programme Setup is disabled by SECURESCOPE_GRC_WORKSPACE_ENABLED.")
        return
    context = render_context_or_error(client_name)
    if context is None:
        return

    engagement_id = int(context["selected_engagement_id"])
    _engagement_key, scope_state_key = workspace_state_keys(client_name)
    if scope_editor_is_open(client_name, engagement_id):
        render_scope_editor(
            client_name,
            engagement_id,
            current_actor(),
            scope_state_key,
        )
        return

    state_key = programme_section_state_key(client_name)
    pending_key = programme_section_pending_key(client_name)
    control_key = f"programme_section_control::{client_name}"

    pending = str(st.session_state.pop(pending_key, "") or "")
    requested = pending or str(st.session_state.get(state_key) or "overview")
    if requested not in PROGRAMME_SECTIONS:
        requested = "overview"

    # This runs before the segmented control is instantiated, which is the
    # only safe point to synchronize a programmatic navigation request with a
    # widget-backed Streamlit session-state key.
    if pending:
        st.session_state[control_key] = requested
    elif (
        control_key in st.session_state
        and str(st.session_state.get(control_key)) not in PROGRAMME_SECTIONS
    ):
        st.session_state[control_key] = requested

    options = ("overview", "discovery", "context", "parties", "scope", "governance", "engagement")
    if requested in {"risks", "policy"}:
        requested = "overview"
    main_requested = "governance" if requested in {"roles", "objectives"} else requested
    if pending or st.session_state.get(control_key) not in options:
        st.session_state[control_key] = main_requested
    selected = section_navigation(
        "Programme section",
        options=list(options),
        format_func=lambda value: PROGRAMME_SECTIONS[str(value)],
        selection_mode="single",
        label_visibility="collapsed",
        key=control_key,
    )
    with selected.panel:
        section = str(selected or "overview")
        if section == "governance":
            governance_key = f"programme_governance::{client_name}"
            if pending and requested in {"roles", "objectives"}:
                st.session_state[governance_key] = requested
            section = (
                section_navigation(
                    "Governance",
                    ["roles", "objectives"],
                    default="roles",
                    key=governance_key,
                    format_func=lambda value: (
                        "Roles & RACI — Clause 5.3"
                        if value == "roles"
                        else "Objectives — Clause 6.2"
                    ),
                )
                or "roles"
            )
        panel = section.panel if hasattr(section, "panel") else nullcontext()
        section = str(section)
        st.session_state[state_key] = section
        with panel:
            scope_id = context.get("selected_scope_id")
            try:
                registers = (
                    {}
                    if section in {"overview", "policy", "objectives", "risks"}
                    else SERVICE.load_section(
                        client_name,
                        engagement_id,
                        int(scope_id) if scope_id is not None else None,
                        section,
                    )
                )
            except GrcWorkspaceServiceError as exc:
                st.error(f"{PROGRAMME_SECTIONS[section]} is unavailable: {exc}")
                return
            with st.container(key="foundation_page"):
                if section in {"context", "parties", "scope", "roles", "objectives"}:
                    from securescope.ui.grc_workspace.stitch_records import render_stitch_records

                    render_stitch_records(client_name, dict(context), section, registers)
                else:
                    _render_selected_section(client_name, context, section, registers)
