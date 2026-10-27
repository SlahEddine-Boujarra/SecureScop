"""Shared client, engagement, and scope selection for ISO programme pages."""

from __future__ import annotations

import hashlib
import os
from typing import Any

import streamlit as st

from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.ui.components import render_context_bar

SERVICE = GrcWorkspaceService()


def current_actor() -> str:
    """Return the configured user identity or local non-approval principal.

    Returns:
        Normalized email or ``local-consultant`` fallback.

    Raises:
        No exceptions are raised.
    """

    identity = st.session_state.get("_foundation_identity", {})
    code = os.getenv("SECURESCOPE_LOCAL_SETUP_CODE", "")
    if code and identity.get("proof") == hashlib.sha256(code.encode()).hexdigest():
        return str(identity["email"])
    return os.getenv("SECURESCOPE_CURRENT_USER_EMAIL", "").strip().lower() or "local-consultant"


def workspace_state_keys(client_name: str) -> tuple[str, str]:
    """Return persistent engagement and scope state keys for a client.

    Args:
        client_name: Active client workspace name.

    Returns:
        Engagement-state key followed by scope-state key.

    Raises:
        No exceptions are raised.
    """

    return (
        f"grc_selected_engagement::{client_name}",
        f"grc_selected_scope::{client_name}",
    )


def open_selected_context(client_name: str) -> dict[str, Any]:
    """Open the session-selected tenant-safe GRC context.

    Args:
        client_name: Active client workspace name.

    Returns:
        GRC service context with engagements, scopes, and overview metrics.

    Raises:
        GrcWorkspaceServiceError: If the context cannot be initialized.
    """

    engagement_key, scope_key = workspace_state_keys(client_name)
    return SERVICE.open_workspace(
        client_name,
        engagement_id=st.session_state.get(engagement_key),
        scope_id=st.session_state.get(scope_key),
        actor=current_actor(),
    )


def render_workspace_selector(
    client_name: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Render compact working context with selectors under one popover.

    The selected client, engagement and scope remain continuously visible, but
    their administration no longer consumes a full row of form controls on
    every ISO page.

    Args:
        client_name: Active client workspace name.
        context: Context returned by :func:`open_selected_context`.

    Returns:
        Context resolved after any engagement or scope selection change.

    Raises:
        GrcWorkspaceServiceError: If the selected context cannot be loaded.
    """

    engagement_key, scope_key = workspace_state_keys(client_name)
    actor = current_actor()
    context_column, change_column = st.columns(
        [5.2, 1],
        gap="small",
        vertical_alignment="center",
    )

    with change_column:
        with st.popover(
            "Change context",
            icon=":material/tune:",
            width="stretch",
        ):
            st.caption(
                "Switch the active certification cycle or working ISMS scope. "
                "All programme data remains client-isolated."
            )
            engagement_by_id = {int(item["id"]): item for item in context.get("engagements", ())}
            selected_engagement_id = st.selectbox(
                "Engagement / certification cycle",
                list(engagement_by_id),
                index=list(engagement_by_id).index(int(context["selected_engagement_id"])),
                format_func=lambda value: (
                    f"{engagement_by_id[int(value)]['name']} · "
                    f"{engagement_by_id[int(value)]['status']}"
                ),
                key=f"grc_engagement_selector::{client_name}",
            )
            if int(selected_engagement_id) != int(context["selected_engagement_id"]):
                st.session_state[engagement_key] = int(selected_engagement_id)
                st.session_state.pop(scope_key, None)
                context = SERVICE.open_workspace(
                    client_name,
                    engagement_id=int(selected_engagement_id),
                    actor=actor,
                )
            else:
                st.session_state[engagement_key] = int(selected_engagement_id)

            scope_by_id = {int(item["id"]): item for item in context.get("scopes", ())}
            if scope_by_id:
                current_scope_id = int(context["selected_scope_id"])
                selected_scope_id = st.selectbox(
                    "Approved or working ISMS scope",
                    list(scope_by_id),
                    index=list(scope_by_id).index(current_scope_id),
                    format_func=lambda value: (
                        f"{scope_by_id[int(value)]['name']} · "
                        f"v{scope_by_id[int(value)].get('latest_version_number', '—')} · "
                        f"{scope_by_id[int(value)].get('latest_status', 'Draft')}"
                    ),
                    key=(f"grc_scope_selector::{client_name}::" f"{selected_engagement_id}"),
                )
            else:
                selected_scope_id = None
                st.info("No ISMS scope exists for this engagement.")

            if selected_scope_id is not None:
                st.session_state[scope_key] = int(selected_scope_id)
                if int(selected_scope_id) != int(context["selected_scope_id"]):
                    context = SERVICE.open_workspace(
                        client_name,
                        engagement_id=int(selected_engagement_id),
                        scope_id=int(selected_scope_id),
                        actor=actor,
                    )

    selected = next(
        (r for r in context.get("scopes", []) if r["id"] == context.get("selected_scope_id")), {}
    )
    st.session_state[f"scope_label::{client_name}::{context.get('selected_scope_id')}"] = (
        selected.get("name") or "Selected ISMS Scope"
    )
    with context_column:
        render_context_bar(client_name, context, actor=actor)
    return context


def render_context_or_error(client_name: str) -> dict[str, Any] | None:
    """Open and render a context while translating known failures to UI state.

    Args:
        client_name: Active client workspace name.

    Returns:
        Resolved context, or ``None`` after a safe error message.

    Raises:
        No exceptions are raised.
    """

    try:
        return render_workspace_selector(client_name, open_selected_context(client_name))
    except GrcWorkspaceServiceError:
        render_context_bar(
            client_name,
            {
                "overview": {
                    "engagement": {"name": "Context unavailable"},
                    "scope": {"name": "Context unavailable"},
                }
            },
            actor=current_actor(),
        )
        st.warning(
            (
                "Programme context could not be loaded. Check the workspace "
                "connection before changing programme records."
            )
        )
        return None


def selected_context_ids(client_name: str) -> tuple[int | None, int | None]:
    """Read the existing client-namespaced engagement and scope selection.

    Args:
        client_name: Current client workspace name.
    Returns:
        Selected engagement and scope IDs without changing session state.
    Raises:
        No exceptions are raised.
    """
    engagement_key, scope_key = workspace_state_keys(client_name)
    return st.session_state.get(engagement_key), st.session_state.get(scope_key)
