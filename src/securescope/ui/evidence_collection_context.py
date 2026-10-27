"""One rerun-safe origin for requirement-driven evidence collection."""

import streamlit as st

from securescope.ui.grc_workspace.context import selected_context_ids

KEY = "evidence_collection_context"


def current_collection_context(client):
    """Return context only for the selected tenant, engagement and scope.

    Args:
        client: Active workspace name.
    Returns:
        Origin dictionary, or empty when another context is selected.
    Raises:
        No expected exceptions for valid session state.
    """
    context = st.session_state.get(KEY) or {}
    engagement, scope = selected_context_ids(client)
    if (context.get("client"), context.get("engagement_id"), context.get("scope_id")) != (
        client,
        engagement,
        scope,
    ):
        return {}
    return dict(context)


def begin_collection(client, control_id, requirement, provider):
    """Record a canonical origin and route to an existing provider workflow.

    Args:
        client: Active workspace.
        control_id: Origin control ID.
        requirement: Existing structured requirement.
        provider: Supported configured provider.
    Returns:
        None; navigation triggers a rerun.
    Raises:
        ValueError: Unsupported provider or missing scope.
    """
    from securescope.ui.navigation_runtime import navigate_to

    engagement, scope = selected_context_ids(client)
    if not engagement or not scope:
        raise ValueError("Select an engagement and ISMS Scope before collection.")
    st.session_state[KEY] = dict(
        client=client,
        engagement_id=engagement,
        scope_id=scope,
        control_id=control_id,
        requirement_id=requirement["id"],
        return_to="control_profile",
        asset_ids=list(requirement.get("asset_ids") or []),
        provider=provider,
    )
    if provider == "nuclei":
        st.session_state["scan_engine"] = "Nuclei"
        navigate_to("3 · Scan Center")
    elif provider == "wazuh":
        navigate_to("5 · SIEM & Wazuh")
    else:
        st.session_state[f"evidence_control_pending::{client}"] = control_id
        st.session_state[f"evidence_section::{client}"] = {
            "manual": "Manual Evidence",
            "request": "Evidence Requests",
        }.get(provider, "Collect Evidence")
        st.session_state[f"assurance_pending_tab::{client}"] = ":material/folder_open: Evidence"
        st.rerun()


def render_collection_return(client):
    """Render the explicit return action while an origin remains active.

    Args:
        client: Active workspace.
    Returns:
        Current valid origin dictionary.
    Raises:
        Streamlit navigation exceptions propagate.
    """
    context = current_collection_context(client)
    if context:
        st.caption(f"Collecting for {context['control_id']} · ISMS Scope #{context['scope_id']}")
        if st.button(f"Return to {context['control_id']}", key="evidence_collection_return"):
            from securescope.ui.control_workspace import open_control_workspace

            st.session_state.pop(KEY, None)
            open_control_workspace(client, context["control_id"])
    return context


def begin_existing_link(client, control_id, requirement):
    """Open scoped evidence selection for an existing requirement, without collecting.

    Args:
        client: Active workspace.
        control_id: Origin control.
        requirement: Canonical criterion to receive the link.
    Returns:
        None; reruns into the existing Evidence Register.
    Raises:
        Streamlit rerun exception by design.
    """
    engagement, scope = selected_context_ids(client)
    st.session_state[KEY] = dict(
        client=client,
        engagement_id=engagement,
        scope_id=scope,
        control_id=control_id,
        requirement_id=requirement["id"],
        return_to="control_profile",
        mode="link",
    )
    st.session_state[f"evidence_control_pending::{client}"] = control_id
    st.session_state[f"evidence_scope_view::{client}::{engagement}::{scope}"] = "Current ISMS Scope"
    st.session_state[f"evidence_section::{client}"] = "Evidence Register"
    st.session_state[f"assurance_pending_tab::{client}"] = ":material/folder_open: Evidence"
    st.rerun()
