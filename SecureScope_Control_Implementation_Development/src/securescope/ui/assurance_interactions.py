"""Workspace-scoped navigation from a control summary into human assessment."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import streamlit as st
from securescope.ui.components.primitives import identity_context

from securescope.ui.control_presenter import human_assessment_label

ASSESSMENT_TAB = ":material/fact_check: Assess control"


def open_control_assessment(client_name: str, control_id: str = "") -> None:
    """Select the assessment section from a Streamlit widget callback.

    Args:
        client_name: Active client workspace.
        control_id: Optional control to preselect when the editor renders.

    Returns:
        None. Updates only this browser session's workspace navigation state.

    Raises:
        StreamlitAPIException: If called after the tab widget is instantiated
            outside a callback; callers must use on_click.
    """

    st.session_state[f"assurance_active_tab::{client_name}"] = ASSESSMENT_TAB
    if control_id:
        st.session_state[f"manual_control_pending::{client_name}"] = control_id


def render_control_preview(
    client_name: str,
    row: Mapping[str, Any],
    *,
    recommendation: str,
    evidence_strength: str,
) -> None:
    """Show the selected control and an explicit route to its assessment form.

    Args:
        client_name: Active client workspace.
        row: A control record re-resolved from this workspace's current rows.
        recommendation: Advisory signal formatted by the calling page.
        evidence_strength: Current evidence summary formatted by the page.

    Returns:
        None. Renders a read-only summary and a navigation button.

    Raises:
        KeyError: If the selected repository row has no control_id.
    """

    control_id = str(row["control_id"])
    with st.container(border=True, key=f"control_preview::{client_name}"):
        heading, action = st.columns([3, 1], vertical_alignment="center")
        with heading:
            st.caption(f"SELECTED CONTROL · {control_id}")
            st.subheader(str(row.get("control_name") or control_id))
        with action:
            st.button(
                "Assess this control",
                type="primary",
                width="stretch",
                on_click=open_control_assessment,
                args=(client_name, control_id),
                key=f"assess_selected::{client_name}",
            )
        human, advisory, evidence = st.columns(3)
        with human:
            st.caption("HUMAN ASSESSMENT")
            st.write(human_assessment_label(row.get("assessment_status")))
        with advisory:
            st.caption("SECURESCOPE RECOMMENDATION")
            st.write(recommendation)
        with evidence:
            st.caption("EVIDENCE")
            st.write(evidence_strength)
        if row.get("control_objective"):
            st.write(str(row["control_objective"]))
        identity_context(row.get("control_owner") or "Unassigned", "Control owner")
        st.caption(f"Profile version: {row.get('profile_version') or '—'}")
