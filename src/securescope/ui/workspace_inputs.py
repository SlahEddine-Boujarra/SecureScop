"""Reusable working inputs for one client workspace."""

from __future__ import annotations

import streamlit as st

from securescope.ui.grc_workspace.context import current_actor


def working_actor(client_name: str, key: str) -> str:
    """Ask once for the recorder and reuse the name across working registers.

    Args:
        client_name: Active workspace.
        key: Unique widget suffix.
    Returns:
        Recorder name. This value never grants membership or approval rights.
    Raises:
        No exceptions are raised directly.
    """
    shared = f"working_actor::{client_name}"
    value = st.text_input(
        "Recorded by",
        value=st.session_state.get(
            shared, ("" if current_actor() == "local-consultant" else current_actor())
        ),
        key=f"recorder::{client_name}::{key}",
    )
    if value.strip():
        st.session_state[shared] = value.strip()
    return value.strip()


def remembered_scope(client_name: str) -> str:
    """Read the reusable scope text entered for this workspace.

    Args:
        client_name: Active workspace.
    Returns:
        Scope draft, or an empty string until supplied.
    Raises:
        No exceptions are raised directly.
    """
    return str(st.session_state.get(f"working_scope::{client_name}", ""))
