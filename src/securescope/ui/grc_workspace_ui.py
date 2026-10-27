"""Compatibility façade for the record-first ISO Programme Setup UI."""

from __future__ import annotations

import streamlit as st

from securescope.ui.grc_workspace.router import (
    grc_workspace_enabled,
    render_programme_setup,
)


@st.fragment
def render_grc_workspace(client_name: str) -> None:
    """Render Programme Foundation through the compatibility façade.

    Args:
        client_name: Exact active client workspace name.

    Returns:
        None.

    Raises:
        No exceptions are raised by this façade.
    """

    render_programme_setup(client_name)


__all__ = [
    "grc_workspace_enabled",
    "render_grc_workspace",
    "render_programme_setup",
]
