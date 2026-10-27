"""Custom browser workbench using Streamlit's existing Components v2 bridge."""

from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.component_styles import component_styles

_COMPONENT: Any = None


def assurance_workbench(data: dict, *, key: str) -> Any:
    """Render the isolated policy/risk UI and return explicit user actions.

    Args:
        data: Authorized, JSON-compatible view data; never credentials.
        key: Client and scope-specific component identity.
    Returns:
        Component result with an optional action event.
    Raises:
        OSError: If bundled assets are missing.
        StreamlitAPIException: If component registration fails.
    """
    global _COMPONENT
    if _COMPONENT is None:
        root = Path(__file__).parent
        _COMPONENT = st.components.v2.component(
            name="securescope_assurance_workbench",
            html='<main id="assurance-workbench"></main>',
            css=component_styles("assurance_workbench.css"),
            js=(root / "assurance_workbench.js").read_text(encoding="utf-8"),
        )
    from securescope.grc.status_labels import LABELS

    return _COMPONENT(data=dict(data, status_labels=LABELS), key=key, on_action_change=lambda: None)
