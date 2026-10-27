"""Stitch presentation bridge for canonical assurance records."""

import json
from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.component_styles import component_styles


def assurance_page(data: dict, *, key: str, on_action=None) -> Any:
    """Render scoped records through bundled CSS and JavaScript.

    Args:
        data: Authorized presentation data, without secrets.
        key: Workspace and scope-specific component identity.
        on_action: Optional callback accepting a navigation or edit event.
    Returns:
        Streamlit component result.
    Raises:
        OSError: If bundled assets are missing.
        StreamlitAPIException: If component rendering fails.
    """
    root = Path(__file__).parent
    component = st.components.v2.component(
        name="securescope_assurance_pages",
        html='<main id="assurance-page"></main>',
        css=component_styles("assurance_plan.css", "assurance_pages.css"),
        js=(root / "assurance_pages.js").read_text(encoding="utf-8"),
    )

    def dispatch():
        """Route the current component event; return None; propagate handler errors."""
        result = st.session_state.get(key, {})
        event = result.get("action") if isinstance(result, dict) else None
        if event and on_action:
            on_action(event)

    return component(
        data=json.loads(json.dumps(data, default=str)),
        key=key,
        on_action_change=dispatch,
    )
