"""Isolated Stitch project-plan presentation; task persistence stays in the controller."""

import json
from pathlib import Path

import streamlit as st

from securescope.ui.component_styles import component_styles

_COMPONENT = None


def render_plan_view(client, rows, metrics, on_action):
    """Render authorized plan data and route explicit navigation actions."""
    global _COMPONENT
    if _COMPONENT is None:
        root = Path(__file__).parent
        _COMPONENT = st.components.v2.component(
            name="securescope_assurance_plan",
            html='<main id="assurance-plan"></main>',
            css=component_styles("assurance_plan.css"),
            js=(root / "assurance_plan.js").read_text(encoding="utf-8"),
        )
    key = f"assurance_plan::{client}"

    def dispatch():
        result = st.session_state.get(key, {})
        event = result.get("action") if isinstance(result, dict) else None
        if event:
            on_action(event)

    return _COMPONENT(
        data=json.loads(json.dumps(dict(rows=rows, metrics=metrics), default=str)),
        key=key,
        on_action_change=dispatch,
    )
