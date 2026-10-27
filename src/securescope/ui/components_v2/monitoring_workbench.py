"""ATLAS monitoring surface within the existing Streamlit Components v2 runtime."""

from pathlib import Path

import streamlit as st

from securescope.ui.component_styles import component_styles
from securescope.ui.navigation_runtime import navigate_to
from securescope.ui.siem_presentation import monitoring_view


def monitoring_workbench(rows: list[dict], client_name: str) -> None:
    """Render current facts and route only an authorized row's evidence-navigation event.

    Args:
        rows: Authorized workspace monitoring records from the existing repository.
        client_name: Active server-side workspace identity.
    Returns:
        None; record inspection/search are presentation state only.
    Raises:
        ValueError: Invalid presentation data or unknown navigation route.
        OSError: Missing bundled component files.
        StreamlitAPIException: Component rendering failure.
    """
    data = monitoring_view(rows, client_name)
    key = f"monitoring_workbench::{client_name}"
    allowed_ids = {r["asset_id"] for r in data["rows"]}
    root = Path(__file__).parent
    component = st.components.v2.component(
        name="securescope_monitoring_workbench",
        html='<section id="monitoring-workbench" aria-label="Workspace monitoring"></section>',
        css=component_styles("monitoring_workbench.css"),
        js=(root / "monitoring_workbench.js").read_text(encoding="utf-8"),
    )
    result = component(data=data, key=key, on_action_change=lambda: None)
    event = result.get("action") if isinstance(result, dict) else getattr(result, "action", None)
    if (
        isinstance(event, dict)
        and event.get("type") == "open_evidence"
        and type(event.get("asset_id")) is int
        and event["asset_id"] in allowed_ids
        and event.get("workspace") == client_name
        and isinstance(event.get("nonce"), str)
        and event["nonce"] != st.session_state.get(key + "::handled")
    ):
        st.session_state[key + "::handled"] = event["nonce"]
        navigate_to("ISO Evidence Hub")
        st.rerun()
