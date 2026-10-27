"""Local UI-only fixture using production components and synthetic records.

Run with ``python -m streamlit run scripts/ui_hardening_preview.py``.
No database calls, credentials, scanners, or persistent client data are used.
"""

from types import SimpleNamespace

import streamlit as st

from securescope.ui.securescope_ui_theme import apply_securescope_ui_theme
from securescope.ui.securescope_sidebar import NAVIGATION_GROUPS, render_sidebar_menu
from securescope.ui.components.context_bar import render_context_bar
from securescope.ui.components.progress_card import render_program_progress_card
from securescope.ui.components.primitives import metric_card, readable_table, empty_state
from securescope.ui.gap_charts import radar_chart

st.set_page_config(layout="wide", initial_sidebar_state="expanded")
apply_securescope_ui_theme()


@st.dialog("Switch workspace")
def workspace_dialog() -> None:
    """Open and dismiss a synthetic workspace dialog.

    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    st.write("UI verification fixture. No client records are modified.")
    if st.button("Done"):
        st.rerun()


def page() -> None:
    """Render production components with representative edge-case values.

    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    render_context_bar("Example Consulting — Northern Operations", {"overview": {
        "engagement": {"name": "ISO 27001 certification programme 2026–2027"},
        "scope": {"name": "Customer platforms, corporate network and cloud services"},
    }}, actor="UI fixture")
    st.title(f"UI verification — {active}")
    cols = st.columns(3)
    for col, item in zip(cols, [("Open gaps", 0, "neutral"), ("Review pending", 4, "warning"), ("Verified controls", 12, "success")]):
        with col:
            metric_card(item[0], item[1], "Synthetic fixture data", item[2])
    left, right = st.columns([1.3, 1])
    with left:
        render_program_progress_card(SimpleNamespace(readiness="Foundation in progress", percentage=12, completed=1, total=8), engagement_name="Programme Foundation", scope_name="Selected ISMS scope")
        readable_table([{"Asset tag": "SRV-001", "OS": "Microsoft Windows Server 2025 Datacenter — long operating system label", "VLAN": "Northern division / production services / restricted", "Lifecycle": "Discovered"}, {"Asset tag": "SRV-002", "OS": "Ubuntu 24.04 LTS", "VLAN": "Corporate / shared platforms", "Lifecycle": "Pending review"}], key="preview_assets")
    with right:
        st.vega_lite_chart(spec=radar_chart([{"code": c, "area": c, "conformity": 50, "met": 5, "in_scope": 10} for c in ("4", "5", "6", "7", "8", "9", "10", "A.5", "A.6", "A.7", "A.8")]), width="stretch")
        empty_state("No evidence requested", "Create a request when supporting evidence is needed.")


registry = {key: st.Page(page, title=label, url_path=f"route_{i}")
            for i, (key, _, label, _) in enumerate(item for _, items in NAVIGATION_GROUPS for item in items)}
registry["Client Workspace"] = st.Page(page, title="Client Workspace", url_path="workspace")
selected = st.navigation(list(registry.values()), position="hidden")
active = next(key for key, value in registry.items() if selected.url_path == value.url_path)
render_sidebar_menu("Example Consulting", open_workspace_dialog=workspace_dialog,
                    page_objects=registry, active_navigation_key=active)
selected.run()
