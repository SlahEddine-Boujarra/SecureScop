"""
SecureScope professional presentation shell.

Presentation only:
- Sidebar/navigation
- Client workspace switcher
- Icon-based section navigation
- Theme tokens and component styling
- Status/severity display helpers

No Nmap, OpenVAS, Wazuh, CISO, PostgreSQL, parsing, report, or business logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.components.primitives import status_pill

SEVERITY_DISPLAY = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Info",
}

LIFECYCLE_DISPLAY = {
    "Discovered": "Discovered",
    "Pending review": "Pending review",
    "Managed": "Managed",
    "Inspection queued": "Inspection queued",
    "Scan queued": "Scan queued",
    "Retired": "Retired",
}

CRITICALITY_DISPLAY = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


def severity_display(value: Any) -> str:
    text = str(value or "Info")
    return SEVERITY_DISPLAY.get(text, text)


def lifecycle_display(value: Any) -> str:
    text = str(value or "Discovered")
    return LIFECYCLE_DISPLAY.get(text, text)


def criticality_display(value: Any) -> str:
    text = str(value or "Medium")
    return CRITICALITY_DISPLAY.get(text, text)


def apply_securescope_ui_theme() -> None:
    """Load tokens and component styles in one deterministic application boundary.

    Returns:
        None.
    Raises:
        OSError: If a packaged stylesheet is missing.
    """
    style_root = Path(__file__).with_name("styles")
    css = "\n".join(
        (style_root / name).read_text(encoding="utf-8")
        for name in ("tokens.css", "screen_compat.css", "legacy.css", "components.css", "sidebar.css")
    )
    st.html("<style>" + css + "</style>")


def render_sidebar_mode_css(compact: bool) -> None:
    """Expose the current sidebar mode to CSS."""
    mode = "compact" if compact else "expanded"
    st.markdown(
        f'<span class="ss-sidebar-mode-{mode}" style="display:none"></span>',
        unsafe_allow_html=True,
    )


def render_asset_legends() -> None:
    """Render lifecycle semantics using the shared status component.

    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    st.html(
        '<div class="ss-legend">'
        + " ".join(status_pill(label) for label in LIFECYCLE_DISPLAY)
        + "</div>"
    )


def render_severity_legend() -> None:
    """Render severity semantics using the shared status component.

    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    st.html(
        '<div class="ss-legend">'
        + " ".join(status_pill(label) for label in SEVERITY_DISPLAY)
        + "</div>"
    )
