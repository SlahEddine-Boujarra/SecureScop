"""Navigation state contracts, independent of database availability."""

from types import SimpleNamespace
from unittest.mock import MagicMock as Mock

from securescope.ui.components import navigation


def test_tab_click_updates_canonical_value_before_domain_callback(monkeypatch):
    state = {}
    tabs = Mock()
    monkeypatch.setattr(navigation, "st", SimpleNamespace(session_state=state, tabs=tabs))
    seen = []
    assert (
        navigation.section_navigation(
            "Lifecycle",
            ["register", "treatment"],
            key="risk",
            on_change=lambda client: seen.append((client, state["risk"])),
            args=("Client",),
        )
        == "register"
    )
    labels = tabs.call_args.args[0]
    state["risk::navigation_tabs"] = labels[1]
    tabs.call_args.kwargs["on_change"]()
    assert seen == [("Client", "treatment")]
    assert (
        navigation.section_navigation("Lifecycle", ["register", "treatment"], key="risk")
        == "treatment"
    )


def test_programmatic_navigation_and_client_keys_remain_isolated(monkeypatch):
    state = {"client-a": "scope", "client-b": "context"}
    tabs = Mock()
    monkeypatch.setattr(navigation, "st", SimpleNamespace(session_state=state, tabs=tabs))
    for key in ("client-a", "client-b"):
        assert (
            navigation.section_navigation("Foundation", ["context", "scope"], key=key) == state[key]
        )
    state["client-a"] = "context"
    navigation.section_navigation("Foundation", ["context", "scope"], key="client-a")
    assert state["client-a::navigation_tabs"].endswith("context")
    assert state["client-b"] == "context"


def test_native_tabs_keep_existing_icons_and_forward_native_options(monkeypatch):
    tabs = Mock()
    monkeypatch.setattr(navigation, "st", SimpleNamespace(tabs=tabs))
    navigation.module_tabs(
        [":material/shield: Control profiles", "Overview"], key="existing", on_change="rerun"
    )
    labels = tabs.call_args.args[0]
    assert labels[0] == ":material/shield: Control profiles"
    assert labels[1] == ":material/dashboard: Overview"
    assert tabs.call_args.kwargs == {"key": "existing", "on_change": "rerun"}


def test_sidebar_dark_overrides_cannot_return():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src/securescope"
    app = (root / "app.py").read_text()
    sidebar = (root / "ui/styles/sidebar.css").read_text()
    assert "Sidebar: keep labels light" not in app
    assert "linear-gradient(180deg, #0b1325 0%, #121e38 100%)" not in app
    assert "-webkit-text-fill-color:currentColor!important" in sidebar
    compatibility = (root / "ui/styles/screen_compat.css").read_text()
    assert 'button:not([data-testid="stSidebar"] *)' not in compatibility


def test_native_tab_style_has_no_competing_legacy_rules():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src/securescope/ui/styles"
    assert '[data-testid="stTabs"]' not in (root / "legacy.css").read_text()
    canonical = (root / "components.css").read_text().split("/* Canonical module navigation:", 1)[1]
    assert "#eff3ff" not in canonical
    assert "flex-wrap:nowrap!important" in canonical


def test_section_formatter_keeps_existing_icon(monkeypatch):
    """An existing formatted icon remains singular in Discovery navigation."""
    state = {}
    tabs = Mock()
    monkeypatch.setattr(navigation, "st", SimpleNamespace(session_state=state, tabs=tabs))
    navigation.section_navigation(
        "Discovery",
        ["context"],
        key="discovery",
        format_func=lambda value: ":material/hub: Context suggestions",
    )
    assert tabs.call_args.args[0] == [":material/hub: Context suggestions"]


def test_selected_content_is_inside_native_panel():
    """Content is owned by its tab, so a browser switch can hide the previous page."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_string("""
import streamlit as st
from securescope.ui.components.navigation import section_navigation
selected = section_navigation("Foundation", ["Overview", "Discovery"], key="section")
with selected.panel:
    st.header(str(selected) + " content")
""").run()
    assert not app.exception
    assert app.tabs[0].header[0].value == "Overview content"
    assert not app.tabs[1].header
    app.session_state["section"] = "Discovery"
    app.run()
    assert not app.exception
    assert app.tabs[1].header[0].value == "Discovery content"
    assert not app.tabs[0].header


def test_shared_tab_indicator_has_one_visual_owner():
    """Native animated decoration must not overlap the shared fixed underline."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src/securescope"
    css = (root / "ui/styles/components.css").read_text()
    assert ".react-aria-SelectionIndicator{display:none!important}" in css
    assert '[role="tablist"]::after{content:none!important}' in css
    assert '[data-testid="stTabs"] button[role="tab"]' not in (root / "app.py").read_text()


def test_navigation_reruns_do_not_accumulate_tab_bars():
    """Repeated selection retains one bar and exactly one active content block."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_string("""
from securescope.ui.components.navigation import section_navigation
import streamlit as st
selected = section_navigation("Lifecycle", ["Assessment", "Treatment"], key="stage")
with selected.panel:
    st.header(str(selected))
""").run()
    for selection in ["Treatment", "Assessment", "Treatment"]:
        app.session_state["stage"] = selection
        app.run()
        assert not app.exception
        assert len(app.get("tab_container")) == 1
        assert len(app.tabs) == 2
        assert [header.value for header in app.header] == [selection]
