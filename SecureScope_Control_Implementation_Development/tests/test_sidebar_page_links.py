"""Regressions for native sidebar destinations across reruns and compact mode."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

from securescope.ui.securescope_sidebar import NAVIGATION_GROUPS

ROOT = Path(__file__).resolve().parents[1]


def test_every_menu_link_renders_its_registered_destination():
    """Simulate the page-hash event sent by each native link.

    Returns:
        None.
    Raises:
        AssertionError: If a link is missing, duplicated or opens another page.
    """
    app = AppTest.from_file(str(ROOT / "scripts/ui_hardening_preview.py")).run()
    assert not app.exception
    destinations = {label: key for _, items in NAVIGATION_GROUPS for key, _, label, _ in items}
    destinations["Client Workspace"] = "Client Workspace"
    links = {link.proto.label: link.proto.page_script_hash for link in app.get("page_link")}
    assert set(links) == set(destinations)
    assert len(app.get("page_link")) == len(destinations)
    assert len(set(links.values())) == len(destinations)
    for label, page_hash in links.items():
        # AppTest's public switch_page accepts filesystem pages only. This
        # supplies the same page hash that the browser sends for callable pages.
        app._page_hash = page_hash
        app.run()
        assert not app.exception
        assert app.title[0].value == f"UI verification — {destinations[label]}"
        assert len(app.get("page_link")) == len(destinations)
        assert not any("no-op" in warning.value for warning in app.warning)


def test_compact_toggle_and_workspace_dialog_keep_menu_links():
    """Keep route targets and accessible labels through unrelated reruns.

    Returns:
        None.
    Raises:
        AssertionError: If a mode/dialog rerun loses or changes destinations.
    """
    app = AppTest.from_file(str(ROOT / "scripts/ui_hardening_preview.py")).run()
    expected = {link.proto.label: link.proto.page_script_hash for link in app.get("page_link")}
    for _ in range(2):
        app.button(key="sidebar_compact_toggle").click().run()
        assert not app.exception
        assert {
            link.proto.label: link.proto.page_script_hash for link in app.get("page_link")
        } == expected
    app.button(key="open_client_dialog_expanded").click().run()
    assert not app.exception
    next(button for button in app.button if button.label == "Done").click().run()
    assert not app.exception
    assert {
        link.proto.label: link.proto.page_script_hash for link in app.get("page_link")
    } == expected
