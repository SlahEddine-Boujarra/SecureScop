"""Regressions for shared stylesheet ownership and presentation-only components."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from securescope.ui.component_styles import component_styles
from securescope.ui.components.primitives import status_pill


@pytest.mark.parametrize(
    "styles",
    [
        ("assurance_workbench.css",),
        ("assurance_plan.css",),
        ("assurance_plan.css", "assurance_pages.css"),
        ("policy_editor.css",),
        ("table.css",),
    ],
)
def test_existing_shadow_components_have_shared_tokens(styles):
    """Isolated components receive a complete, matching token vocabulary."""
    css = component_styles(*styles)
    assert css.startswith("/* SecureScope design tokens.")
    assert ":host {" in css
    assert "--ss-text:" in css
    assert "--ss-accent:" in css
    assert "var(--ss-accent)" in css
    assert css.index("--ss-text:") < css.index("Current presentation inside")


def test_stylesheet_loader_rejects_paths_outside_bundled_assets():
    """Only packaged CSS resources can be loaded through the component adapter."""
    with pytest.raises(ValueError):
        component_styles("../app.py")


def test_style_injection_has_one_application_owner():
    """Old inline theme injectors cannot override the shared application loader."""
    root = Path(__file__).resolve().parents[1] / "src/securescope"
    source = (root / "app.py").read_text()
    for name in [
        "inject_dashboard_styles",
        "inject_full_app_styles",
        "inject_asset_management_styles",
        "inject_ui_readability_patch",
    ]:
        assert f"def {name}" not in source
        assert f"{name}()" not in source
    assert source.count("\napply_securescope_ui_theme()") == 1
    assert "st.tabs(" not in source


@pytest.mark.parametrize(
    "label,tone",
    [
        ("Draft", "neutral"),
        ("In Progress", "info"),
        ("Needs review", "warning"),
        ("Blocked", "danger"),
        ("Approved", "success"),
    ],
)
def test_existing_statuses_keep_text_and_semantic_tone(label, tone):
    """Shared display styling never replaces the persisted status vocabulary."""
    markup = status_pill(label)
    assert f'data-tone="{tone}"' in markup
    assert "ss-status" in markup


def test_visible_workflow_section_uses_shared_status_component():
    """Workflow headings remain visible and status labels cannot inject HTML."""
    app = AppTest.from_string("""
from securescope.ui.workflow_sections import workflow_section
import streamlit as st
with workflow_section("Assessment", "Review the saved evidence.", status="<script>bad</script>", step=2):
    st.text_input("Conclusion")
""").run()
    assert not app.exception
    assert "2 · Assessment" in app.markdown[0].value
    assert app.text_input[0].label == "Conclusion"
    assert "&lt;script&gt;" in app.get("html")[0].proto.body
