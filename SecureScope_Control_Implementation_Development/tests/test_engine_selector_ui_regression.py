"""Regression checks for the v5.2.0 scanner selector conflict."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"


def test_sidebar_no_longer_owns_scanner_engine_widget() -> None:
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "sidebar_scan_engine_selector" not in source
    assert "cycle_scanner_engine_compact" not in source
    assert "Vulnerability engine</div>" not in source


def test_scan_center_uses_normal_engine_buttons() -> None:
    source = (ROOT / "ui" / "dual_engine_ui.py").read_text(encoding="utf-8")
    assert "scan_center_engine_button_" in source
    assert "on_click=_activate_scan_engine" in source
    assert "scan_center_engine_selector" not in source
    assert "st.segmented_control(" not in source


def test_target_selection_uses_normal_buttons() -> None:
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    dual_source = (ROOT / "ui" / "dual_engine_ui.py").read_text(encoding="utf-8")
    assert 'render_button_choice(\n            "Target selection"' in app_source
    assert 'render_button_choice(\n                    "Target selection"' in dual_source
