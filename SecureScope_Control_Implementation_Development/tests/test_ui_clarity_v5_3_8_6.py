"""Regression contracts for the v5.3.8.6 UX clarity release."""

from pathlib import Path

from tests.ui_style_sources import read_theme_source

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def test_command_center_does_not_render_attention_queue() -> None:
    """Keep the tall duplicate attention panel out of the dashboard."""

    source = (SOURCE_ROOT / "ui/pages/command_center.py").read_text(encoding="utf-8")
    assert "render_attention_queue" not in source
    assert "render_attention_panel" in source
    assert "Programme Attention" in source
    assert "Continue Programme" in source


def test_theme_uses_windows_first_professional_font_stack() -> None:
    """Keep typography offline-safe and consistent with the Windows release."""

    source = read_theme_source()
    assert "Segoe UI Variable Text" in source
    assert "--ss-font-sans" in source
    assert "font-family: var(--ss-font-sans)" in source


def test_programme_overview_does_not_duplicate_register_navigation() -> None:
    """The segmented programme navigation is the single register navigation."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    assert "Advanced registers" not in source
    assert "Foundation areas" in source
    assert "Review details" in source


def test_ui_and_table_standards_are_documented() -> None:
    """Keep the UX system and table contract versioned with the application."""

    assert (PROJECT_ROOT / "docs/ui_ux/SECURESCOPE_UI_UX_STANDARD.md").exists()
    assert (PROJECT_ROOT / "docs/ui_ux/DATA_TABLE_STANDARD.md").exists()
