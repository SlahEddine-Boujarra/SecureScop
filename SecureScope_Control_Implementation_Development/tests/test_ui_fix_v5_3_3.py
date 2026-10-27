"""Static contracts for the targeted SecureScope v5.3.3 UI correction."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.ui_style_sources import read_theme_source

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"


def _function_source(source: str, function_name: str) -> str:
    """Return one top-level function body from Python source text.

    Args:
        source: Complete Python source text.
        function_name: Top-level function name without the ``def`` keyword.

    Returns:
        The source slice beginning at the selected function.

    Raises:
        AssertionError: If the requested function cannot be located.
    """
    marker = f"def {function_name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"Missing function: {function_name}")
    next_function = source.find("\ndef ", start + len(marker))
    return source[start:] if next_function < 0 else source[start:next_function]


class UiFixContractTests(unittest.TestCase):
    """Verify menu alignment and Asset Management presentation boundaries."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the two presentation sources once for all tests.

        Returns:
            None.

        Raises:
            OSError: If a required source file cannot be read.
        """
        cls.app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        cls.theme_source = read_theme_source()

    def test_expanded_sidebar_items_are_left_aligned(self) -> None:
        """Require a fixed icon/label origin and spacing in expanded mode."""
        self.assertIn("justify-content: flex-start !important", self.theme_source)
        self.assertIn("gap: var(--ss-space-2) !important", self.theme_source)
        self.assertIn("text-align: left !important", self.theme_source)

    def test_tabs_are_separated_button_controls(self) -> None:
        """Prevent the ISO section labels from being concatenated."""
        self.assertIn("flex-wrap:nowrap!important;gap:6px!important", self.theme_source)
        self.assertIn("border-bottom-color:var(--ss-accent)!important", self.theme_source)
        self.assertIn("min-width:max-content!important", self.theme_source)
        self.assertIn("background:var(--ss-surface)!important", self.theme_source)

    def test_asset_page_has_no_workflow_or_clock_panel(self) -> None:
        """Keep workflow shortcuts and clock assurance out of Asset Management."""
        function_source = _function_source(
            self.app_source,
            "render_asset_management_page",
        )
        self.assertNotIn('render_workflow_bar("Asset Management")', function_source)
        self.assertNotIn("render_ntp_clock_synchronization_panel", function_source)
        self.assertNotIn('("Clock status",', function_source)
        self.assertNotIn('("Time source",', function_source)

    def test_asset_register_has_no_clock_columns(self) -> None:
        """Remove clock fields from the Asset Management register only."""
        function_source = _function_source(self.app_source, "_asset_table_rows")
        self.assertNotIn('"Clock status":', function_source)
        self.assertNotIn('"Time source":', function_source)

    def test_ntp_backend_remains_available(self) -> None:
        """Preserve the NTP service and ISO A.8.17 evidence implementation."""
        self.assertIn("def render_ntp_clock_synchronization_panel", self.app_source)
        self.assertIn("collect_wazuh_ntp_evidence", self.app_source)
        self.assertTrue((ROOT / "integrations" / "ntp_audit_service.py").is_file())
        self.assertTrue((ROOT / "persistence" / "clock_evidence_persistence.py").is_file())


if __name__ == "__main__":
    unittest.main()
