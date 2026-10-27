"""Static regression contracts for the integrated v5.3.5 sidebar."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"


def _function_source(source: str, function_name: str) -> str:
    """Return one top-level function body from Python source text.

    Args:
        source: Complete Python source text.
        function_name: Top-level function name without the ``def`` keyword.

    Returns:
        Source slice beginning at the selected function.

    Raises:
        AssertionError: If the requested function cannot be found.
    """
    marker = f"def {function_name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"Missing function: {function_name}")

    next_function = source.find("\ndef ", start + len(marker))
    return source[start:] if next_function < 0 else source[start:next_function]


class SidebarIntegrationV535Tests(unittest.TestCase):
    """Protect the menu integration and workspace-scoped application state."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load application and sidebar sources used by the contracts.

        Returns:
            None.

        Raises:
            OSError: If a required source file cannot be read.
        """
        cls.app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        cls.sidebar_source = (ROOT / "ui" / "securescope_sidebar.py").read_text(encoding="utf-8")
        cls.navigation_source = (ROOT / "ui" / "navigation.py").read_text(encoding="utf-8")

    def test_real_application_uses_integrated_sidebar_module(self) -> None:
        """Require the application entry point to call the shared menu."""
        render_source = _function_source(
            self.app_source,
            "render_app_sidebar",
        )

        self.assertIn(
            "from securescope.ui.securescope_sidebar import render_sidebar_menu",
            self.app_source,
        )
        self.assertIn("return render_sidebar_menu(", render_source)
        self.assertIn(
            "open_workspace_dialog=render_client_workspace_dialog",
            render_source,
        )
        self.assertIn(
            "open_connection_dialog=render_connection_status_dialog",
            render_source,
        )
        self.assertNotIn("render_sidebar_mode_css", self.app_source)
        self.assertNotIn("def _toggle_sidebar_compact", self.app_source)

    def test_sidebar_routes_every_existing_application_page(self) -> None:
        """Keep the custom sidebar compatible with the modern page registry."""
        expected_keys = (
            '"ISO Command Center"',
            '"Overview"',
            '"Programme Setup"',
            '"Gap Assessment"',
            '"2 · Asset Management"',
            '"3 · Scan Center"',
            '"4 · Reports & Findings"',
            '"5 · SIEM & Wazuh"',
            '"Remediation"',
            '"Client History"',
            '"Client Workspace"',
            '"1 · Asset Discovery"',
            '"6 · ISO 27001 Assessment"',
            '"ISO Evidence Hub"',
        )

        for key in expected_keys:
            self.assertIn(key, self.navigation_source)
            self.assertIn(key, self.app_source)

        self.assertIn("st.page_link(", self.sidebar_source)
        self.assertNotIn("st.switch_page(", self.sidebar_source)

    def test_compact_geometry_matches_validated_menu(self) -> None:
        """Keep the approved rail, button and icon dimensions unchanged."""
        from tests.ui_style_sources import read_theme_source

        css = read_theme_source()
        for contract in (
            "--ss-sidebar-compact-width: 72px",
            "--ss-sidebar-width: 252px",
            "flex: 0 0 20px",
            "ss-sidebar-mode-compact",
        ):
            self.assertIn(contract, css)
        for key in (
            "sidebar_compact_toggle",
            "open_client_dialog_compact",
            "open_connection_dialog_compact",
        ):
            self.assertIn(key, self.sidebar_source)

        self.assertNotIn('if __name__ == "__main__"', self.sidebar_source)

    def test_workspace_switch_still_clears_client_local_state(self) -> None:
        """Prevent menu integration from weakening client isolation."""
        switch_source = _function_source(
            self.app_source,
            "switch_client_workspace",
        )

        expected_state_updates = (
            "st.session_state.active_client_name = clean_name",
            "load_asset_inventory(clean_name)",
            "load_scan_history(clean_name)",
            '"selected_persistent_openvas_batch_id"',
            '"openvas_live_selected_job_id"',
            '"openvas_parallel_pending_launch"',
        )

        for update in expected_state_updates:
            self.assertIn(update, switch_source)


if __name__ == "__main__":
    unittest.main()
