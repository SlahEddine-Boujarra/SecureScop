"""Static contracts for the SecureScope v5.3.4 UI-only correction."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.ui_style_sources import read_theme_source

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"


class UiFixV534ContractTests(unittest.TestCase):
    """Protect the global bar removal, menu alignment and icon toolbars."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load presentation sources used by every contract.

        Returns:
            None.

        Raises:
            OSError: If one of the required source files cannot be read.
        """
        cls.app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        cls.exposure_source = (ROOT / "ui" / "exposure_management_ui.py").read_text(
            encoding="utf-8"
        )
        cls.theme_source = read_theme_source()

    def test_workflow_bar_is_removed_globally(self) -> None:
        """Reject renderer calls, renderer code and stale navigation state."""
        combined_source = self.app_source + self.theme_source
        self.assertNotIn("render_workflow_bar", combined_source)
        self.assertNotIn("ss-flow-shell", combined_source)
        self.assertNotIn("workflow_navigation_request", combined_source)
        self.assertNotIn("workflow_button_", combined_source)

    def test_sidebar_material_icons_have_a_fixed_column(self) -> None:
        """Require every Material glyph to consume the same horizontal width."""
        self.assertIn('[data-testid="stIconMaterial"]', self.theme_source)
        self.assertIn(".material-symbols-rounded", self.theme_source)
        self.assertIn("width: 20px", self.theme_source)
        self.assertIn("flex: 0 0 20px", self.theme_source)
        self.assertIn("justify-content: flex-start !important", self.theme_source)

    def test_iso_a8_sections_keep_clear_visible_labels(self) -> None:
        """Keep only the non-duplicated A.8 assurance workspaces."""
        expected_labels = (
            ":material/dashboard: A.8 dashboard",
            ":material/fact_check: Review control",
            ":material/link: Technical evidence",
            ":material/schema: Methodology",
            ":material/description: A.8 export",
        )
        for label in expected_labels:
            self.assertIn(label, self.app_source)
        self.assertNotIn(
            ":material/task_alt: Corrective actions",
            self.app_source,
        )
        self.assertNotIn(
            ":material/bug_report: Vulnerability intelligence",
            self.app_source,
        )
        self.assertIn('key="iso_a8_icon_tabs"', self.app_source)

    def test_gap_assessment_sections_are_accessible_controls(self) -> None:
        """Keep the assurance and governance sections clearly named."""
        expected_labels = (
            ":material/table_view: Control profiles",
            ":material/fact_check: Assess control",
            ":material/folder_open: Evidence",
            ":material/assignment_late: Gap actions",
            ":material/description: Statement of Applicability",
        )
        for label in expected_labels:
            self.assertIn(label, self.exposure_source)
        self.assertNotIn(
            ":material/workspaces: GRC Workspace",
            self.exposure_source,
        )
        self.assertIn(
            'key="control_assurance_tabs"',
            self.exposure_source,
        )

    def test_assurance_tabs_keep_labels_visible(self) -> None:
        """Do not hide assurance navigation behind icon-only tooltips."""
        self.assertIn(
            '[data-testid="stMain"] [role="tab"] p',
            self.theme_source,
        )
        self.assertIn("font-size:13px!important", self.theme_source)
        self.assertIn("min-width:max-content!important", self.theme_source)


if __name__ == "__main__":
    unittest.main()
