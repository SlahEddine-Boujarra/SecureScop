"""Regression contracts for the v5.3.8.3 UI repair and dashboard release."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from securescope.ui.components.register_table import render_register_table
from tests.ui_style_sources import read_theme_source

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


class RegisterTableCompatibilityTests(unittest.TestCase):
    """Protect Streamlit 1.49+ dataframe height validation compatibility."""

    def test_omits_none_height_from_dataframe_call(self) -> None:
        """Do not pass ``height=None`` to modern Streamlit versions."""

        frame = pd.DataFrame([{"Control": "A.5.1"}])
        with patch(
            "securescope.ui.components.register_table.st.dataframe",
            create=True,
        ) as mocked:
            render_register_table(
                frame,
                empty_title="Empty",
                empty_message="Empty",
                key="height_none_test",
            )
        self.assertNotIn("height", mocked.call_args.kwargs)

    def test_preserves_explicit_dataframe_height(self) -> None:
        """Keep caller-supplied positive pixel heights unchanged."""

        frame = pd.DataFrame([{"Control": "A.5.1"}])
        with patch(
            "securescope.ui.components.register_table.st.dataframe",
            create=True,
        ) as mocked:
            render_register_table(
                frame,
                empty_title="Empty",
                empty_message="Empty",
                height=240,
            )
        self.assertEqual(mocked.call_args.kwargs["height"], 240)


class UiRepairArchitectureTests(unittest.TestCase):
    """Protect the visible-navigation, field and dashboard repairs."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load UI sources shared by static regression checks."""

        cls.theme_source = read_theme_source()
        cls.command_source = (SOURCE_ROOT / "ui" / "pages" / "command_center.py").read_text(
            encoding="utf-8"
        )
        cls.dashboard_source = (SOURCE_ROOT / "ui" / "components" / "dashboard.py").read_text(
            encoding="utf-8"
        )

    def test_form_controls_have_stronger_visible_boundaries(self) -> None:
        """Keep empty input and text-area fields visible on light surfaces."""

        self.assertIn("--ss-field-border", self.theme_source)
        self.assertIn("--ss-field-bg", self.theme_source)
        self.assertIn('div[data-baseweb="textarea"]', self.theme_source)
        self.assertIn("min-height: 5.25rem", self.theme_source)

    def test_control_navigation_keeps_labels_visible(self) -> None:
        """Do not return Control/SoA navigation to icon-only mystery tabs."""

        self.assertIn('[data-testid="stMain"] [role="tab"] p', self.theme_source)
        self.assertIn("font-size:13px!important", self.theme_source)
        self.assertIn(
            "display:flex!important;align-items:center!important;gap:7px!important",
            self.theme_source,
        )

    def test_command_center_has_decision_dashboard_components(self) -> None:
        """Keep the new dashboard metrics, assurance and evidence panels wired."""

        for symbol in (
            "render_stitch_metrics",
            "render_certification_journey",
            "render_assurance_distribution",
            "render_technical_coverage",
            "render_attention_panel",
        ):
            self.assertIn(symbol, self.command_source)
        self.assertIn("Programme Foundation", self.command_source)
        self.assertIn("Controls Assessed", self.command_source)
        self.assertIn("Open Gaps", self.command_source)
        self.assertIn("Evidence Coverage", self.command_source)
        stitch_source = (SOURCE_ROOT / "ui" / "components" / "stitch.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("ss-stitch-kpi", stitch_source)


if __name__ == "__main__":
    unittest.main()
