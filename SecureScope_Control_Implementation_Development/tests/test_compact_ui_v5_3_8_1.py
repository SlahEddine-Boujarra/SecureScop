"""Static regression contracts for the v5.3.8.1 compact UI maintenance release."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from tests.ui_style_sources import read_theme_source

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def _function_source(source: str, function_name: str) -> str:
    """Return one top-level function body from Python source text.

    Args:
        source: Complete Python module source.
        function_name: Function name without the ``def`` keyword.

    Returns:
        Source slice beginning at the requested function.

    Raises:
        AssertionError: If the requested function is missing.
    """

    marker = f"def {function_name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"Missing function: {function_name}")
    next_function = source.find("\ndef ", start + len(marker))
    return source[start:] if next_function < 0 else source[start:next_function]


class CompactUiContractTests(unittest.TestCase):
    """Protect visible fields, compact workflows and readable registers."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the presentation sources used by every test.

        Returns:
            None.

        Raises:
            OSError: If a required source file cannot be read.
        """

        cls.exposure_source = (SOURCE_ROOT / "ui" / "exposure_management_ui.py").read_text(
            encoding="utf-8"
        )
        cls.workspace_source = (SOURCE_ROOT / "ui" / "grc_workspace_ui.py").read_text(
            encoding="utf-8"
        )
        cls.context_source = (SOURCE_ROOT / "ui" / "grc_workspace" / "context.py").read_text(
            encoding="utf-8"
        )
        cls.context_bar_source = (SOURCE_ROOT / "ui" / "components" / "context_bar.py").read_text(
            encoding="utf-8"
        )
        cls.theme_source = read_theme_source()
        cls.sidebar_source = (SOURCE_ROOT / "ui" / "securescope_sidebar.py").read_text(
            encoding="utf-8"
        )

    def test_main_form_controls_have_visible_baseweb_boundaries(self) -> None:
        """Style current Streamlit wrappers instead of only native inputs."""

        self.assertIn('[data-testid="stMain"]', self.theme_source)
        self.assertIn('div[data-baseweb="input"]', self.theme_source)
        self.assertIn('div[data-baseweb="textarea"]', self.theme_source)
        self.assertIn("border: 1px solid var(--ss-border-strong)", self.theme_source)
        self.assertIn('[data-testid="stForm"]', self.theme_source)
        self.assertIn("gap: .72rem !important", self.theme_source)

    def test_assessment_workflow_has_numbered_compact_sections(self) -> None:
        """Prevent the manual assessment from returning to one long blank form."""

        function_source = _function_source(
            self.exposure_source,
            "_render_manual_control_assessment",
        )
        expected_sections = (
            "1. Scope and assessment conclusion",
            "2. Gap and treatment",
            "3. Six independent assurance dimensions",
            "4. Evidence and validation",
            "5. Effectiveness test",
        )
        for section in expected_sections:
            self.assertIn(section, function_source)
        self.assertIn("FORM_TEXT_AREA_HEIGHT", function_source)
        self.assertIn("dimension_columns = st.columns(3)", function_source)

    def test_target_and_treatment_forms_use_grouped_columns(self) -> None:
        """Keep approval and risk-treatment fields grouped by business purpose."""

        assessment_source = _function_source(
            self.exposure_source,
            "_render_manual_control_assessment",
        )
        gap_page_source = _function_source(
            self.exposure_source,
            "render_gap_assessment_page",
        )
        self.assertIn("target_columns = st.columns(3)", assessment_source)
        self.assertIn("rationale_columns = st.columns(2)", assessment_source)
        self.assertNotIn(
            "render_treatment_links(client_name)",
            gap_page_source,
        )
        self.assertNotIn("risk_treatment_plan_form", gap_page_source)

    def test_remediation_registers_do_not_render_raw_repository_rows(self) -> None:
        """Expose consultant labels while retaining stable numeric references."""

        page_source = _function_source(
            self.exposure_source,
            "render_remediation_page",
        )
        plan_helper = _function_source(
            self.exposure_source,
            "_remediation_plan_rows",
        )
        work_helper = _function_source(
            self.exposure_source,
            "_remediation_work_item_rows",
        )
        treatment_helper = _function_source(
            self.exposure_source,
            "_risk_treatment_plan_rows",
        )
        self.assertIn("_remediation_plan_rows(plans)", page_source)
        self.assertIn("_remediation_work_item_rows(work_items)", page_source)
        self.assertNotIn("pd.DataFrame(plans)", page_source)
        self.assertNotIn("pd.DataFrame(work_items)", page_source)
        self.assertNotIn("plan_uuid", plan_helper)
        self.assertIn('"Work item"', work_helper)
        self.assertNotIn("plan_uuid", treatment_helper)
        self.assertIn('"Linked controls"', treatment_helper)

    def test_current_actor_is_part_of_the_persistent_context_bar(self) -> None:
        """Keep actor identity aligned without recreating the oversized metric."""

        self.assertIn("render_context_bar(client_name, context, actor=actor)", self.context_source)
        self.assertIn('("Current actor", actor, "person")', self.context_bar_source)
        self.assertNotIn('st.metric(\n            "Current actor"', self.workspace_source)

    def test_sidebar_uses_labels_that_fit_the_expanded_rail(self) -> None:
        """Keep long route names from appearing truncated in normal navigation."""

        self.assertIn('"Scan Center"', self.sidebar_source)
        self.assertIn('"Control Assurance"', self.sidebar_source)
        self.assertIn('"Vulnerabilities"', self.sidebar_source)
        self.assertIn("--ss-shell-primary: var(--ss-accent)", self.theme_source)

    def test_database_migrations_remain_byte_identical(self) -> None:
        """Confirm the UI patch does not mutate published database history."""

        expected = {
            "001_v6_exposure_grc.sql": (
                "9f48796bfb070d6de8ca7eda96b0d61e889d940ad503c9c8fc1c439e625f9d0f"
            ),
            "002_v6_1_quick_remediation.sql": (
                "77f6cb0179325e859b7f5cffc864b4f934f1675b8bf293afff0b816027210874"
            ),
            "003_legacy_iso_evidence_bridge.sql": (
                "26e564bc022ee3daf151b25cd007ccafa513da2ea07883dc7e93758cb5138a09"
            ),
            "003_v5_3_7_iso_evidence_platform.sql": (
                "1137a461d007f793632191e84d251da945b40f0a375372254481f12a96c3831e"
            ),
            "004_v5_3_7_iso_evidence_platform.sql": (
                "90592065cdd951c0138c33497103ab57ac3f2381574f38fda5f3a2e995ba1813"
            ),
            "005_grc_engagement_context_scope.sql": (
                "dd0026bf1aaa33b5622576ed37c0932f0043b66b05bef8fb9c3f4f418f3da9e2"
            ),
        }
        migration_root = PROJECT_ROOT / "database" / "migrations"
        for filename, expected_hash in expected.items():
            actual = hashlib.sha256((migration_root / filename).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_hash, filename)


if __name__ == "__main__":
    unittest.main()
