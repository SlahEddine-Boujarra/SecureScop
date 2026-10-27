"""Regression contracts for the v5.3.8.2 Experience Foundation."""

from __future__ import annotations

import hashlib
import unittest
from datetime import date, timedelta
from pathlib import Path

from securescope.grc.program_progress_service import calculate_program_progress

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


class ProgramProgressTests(unittest.TestCase):
    """Verify conservative programme progress and attention rules."""

    def test_only_scoped_foundation_items_contribute_to_percentage(self) -> None:
        """Calculate progress from eight explicit foundation rules only."""

        snapshot = calculate_program_progress(
            {
                "engagement": {"status": "Active"},
                "approved_scope_version": {"id": 4},
                "context_issues": 2,
                "interested_parties": 1,
                "applicable_requirements": 1,
                "role_assignments": 3,
            },
            [{"version_number": 1}],
            [{"status": "Planned", "due_date": date.today()}],
        )

        self.assertEqual(snapshot.completed, 8)
        self.assertEqual(snapshot.total, 8)
        self.assertEqual(snapshot.percentage, 100)
        self.assertEqual(snapshot.readiness, "Foundation ready for internal review")
        self.assertEqual(snapshot.dimensions[0].percentage, 100)
        self.assertIsNone(snapshot.dimensions[1].percentage)

    def test_missing_scope_and_overdue_milestone_create_attention(self) -> None:
        """Prioritize overdue work without calling it noncompliance."""

        snapshot = calculate_program_progress(
            {
                "engagement": {"status": "Draft"},
                "approved_scope_version": None,
                "context_issues": 0,
                "interested_parties": 0,
                "applicable_requirements": 0,
                "role_assignments": 0,
            },
            [],
            [
                {
                    "status": "Planned",
                    "due_date": date.today() - timedelta(days=1),
                }
            ],
            today=date.today(),
        )

        self.assertEqual(snapshot.percentage, 12)
        self.assertEqual(snapshot.attention[0].severity, "Overdue")
        self.assertTrue(any(item.section == "scope" for item in snapshot.attention))


class ExperienceArchitectureTests(unittest.TestCase):
    """Protect direct routing, lazy queries, and form-on-demand behavior."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load presentation sources shared by architecture tests.

        Returns:
            None.

        Raises:
            OSError: If a required source file cannot be read.
        """

        cls.app_source = (SOURCE_ROOT / "app.py").read_text(encoding="utf-8")
        cls.sidebar_source = (SOURCE_ROOT / "ui" / "securescope_sidebar.py").read_text(
            encoding="utf-8"
        )
        cls.router_source = (SOURCE_ROOT / "ui" / "grc_workspace" / "router.py").read_text(
            encoding="utf-8"
        )
        cls.dialog_source = (SOURCE_ROOT / "ui" / "grc_workspace" / "dialogs.py").read_text(
            encoding="utf-8"
        )
        cls.scope_editor_source = (
            SOURCE_ROOT / "ui" / "grc_workspace" / "scope_editor.py"
        ).read_text(encoding="utf-8")
        cls.exposure_source = (SOURCE_ROOT / "ui" / "exposure_management_ui.py").read_text(
            encoding="utf-8"
        )
        cls.service_source = (SOURCE_ROOT / "grc" / "engagement_service.py").read_text(
            encoding="utf-8"
        )
        cls.navigation_source = (SOURCE_ROOT / "ui" / "navigation.py").read_text(encoding="utf-8")

    def test_command_center_and_programme_setup_are_direct_routes(self) -> None:
        """Keep ISO workspaces as first-class modern Streamlit routes."""

        self.assertIn('PageSpec("ISO Command Center"', self.navigation_source)
        self.assertIn('PageSpec("Programme Setup"', self.navigation_source)
        self.assertIn('PageSpec("ISO Evidence Hub"', self.navigation_source)
        self.assertIn('"ISO Command Center": lambda: render_iso_command_center(', self.app_source)
        self.assertIn('"Programme Setup": lambda: render_grc_workspace(', self.app_source)
        self.assertIn('"ISO Evidence Hub": lambda: render_iso_evidence_hub(', self.app_source)
        self.assertIn("run_hidden_navigation(page_registry)", self.app_source)
        self.assertNotIn(":material/workspaces: GRC Workspace", self.exposure_source)
        self.assertNotIn("render_grc_workspace(client_name)", self.exposure_source)

    def test_programme_router_renders_only_selected_section(self) -> None:
        """Query and render only the selected Programme Setup section."""

        self.assertIn("section_navigation(", self.router_source)
        self.assertIn("SERVICE.load_section(", self.router_source)
        self.assertNotIn("st.tabs(", self.router_source)
        self.assertIn('"overview"', self.service_source)
        self.assertIn('"roles"', self.service_source)

    def test_short_forms_are_dialogs_and_scope_is_a_six_step_editor(self) -> None:
        """Keep create forms hidden until an explicit action is requested."""

        self.assertGreaterEqual(self.dialog_source.count("@st.dialog("), 10)
        self.assertIn("SCOPE_EDITOR_STEPS = (", self.scope_editor_source)
        for step in (
            "Identity & purpose",
            "Organization & locations",
            "Services & technology",
            "Boundaries & interfaces",
            "Exclusions & dates",
            "Review & create",
        ):
            self.assertIn(step, self.scope_editor_source)
        self.assertIn("Create draft version", self.scope_editor_source)

    def test_progress_is_never_presented_as_compliance_or_certification(self) -> None:
        """Require explicit non-certification wording in the command card."""

        from unittest.mock import patch

        from securescope.ui.components import progress_card

        snapshot = calculate_program_progress({}, [], [])
        with patch.object(progress_card, "render_html") as render:
            progress_card.render_program_progress_card(
                snapshot, engagement_name="Test engagement", scope_name="Test scope"
            )
        markup = render.call_args.args[0]
        self.assertIn("Not a compliance or certification score", markup)
        self.assertIn("programme foundation", markup)

    def test_published_migrations_remain_byte_identical(self) -> None:
        """Verify the experience release does not rewrite database history."""

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
