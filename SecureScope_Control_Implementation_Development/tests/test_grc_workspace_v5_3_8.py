"""Regression, domain and security contracts for SecureScope v5.3.8."""

from __future__ import annotations

import hashlib
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from securescope.grc.engagement_models import (
    ContextIssueDraft,
    EngagementDraft,
    GrcValidationError,
    RaciAssignmentDraft,
    ScopeDraft,
)
from securescope.grc.engagement_service import GrcWorkspaceService
from securescope.persistence.migration_service import discover_migrations

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GrcDomainValidationTests(unittest.TestCase):
    """Verify deterministic validation before PostgreSQL mutations."""

    def test_engagement_reference_and_dates_are_normalized(self) -> None:
        """Normalize a reference and preserve a valid engagement schedule."""

        draft = EngagementDraft(
            reference=" iso 2027 / initial ",
            name="Initial certification",
            engagement_type="ISO 27001 implementation",
            objective="Reach Stage 2 readiness.",
            status="Planned",
            cycle_year=2027,
            planned_start_date=date(2027, 1, 10),
            planned_end_date=date(2027, 8, 10),
        ).validate()
        self.assertEqual(draft.reference, "ISO-2027-/-INITIAL")
        self.assertEqual(draft.cycle_year, 2027)

    def test_engagement_rejects_reversed_schedule(self) -> None:
        """Reject a planned end date that precedes the start date."""

        with self.assertRaises(GrcValidationError):
            EngagementDraft(
                reference="ISO-2027",
                name="Initial certification",
                engagement_type="ISO 27001 implementation",
                objective="Reach Stage 2 readiness.",
                planned_start_date=date(2027, 8, 10),
                planned_end_date=date(2027, 1, 10),
            ).validate()

    def test_scope_lists_are_deduplicated_without_changing_order(self) -> None:
        """Keep a stable scope version while removing duplicate list values."""

        scope = ScopeDraft(
            scope_code="corp-it",
            name="Corporate IT",
            scope_statement="Corporate IT services operated from Tunis.",
            locations=("Tunis", "tunis", "Sfax"),
        ).validate()
        self.assertEqual(scope.scope_code, "CORP-IT")
        self.assertEqual(scope.locations, ("Tunis", "Sfax"))

    def test_context_issue_rejects_unknown_relevance(self) -> None:
        """Prevent free-form relevance values from bypassing reporting logic."""

        with self.assertRaises(GrcValidationError):
            ContextIssueDraft(
                issue_type="Internal",
                category="Governance",
                title="Example",
                description="Example issue.",
                effect_on_isms="Requires review.",
                relevance="Probably",
                owner="ISMS manager",
            ).validate()

    def test_raci_assignment_requires_real_positive_user_id(self) -> None:
        """Reject text-only or invalid identities before role persistence."""

        with self.assertRaises(GrcValidationError):
            RaciAssignmentDraft(
                user_id=0,
                role_name="ISMS Manager",
                responsibility="Operate the ISMS.",
                raci_type="Accountable",
                authority="Approve operational decisions.",
                effective_from=date.today(),
            ).validate()


class MigrationContractTests(unittest.TestCase):
    """Protect immutable history and the additive migration-005 contract."""

    def test_published_migrations_one_through_four_are_byte_stable(self) -> None:
        """Fail when any migration published before v5.3.8 is edited."""

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
        }
        migration_root = PROJECT_ROOT / "database" / "migrations"
        for filename, expected_hash in expected.items():
            actual = hashlib.sha256((migration_root / filename).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_hash, filename)

    def test_migration_discovery_selects_known_bridge_and_new_migration(self) -> None:
        """Use the explicit migration-003 bridge and then apply 004 and 005."""

        migrations = discover_migrations(PROJECT_ROOT / "database" / "migrations")
        versions = [item.version for item in migrations]
        self.assertTrue(versions)
        self.assertEqual(len(versions), len(set(versions)))
        self.assertEqual(versions, list(range(1, max(versions) + 1)))
        self.assertEqual(migrations[2].name, "legacy_iso_evidence_bridge")
        self.assertEqual(migrations[4].name, "grc_engagement_context_scope")
        self.assertEqual(migrations[5].name, "organization_knowledge_compat")

    def test_migration_five_is_additive_and_engagement_scoped(self) -> None:
        """Require tenant keys, immutable approvals and safe legacy backfill."""

        source = (
            PROJECT_ROOT / "database" / "migrations" / "005_grc_engagement_context_scope.sql"
        ).read_text(encoding="utf-8")
        upper = source.upper()
        self.assertNotIn("DROP TABLE", upper)
        self.assertNotIn("DROP COLUMN", upper)
        self.assertGreaterEqual(source.count("client_id BIGINT NOT NULL"), 14)
        self.assertGreaterEqual(source.count("engagement_id BIGINT NOT NULL"), 11)
        self.assertIn("Approved SecureScope scope versions are immutable", source)
        self.assertIn("securescope_grc_approvals", source)
        self.assertIn("securescope_grc_audit_events", source)
        self.assertIn("Existing ISO 27001 Programme", source)
        self.assertIn("ON CONFLICT (client_id, scope_id, version_number)", source)


class WorkspaceSelectionTests(unittest.TestCase):
    """Verify the client → engagement → approved-scope selection behavior."""

    @patch("securescope.grc.engagement_service.repository.workspace_overview")
    @patch("securescope.grc.engagement_service.repository.list_scopes")
    @patch("securescope.grc.engagement_service.repository.list_engagements")
    @patch("securescope.grc.engagement_service.repository.ensure_workspace_foundation")
    def test_invalid_saved_selection_returns_to_default_and_approved_scope(
        self,
        foundation_mock,
        engagements_mock,
        scopes_mock,
        overview_mock,
    ) -> None:
        """Recover stale session IDs without crossing the active workspace."""

        foundation_mock.return_value = {
            "engagement_id": 10,
            "scope_id": 20,
        }
        engagements_mock.return_value = [
            {"id": 10, "name": "Default"},
            {"id": 11, "name": "Other"},
        ]
        scopes_mock.return_value = [
            {"id": 20, "current_approved_version_id": None},
            {"id": 21, "current_approved_version_id": 99},
        ]
        overview_mock.return_value = {"engagement": {}, "scope": {}}

        context = GrcWorkspaceService().open_workspace(
            "ACME Tunisia",
            engagement_id=999,
            scope_id=998,
        )

        self.assertEqual(context["selected_engagement_id"], 10)
        self.assertEqual(context["selected_scope_id"], 21)
        overview_mock.assert_called_once_with("ACME Tunisia", 10, 21)


class UiAndApiContractTests(unittest.TestCase):
    """Protect agreed placement, human approvals and scanner separation."""

    def test_programme_setup_is_not_nested_in_gap_assessment(self) -> None:
        """Route GRC setup directly and keep control assessment focused."""

        source = (PROJECT_ROOT / "src/securescope/ui/exposure_management_ui.py").read_text(
            encoding="utf-8"
        )
        app_source = (PROJECT_ROOT / "src/securescope/app.py").read_text(encoding="utf-8")
        navigation_source = (PROJECT_ROOT / "src/securescope/ui/navigation.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(":material/workspaces: GRC Workspace", source)
        self.assertNotIn("render_grc_workspace(client_name)", source)
        self.assertIn('PageSpec("Programme Setup", "Programme Foundation"', navigation_source)
        self.assertIn('"Programme Setup": lambda: render_grc_workspace(', app_source)
        self.assertNotIn(":material/devices: A.8.1 endpoint coverage", source)

    def test_client_dialog_routes_to_workspace_overview(self) -> None:
        """Make Client Workspace selection open the default GRC overview."""

        source = (PROJECT_ROOT / "src/securescope/app.py").read_text(encoding="utf-8")
        start = source.index("def _switch_client_from_dialog")
        end = source.index("@st.dialog", start)
        function_source = source[start:end]
        self.assertIn('navigate_to("ISO Command Center")', function_source)

    def test_repository_has_no_scanner_dependency(self) -> None:
        """Keep GRC transactions independent from scanner worker execution."""

        source = (
            PROJECT_ROOT / "src/securescope/persistence/grc_workspace_repository.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("securescope.scanners", source)
        self.assertNotIn("openvas", source.lower())
        self.assertNotIn("nuclei", source.lower())
        self.assertIn("WHERE client_id = %s AND id = %s", source)

    def test_grc_audit_hash_chain_serializes_first_write(self) -> None:
        """Prevent concurrent first events from branching a client's hash chain."""

        source = (
            PROJECT_ROOT / "src/securescope/persistence/grc_workspace_repository.py"
        ).read_text(encoding="utf-8")
        lock_position = source.index("pg_advisory_xact_lock")
        event_position = source.index("SELECT event_hash", lock_position)
        self.assertLess(lock_position, event_position)

    def test_api_exposes_scope_approval_and_context_routes(self) -> None:
        """Expose the foundation through authenticated FastAPI routes."""

        source = (PROJECT_ROOT / "src/securescope/api/app.py").read_text(encoding="utf-8")
        self.assertIn('"/v1/grc/workspace"', source)
        self.assertIn('"/v1/grc/engagements"', source)
        self.assertIn('"{version_id}/approve"', source)
        self.assertIn("approver_email=context.email", source)
        self.assertIn('"/v1/grc/engagements/{engagement_id}/context-issues"', source)


if __name__ == "__main__":
    unittest.main()
