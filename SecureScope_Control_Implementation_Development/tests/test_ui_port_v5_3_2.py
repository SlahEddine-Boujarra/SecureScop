"""Static UI and integration contracts for the targeted v5.3.2 port."""

from __future__ import annotations

import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


class UiPortContractTests(unittest.TestCase):
    """Verify that only the two requested application routes were added."""

    def test_sidebar_contains_remediation_and_gap_assessment(self) -> None:
        """Expose both new modules in the preserved v5.3.1 sidebar."""

        app_source = (SOURCE_ROOT / "app.py").read_text(encoding="utf-8")
        navigation_source = (SOURCE_ROOT / "ui" / "navigation.py").read_text(encoding="utf-8")
        self.assertIn('PageSpec("Remediation", "Remediation"', navigation_source)
        self.assertIn('PageSpec("Gap Assessment", "Control Assurance"', navigation_source)
        renderers = app_source.split("def _page_renderers()", 1)[1]
        self.assertIn('"Remediation": lambda: render_remediation_page(', renderers)
        self.assertIn('"Gap Assessment": lambda: render_gap_assessment_page(', renderers)

    def test_scanner_services_are_not_imported_by_remediation_domain(self) -> None:
        """Keep scanner execution outside deterministic plan preparation."""

        source = (SOURCE_ROOT / "compliance" / "quick_remediation_service.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("openvas_worker_service", source)
        self.assertNotIn("nuclei_worker_service", source)
        self.assertNotIn("subprocess", source)

    def test_all_new_sql_tables_are_workspace_scoped(self) -> None:
        """Require client identifiers throughout both additive migrations."""

        for migration_name in (
            "001_v6_exposure_grc.sql",
            "002_v6_1_quick_remediation.sql",
        ):
            migration = (PROJECT_ROOT / "database" / "migrations" / migration_name).read_text(
                encoding="utf-8"
            )
            self.assertIn("client_id BIGINT NOT NULL", migration)
            self.assertIn("REFERENCES securescope_clients(id)", migration)
            self.assertNotIn("DROP TABLE", migration.upper())
            self.assertNotIn("TRUNCATE", migration.upper())


if __name__ == "__main__":
    unittest.main()
