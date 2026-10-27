"""Offline regression and security tests for SecureScope v5.3.7."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from securescope.evidence.connector_runner import ConnectorPlanError, build_collection_plan
from securescope.evidence.models import WorkspaceRole, role_can
from securescope.evidence.normalization import EvidenceNormalizationError, normalize_report
from securescope.evidence.storage import EvidenceStorageError, read_artifact, store_artifact
from securescope.evidence.tool_catalog import (
    IMPORT_ONLY_TOOL_IDS,
    TOOL_CATALOG,
    validate_tool_catalog,
)
from securescope.grc.control_catalog import (
    ISO_ANNEX_A_CATALOG,
    ISO_CLAUSE_CATALOG,
    ISO_CONTROL_CATALOG,
    validate_control_catalog,
)
from securescope.persistence.migration_service import (
    COMPATIBLE_MIGRATION_CHECKSUMS,
    _checksums_are_compatible,
    discover_migrations,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class IsoEvidenceCatalogTests(unittest.TestCase):
    """Validate framework and source-catalog completeness."""

    def test_catalog_contains_all_annex_a_controls_and_clauses(self) -> None:
        self.assertIsNone(validate_control_catalog())
        self.assertEqual(len(ISO_ANNEX_A_CATALOG), 93)
        self.assertEqual(len(ISO_CLAUSE_CATALOG), 30)
        self.assertEqual(len(ISO_CONTROL_CATALOG), 123)
        self.assertEqual(
            set(ISO_CONTROL_CATALOG), set(ISO_ANNEX_A_CATALOG) | set(ISO_CLAUSE_CATALOG)
        )
        self.assertTrue(
            all(item["consultant_validation_required"] for item in ISO_CONTROL_CATALOG.values())
        )
        self.assertTrue(
            all(
                item["automation_level"] in {"Manual", "Hybrid"}
                for item in ISO_CONTROL_CATALOG.values()
            )
        )

    def test_tool_catalog_is_exact_and_offensive_sources_are_import_only(self) -> None:
        self.assertIsNone(validate_tool_catalog())
        self.assertEqual(len(TOOL_CATALOG), 31)
        self.assertEqual(
            IMPORT_ONLY_TOOL_IDS,
            {"metasploit", "hydra", "medusa", "ncrack", "beef", "atomic-red-team"},
        )
        self.assertFalse(any(TOOL_CATALOG[item].can_execute for item in IMPORT_ONLY_TOOL_IDS))
        self.assertIn("droopescan", TOOL_CATALOG)
        self.assertNotIn("wpscan", TOOL_CATALOG)


class EvidenceNormalizationTests(unittest.TestCase):
    """Verify bounded parsing, redaction and XML safety."""

    def test_json_observations_are_normalized_and_secrets_redacted(self) -> None:
        report = (
            b'{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1",'
            b'"Title":"Example","Severity":"HIGH","api_key":"do-not-store"}]}]}'
        )
        result = normalize_report("trivy", "report.json", report)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].observation_id, "CVE-2026-1")
        self.assertEqual(result.observations[0].title, "Example")
        self.assertEqual(result.observations[0].severity, "High")
        self.assertEqual(result.observations[0].attributes["api_key"], "[REDACTED]")

    def test_xml_dtd_and_entity_are_rejected_anywhere(self) -> None:
        malicious = (
            b" " * 9_000 + b'<!DOCTYPE x [<!ENTITY ext SYSTEM "file:///etc/passwd">]><x>&ext;</x>'
        )
        with self.assertRaises(EvidenceNormalizationError):
            normalize_report("openvas", "report.xml", malicious)

    def test_paths_and_oversized_reports_are_rejected(self) -> None:
        with self.assertRaises(EvidenceNormalizationError):
            normalize_report("trivy", "..\\secret.json", b"{}")
        with self.assertRaises(EvidenceNormalizationError):
            normalize_report("trivy", "report.json", b"{}" * 10, max_bytes=5)


class WorkspaceAndRoleTests(unittest.TestCase):
    """Verify read-only roles and artifact workspace boundaries."""

    def test_auditor_is_read_only(self) -> None:
        self.assertTrue(role_can(WorkspaceRole.AUDITOR, "read"))
        self.assertTrue(role_can(WorkspaceRole.AUDITOR, "export"))
        self.assertFalse(role_can(WorkspaceRole.AUDITOR, "review"))
        self.assertFalse(role_can(WorkspaceRole.AUDITOR, "submit"))
        self.assertTrue(role_can(WorkspaceRole.CONSULTANT, "review"))

    def test_artifact_cannot_be_read_through_another_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(
                os.environ, {"SECURESCOPE_EVIDENCE_STORAGE_ROOT": directory}, clear=False
            ):
                artifact = store_artifact(11, "report.json", b'{"safe": true}')
                self.assertEqual(read_artifact(11, artifact.storage_reference), b'{"safe": true}')
                with self.assertRaises(EvidenceStorageError):
                    read_artifact(12, artifact.storage_reference)


class ConnectorBoundaryTests(unittest.TestCase):
    """Verify the execution policy is enforced below the interface."""

    def test_import_only_tool_has_no_collection_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConnectorPlanError):
                build_collection_plan("metasploit", "example.com", Path(directory))

    def test_zap_rejects_credentials_in_target_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "securescope.evidence.connector_runner.shutil.which", return_value="/opt/zap/zap.sh"
            ):
                with self.assertRaises(ConnectorPlanError):
                    build_collection_plan(
                        "zap", "https://user:password@example.com", Path(directory)
                    )

    def test_subprocess_contract_uses_argument_list_and_no_free_arguments(self) -> None:
        source = (PROJECT_ROOT / "src/securescope/evidence/connector_runner.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("shell=False", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("extra_args", source)


class ArchitectureRegressionTests(unittest.TestCase):
    """Protect client scoping and the agreed UI placement."""

    def test_new_migration_is_additive_and_client_scoped(self) -> None:
        migration = (
            PROJECT_ROOT / "database/migrations/004_v5_3_7_iso_evidence_platform.sql"
        ).read_text(encoding="utf-8")
        self.assertNotIn("DROP TABLE", migration.upper())
        self.assertNotIn("DROP COLUMN", migration.upper())
        self.assertGreaterEqual(migration.count("client_id BIGINT NOT NULL"), 8)
        self.assertIn("FOREIGN KEY (client_id, evidence_id)", migration)
        self.assertIn("FOREIGN KEY (client_id, artifact_id)", migration)

    def test_migration_three_variants_reconcile_through_migration_four(self) -> None:
        migrations = discover_migrations(PROJECT_ROOT / "database/migrations")
        versions = [migration.version for migration in migrations]
        self.assertTrue(versions)
        self.assertEqual(len(versions), len(set(versions)))
        self.assertEqual(versions, list(range(1, max(versions) + 1)))
        self.assertEqual(migrations[5].name, "organization_knowledge_compat")
        bridge = migrations[2]
        self.assertEqual(bridge.name, "legacy_iso_evidence_bridge")
        for checksum in COMPATIBLE_MIGRATION_CHECKSUMS[3]:
            self.assertTrue(_checksums_are_compatible(bridge, checksum))
        self.assertFalse(_checksums_are_compatible(bridge, "0" * 64))

    def test_evidence_hub_is_available_as_a_direct_workspace_route(self) -> None:
        """Keep the evidence workspace directly reachable after v5.3.8.2."""

        app_source = (PROJECT_ROOT / "src/securescope/app.py").read_text(encoding="utf-8")
        navigation_source = (PROJECT_ROOT / "src/securescope/ui/navigation.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('PageSpec("ISO Evidence Hub", "Evidence Hub"', navigation_source)
        self.assertIn('"ISO Evidence Hub": lambda: render_iso_evidence_hub(', app_source)
        self.assertIn("hidden=True", navigation_source)


if __name__ == "__main__":
    unittest.main()
