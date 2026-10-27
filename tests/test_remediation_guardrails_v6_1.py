"""Static offline tests for remediation execution safety boundaries."""

from __future__ import annotations

import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


class RemediationGuardrailTests(unittest.TestCase):
    """Verify default-off, allow-listed and verification-only behavior."""

    def test_execution_is_default_off(self) -> None:
        """Require an explicit configuration kill-switch change."""

        env_text = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("WAZUH_REMEDIATION_EXECUTION_ENABLED=false", env_text)
        self.assertIn("REMEDIATION_WORKER_AUTOSTART=false", env_text)
        self.assertIn("WAZUH_REMEDIATION_COMMAND_ALLOWLIST=\n", env_text)

    def test_adapter_dispatches_only_recipe_command(self) -> None:
        """Reject arbitrary user/scanner command construction by design."""

        source = (SOURCE_ROOT / "integrations" / "wazuh_remediation_adapter.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("command_id=request.recipe.command_id", source)
        self.assertIn("configured_command_allowlist()", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess", source)

    def test_worker_never_marks_finding_verified(self) -> None:
        """Stop after queuing fresh scanner evidence."""

        source = (SOURCE_ROOT / "compliance" / "remediation_worker_service.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"Pending verification"', source)
        forbidden_transition = (
            "update_execution_status(\n            client_name,\n"
            '            execution_id,\n            "Verified"'
        )
        self.assertNotIn(forbidden_transition, source)

    def test_workspace_scope_is_present_in_mutations(self) -> None:
        """Require client ID in execution update and plan/finding validation."""

        source = (SOURCE_ROOT / "persistence" / "remediation_execution_repository.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("WHERE client_id = %s AND id = %s", source)
        self.assertIn("link.client_id = %s", source)

    def test_endpoint_recipes_require_wazuh_add_message(self) -> None:
        """Ensure both reviewed scripts reject non-add Active Response input."""

        linux = (
            PROJECT_ROOT
            / "integrations"
            / "wazuh"
            / "remediation"
            / "linux"
            / "securescope_security_updates.sh"
        ).read_text(encoding="utf-8")
        windows = (
            PROJECT_ROOT
            / "integrations"
            / "wazuh"
            / "remediation"
            / "windows"
            / "securescope_security_updates.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(r"\"command\"", linux)
        self.assertIn(r"\"add\"", linux)
        self.assertIn("[Console]::In.ReadLine()", windows)
        self.assertIn('$activeResponse.command -ne "add"', windows)

    def test_execution_migration_is_additive(self) -> None:
        """Ensure migration adds execution/event tables without destructive SQL."""

        migration = (
            PROJECT_ROOT / "database" / "migrations" / "002_v6_1_quick_remediation.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS", migration)
        self.assertIn("securescope_remediation_execution_events", migration)
        self.assertNotIn("DROP TABLE", migration.upper())
        self.assertNotIn("TRUNCATE", migration.upper())


if __name__ == "__main__":
    unittest.main()
