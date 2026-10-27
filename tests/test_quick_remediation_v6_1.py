"""Offline tests for deterministic Quick Remediation preparation."""

from __future__ import annotations

import unittest
from datetime import date, datetime, timezone

from securescope.compliance.quick_remediation_service import (
    calculate_remediation_priority,
    group_remediation_candidates,
    proposal_from_candidates,
    severity_default_priority,
)
from securescope.compliance.remediation_recipe_service import RemediationRecipeRegistry


class QuickRemediationTests(unittest.TestCase):
    """Verify grouping, priority and safe recipe selection."""

    @staticmethod
    def finding(
        finding_id: int,
        asset: str,
        *,
        severity: str = "Low",
        action: str = "Apply the vendor security update.",
    ) -> dict[str, object]:
        """Return one canonical test finding."""

        return {
            "id": finding_id,
            "severity": severity,
            "vulnerability_identity": "CVE-2026-1234",
            "asset_identity": asset,
            "title": "Example security update",
            "component": "operating system security update",
            "operating_system": "Windows 11",
            "first_seen": "2026-07-01T00:00:00+00:00",
            "most_recent_evidence": {
                "remediation": action,
                "operating_system": "Windows 11",
            },
        }

    def test_low_does_not_default_to_critical(self) -> None:
        """Prevent the screenshot regression Low -> Critical."""

        self.assertEqual(severity_default_priority("Low"), "Low")
        result = calculate_remediation_priority(
            self.finding(1, "ip:192.0.2.1"),
            now=datetime(2026, 8, 3, tzinfo=timezone.utc),
        )
        self.assertEqual(result.label, "Low")

    def test_confirmed_kev_can_justify_critical(self) -> None:
        """Permit a documented threat-intelligence escalation."""

        finding = self.finding(1, "ip:192.0.2.1")
        finding["kev_known_exploited"] = True
        self.assertEqual(calculate_remediation_priority(finding).label, "Critical")

    def test_same_identity_and_action_group_across_assets(self) -> None:
        """Preserve two finding and asset links in one action group."""

        candidates = group_remediation_candidates(
            [
                self.finding(1, "ip:192.0.2.1"),
                self.finding(2, "ip:192.0.2.2"),
            ],
            today=date(2026, 8, 3),
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].finding_ids, (1, 2))
        self.assertEqual(len(candidates[0].assets), 2)

    def test_different_action_does_not_group(self) -> None:
        """Avoid merging findings that require different changes."""

        candidates = group_remediation_candidates(
            [
                self.finding(1, "ip:192.0.2.1"),
                self.finding(
                    2,
                    "ip:192.0.2.2",
                    action="Disable the affected feature.",
                ),
            ]
        )
        self.assertEqual(len(candidates), 2)

    def test_informational_findings_are_excluded(self) -> None:
        """Do not route informational observations to remediation by default."""

        rows = [self.finding(1, "ip:192.0.2.1", severity="Info")]
        self.assertEqual(group_remediation_candidates(rows), [])

    def test_registry_matches_reviewed_windows_recipe(self) -> None:
        """Match metadata, never scanner-provided executable text."""

        registry = RemediationRecipeRegistry.load()
        finding = self.finding(1, "ip:192.0.2.1")
        finding["title"] = "Microsoft Windows security update missing"
        finding["most_recent_evidence"]["command"] = "Remove-Item -Recurse C:\\"
        recipe = registry.match(finding)
        self.assertIsNotNone(recipe)
        self.assertEqual(recipe.recipe_id, "windows-security-updates")
        self.assertNotIn("Remove-Item", recipe.command_id)

    def test_compact_proposal_contains_verification(self) -> None:
        """Generate owner/due/validation defaults without an LLM."""

        candidate = group_remediation_candidates(
            [self.finding(1, "ip:192.0.2.1")],
            today=date(2026, 8, 3),
        )[0]
        proposal = proposal_from_candidates([candidate])
        self.assertEqual(proposal["finding_ids"], [1])
        self.assertIn("verification", proposal["validation_method"].lower())


if __name__ == "__main__":
    unittest.main()
