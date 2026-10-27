"""Offline unit tests for the v5.3.2 Gap Assessment port."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from securescope.core.gap_assessment_domain import (
    CriterionResult,
    InvalidAssessmentStatusError,
    a81_wazuh_endpoint_coverage,
    assurance_score,
    calculate_coverage,
    evaluate_checklist,
    evaluate_composite_control,
    validate_assessment_status,
)


class GapAssessmentPortTests(unittest.TestCase):
    """Verify transparent gap calculations and analyst validation rules."""

    def test_coverage_gap_uses_current_and_approved_target(self) -> None:
        """Calculate 27/100 against an 80 percent approved target."""

        result = calculate_coverage(100, 27, 80)
        self.assertEqual(result.current_coverage, 27.0)
        self.assertEqual(result.coverage_gap, 53.0)
        self.assertEqual(result.additional_required, 53)
        self.assertEqual(result.status, "Gap identified")

    def test_missing_scope_is_not_rendered_as_zero(self) -> None:
        """Keep unavailable coverage explicitly unassessed."""

        result = calculate_coverage(0, 0, 80)
        self.assertIsNone(result.current_coverage)
        self.assertIsNone(result.coverage_gap)
        self.assertEqual(result.status, "Not assessed")

    def test_a81_coverage_counts_only_endpoint_devices(self) -> None:
        """Exclude servers and network devices from A.8.1 endpoint scope."""

        assets = [
            {"asset_tag": "PC-001", "ip": "192.0.2.1", "device_type": "Laptop"},
            {"asset_tag": "PC-002", "ip": "192.0.2.2", "device_type": "Workstation"},
            {"asset_tag": "SRV-001", "ip": "192.0.2.3", "device_type": "Server"},
        ]
        wazuh_rows = [
            {
                "asset_tag": "PC-001",
                "schema_version": 2,
                "asset_id": 1,
                "binding_id": 1,
                "identity_verified": True,
                "connector_id": "source",
                "manager_name": "manager",
                "wazuh_agent_id": "001",
                "api_verified": True,
                "source_health": "healthy",
                "collected_at": datetime.now(timezone.utc),
                "wazuh_last_keep_alive": datetime.now(timezone.utc),
                "heartbeat_max_age_seconds": 300,
                "telemetry_max_age_seconds": 3600,
                "telemetry": dict(
                    authenticated=True,
                    kind="security_event",
                    agent_id="001",
                    manager_name="manager",
                    source_event_id="i:e",
                    rule_id="1",
                    observed_at=datetime.now(timezone.utc),
                ),
                "wazuh_status": "active",
            }
        ]
        result = a81_wazuh_endpoint_coverage(assets, wazuh_rows, 80)
        self.assertEqual(result.total_in_scope, 2)
        self.assertEqual(result.covered_in_scope, 1)
        self.assertEqual(result.current_coverage, 50.0)

    def test_automation_cannot_claim_effective_implementation(self) -> None:
        """Reserve the final effectiveness decision for an analyst."""

        with self.assertRaises(InvalidAssessmentStatusError):
            validate_assessment_status(
                "Implemented and effective",
                automated=True,
                effectiveness_evidence=True,
                authorized_validation=True,
            )

    def test_composite_model_does_not_hide_unassessed_objective(self) -> None:
        """Keep an incomplete assurance objective visible."""

        result = evaluate_composite_control(["Target achieved", "Manual assessment required"])
        self.assertEqual(result.status, "Manual assessment required")
        self.assertFalse(result.target_achieved)

    def test_checklist_keeps_failed_required_criterion_visible(self) -> None:
        """Return a gap when a required criterion fails."""

        criteria = [
            CriterionResult("policy", "Policy exists", True, "Pass", validated=True),
            CriterionResult("review", "Review performed", True, "Fail"),
        ]
        self.assertEqual(evaluate_checklist(criteria), "Gap identified")

    def test_assurance_score_reports_missing_dimensions(self) -> None:
        """Do not treat unavailable assurance dimensions as zero."""

        result = assurance_score(
            {
                "Design adequacy": 80,
                "Implementation": 60,
                "Scope coverage": None,
            }
        )
        self.assertEqual(result["assurance_score"], 70.0)
        self.assertIn("Scope coverage", result["missing_dimensions"])
        self.assertFalse(result["is_complete"])


if __name__ == "__main__":
    unittest.main()
