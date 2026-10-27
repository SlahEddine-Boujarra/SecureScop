from __future__ import annotations

from securescope.compliance.iso_control_assessment_service import (
    add_maturity,
    assessment_summary,
    maturity_level,
)
from securescope.reporting.iso_report_service import build_iso_assurance_pdf, build_iso_evidence_zip


def test_maturity_and_summary() -> None:
    assert maturity_level(0) == (0, "Non-existent")
    assert maturity_level(92) == (5, "Optimized")
    rows = add_maturity(
        [
            {
                "control_id": "A.8.1",
                "automated_status": "Gap detected",
                "score": 20,
            },
            {
                "control_id": "A.8.2",
                "automated_status": "Likely implemented",
                "score": 90,
            },
        ]
    )
    assert rows[0]["Control"] == "A.8.1"
    assert rows[0]["Automatic status"] == "Gap detected"
    assert rows[0]["Score"] == 20.0
    summary = assessment_summary(rows)
    assert summary["readiness_score"] == 55.0
    assert summary["gap_controls"] == 1


def test_iso_reports_are_generated() -> None:
    assessments = [
        {
            "Control": "A.8.17",
            "Control name": "Clock synchronization",
            "Automatic status": "Likely implemented",
            "final_status": "Pending validation — Likely implemented",
            "Score": 88,
            "Maturity": "4 — Measured",
            "Evidence": ["All endpoints synchronized"],
            "Gaps": ["Validate source approval"],
            "automated_status": "Likely implemented",
            "score": 88,
        }
    ]
    pdf = build_iso_assurance_pdf(
        client_name="Example",
        assessments=assessments,
        actions=[],
        clock_summary={
            "status": "Synchronized",
            "assets_with_endpoint_evidence": 1,
            "assets_total": 1,
            "synchronized_assets": 1,
            "gap_assets": 0,
            "sources": ["time.corp"],
        },
    )
    assert pdf.startswith(b"%PDF")

    archive = build_iso_evidence_zip(
        client_name="Example",
        assessments=assessments,
        actions=[],
        clock_rows=[],
        assets=[],
        scan_history=[],
    )
    assert archive.startswith(b"PK")
