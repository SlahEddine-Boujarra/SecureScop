import pandas as pd

import securescope.reporting.dual_engine_report as der
from securescope.reporting.openvas_pdf_report import generate_asset_report_pdf
from securescope.ui.dual_engine_ui import _jobs_frame


def _finding(name: str, severity: str = "High") -> dict:
    return {
        "Finding": name,
        "Severity": severity,
        "CVSS": 8.0 if severity == "High" else 5.0,
        "Host": "192.168.100.10",
        "Port": "443/tcp",
        "CVE": "CVE-2026-12345",
        "Description": "Example finding.",
        "Solution": "Apply the recommended security update.",
        "ISO Controls": "A.8.8 Management of technical vulnerabilities",
        "ISO Mapping": [{"id": "A.8.8", "name": "Management of technical vulnerabilities"}],
    }


def test_build_consolidated_record_keeps_both_engines():
    records = {
        "OpenVAS": {
            "scanner_engine": "OpenVAS",
            "asset_ip": "192.168.100.10",
            "asset": {"ip": "192.168.100.10", "asset_tag": "AST-1"},
            "report_id": "openvas-r1",
            "scanned_at": "2026-07-28T17:00:00+00:00",
            "findings": [_finding("OpenVAS finding")],
        },
        "Nuclei": {
            "scanner_engine": "Nuclei",
            "asset_ip": "192.168.100.10",
            "asset": {"ip": "192.168.100.10", "asset_tag": "AST-1"},
            "report_id": "nuclei-r1",
            "scanned_at": "2026-07-28T18:00:00+00:00",
            "findings": [_finding("Nuclei finding", "Medium")],
        },
    }

    record = der.build_consolidated_record("Default Client", "192.168.100.10", records)

    assert record["scanner_engine"] == "Dual engine"
    assert len(record["findings"]) == 2
    assert {item["Scanner Engine"] for item in record["findings"]} == {
        "OpenVAS",
        "Nuclei",
    }
    assert [item["engine"] for item in record["engine_records"]] == [
        "OpenVAS",
        "Nuclei",
    ]


def test_dual_engine_pdf_is_valid():
    record = der.build_consolidated_record(
        "Default Client",
        "192.168.100.10",
        {
            "OpenVAS": {
                "scanner_engine": "OpenVAS",
                "asset_ip": "192.168.100.10",
                "asset": {"ip": "192.168.100.10", "asset_tag": "AST-1"},
                "report_id": "openvas-r1",
                "scanned_at": "2026-07-28T17:00:00+00:00",
                "findings": [_finding("OpenVAS finding")],
            },
            "Nuclei": {
                "scanner_engine": "Nuclei",
                "asset_ip": "192.168.100.10",
                "asset": {"ip": "192.168.100.10", "asset_tag": "AST-1"},
                "report_id": "nuclei-r1",
                "scanned_at": "2026-07-28T18:00:00+00:00",
                "findings": [_finding("Nuclei finding", "Medium")],
            },
        },
    )
    pdf = generate_asset_report_pdf(record, client_name="Default Client")
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 4000


def test_nuclei_jobs_frame_uses_nullable_integer_columns():
    frame = _jobs_frame(
        [
            {
                "id": 1,
                "attempt_number": 1,
                "is_current_attempt": True,
                "asset_tag": "AST-1",
                "asset_ip": "192.168.100.10",
                "ui_status": "Queued",
                "provider_status": "Not started",
                "stats_payload": {},
                "runner_pid": None,
            },
            {
                "id": 2,
                "attempt_number": 1,
                "is_current_attempt": True,
                "asset_tag": "AST-2",
                "asset_ip": "192.168.100.11",
                "ui_status": "Running",
                "provider_status": "Executing",
                "stats_payload": {"requests": 123},
                "runner_pid": 4567,
            },
        ]
    )

    assert str(frame["Runner PID"].dtype) == "Int64"
    assert str(frame["Requests"].dtype) == "Int64"
    assert pd.isna(frame.loc[0, "Runner PID"])
    assert frame.loc[1, "Runner PID"] == 4567
