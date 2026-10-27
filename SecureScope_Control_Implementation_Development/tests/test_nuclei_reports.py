"""Tests for Nuclei JSONL normalization."""

from __future__ import annotations

import json

from securescope.reporting.nuclei_report import parse_nuclei_jsonl


def test_parse_nuclei_jsonl_normalizes_finding() -> None:
    payload = {
        "template-id": "CVE-2024-12345",
        "type": "http",
        "host": "https://192.0.2.10",
        "ip": "192.0.2.10",
        "matched-at": "https://192.0.2.10/login",
        "matcher-name": "version",
        "info": {
            "name": "Example vulnerable component",
            "severity": "high",
            "description": "An example CVE match.",
            "remediation": "Upgrade the affected component.",
            "tags": ["cve", "exposure"],
            "classification": {
                "cve-id": ["CVE-2024-12345"],
                "cvss-score": 8.1,
            },
        },
    }
    source = (json.dumps(payload) + "\n").encode()
    findings, metadata = parse_nuclei_jsonl(
        source,
        report_id="nuclei-report-1",
        asset_ip="192.0.2.10",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["Scanner"] == "ProjectDiscovery Nuclei"
    assert finding["Severity"] == "High"
    assert finding["CVSS"] == 8.1
    assert finding["CVE"] == "CVE-2024-12345"
    assert finding["Template ID"] == "CVE-2024-12345"
    assert metadata["high_count"] == 1
