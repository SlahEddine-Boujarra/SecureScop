"""Import smoke tests for OpenVAS/Nuclei non-UI services."""

from __future__ import annotations

import importlib


def test_dual_engine_service_modules_import() -> None:
    """Import every Nuclei integration layer."""

    modules = [
        "securescope.core.scanner_engine_service",
        "securescope.scanners.nuclei.nuclei_client",
        "securescope.persistence.nuclei_persistence",
        "securescope.reporting.nuclei_report",
        "securescope.scanners.nuclei.nuclei_worker_probe",
        "securescope.scanners.nuclei.nuclei_worker_service",
        "securescope.ui.dual_engine_ui",
    ]
    for module_name in modules:
        assert importlib.import_module(module_name) is not None


def test_ciso_provider_neutral_alias_is_a_class_method(monkeypatch) -> None:
    """Keep provider-neutral finding synchronization available."""

    from securescope.integrations.ciso_assistant_service import CisoAssistantClient

    client = object.__new__(CisoAssistantClient)
    captured = {}

    def fake_sync(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(client, "sync_openvas_findings", fake_sync)
    result = client.sync_scanner_findings(report_id="report-1")
    assert result == {"ok": True}
    assert captured == {"report_id": "report-1"}
