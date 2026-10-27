"""Regression tests for evidence-source coverage on the Command Center."""

from securescope.ui.components.primitives import status_tone
from securescope.ui.pages import command_center
from securescope.ui.securescope_sidebar import NAVIGATION_GROUPS


def test_wazuh_coverage_counts_only_verified_monitoring(monkeypatch):
    """Current factual Wazuh states must feed the dashboard coverage metric."""
    monkeypatch.setattr(
        command_center,
        "load_latest_wazuh_status",
        lambda _client: [
            {"asset_ip": "10.0.0.10", "monitoring_status": "Monitoring verified"},
            {
                "asset_ip": "10.0.0.11",
                "monitoring_status": "Agent active — telemetry unverified",
            },
            {"asset_ip": "10.0.0.12", "monitoring_status": "Monitoring stale"},
        ],
    )
    assets = [
        {"ip": "10.0.0.10", "asset_tag": "srv-01"},
        {"ip": "10.0.0.11", "asset_tag": "srv-02"},
        {"ip": "10.0.0.12", "asset_tag": "srv-03"},
    ]

    rows = {
        label: (value, detail)
        for label, value, detail in command_center._technical_coverage_rows("Client", assets, [])
    }

    assert rows["Wazuh"] == ("33%", "1/3 assets with verified monitoring")


def test_evidence_hub_is_a_primary_security_destination():
    """The evidence workflow must not be hidden behind contextual navigation."""
    visible_routes = {
        route
        for _group, items in NAVIGATION_GROUPS
        for route, _page, _label, _icon in items
    }

    assert "ISO Evidence Hub" in visible_routes


def test_current_source_states_have_meaningful_semantic_tones():
    """New factual states should not fall back to an undifferentiated neutral pill."""
    assert status_tone("Monitoring verified") == "success"
    assert status_tone("Monitoring stale") == "warning"
    assert status_tone("Agent disconnected") == "danger"
    assert status_tone("Monitoring not verified") == "neutral"
