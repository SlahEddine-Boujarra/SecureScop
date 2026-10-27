"""Tests for deterministic Nmap-to-Nuclei target derivation."""

from securescope.scanners.nuclei.nuclei_worker_service import build_asset_targets


def test_asset_targets_include_network_and_web_endpoints() -> None:
    asset = {
        "ip": "192.0.2.10",
        "hostname": "web.example.test",
        "open_ports": "22/tcp ssh; 80/tcp http; 8443/tcp https-alt",
    }
    assert build_asset_targets(asset) == [
        "192.0.2.10",
        "web.example.test",
        "http://192.0.2.10",
        "http://web.example.test",
        "https://192.0.2.10:8443",
        "https://web.example.test:8443",
    ]


def test_asset_without_ip_has_no_targets() -> None:
    assert build_asset_targets({"hostname": "host"}) == []
