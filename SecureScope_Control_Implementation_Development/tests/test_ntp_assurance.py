from __future__ import annotations

from datetime import datetime, timezone

from securescope.compliance.iso_control_assessment_service import evaluate_a8_controls
from securescope.integrations.ntp_audit_service import (
    apply_clock_status,
    fleet_clock_summary,
    match_clock_evidence_to_assets,
    parse_ntp_evidence_text,
)


def test_parse_wazuh_ntp_event_and_manager_delta() -> None:
    epoch_ms = int(datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc).timestamp() * 1000)
    event = (
        'prefix SECURESCOPE_NTP: {"hostname":"srv01","ip":"192.0.2.5",'
        '"synchronized":true,"source":"time.corp",'
        '"offset_ms":12.5,"stratum":3,"service":"chrony",'
        f'"epoch_ms":{epoch_ms}}}'
    )
    parsed = parse_ntp_evidence_text(
        event,
        fallback_agent_id="007",
        fallback_timestamp="2026-07-27T12:00:01Z",
    )
    assert parsed is not None
    assert parsed["asset_ip"] == "192.0.2.5"
    assert parsed["clock_synchronized"] is True
    assert parsed["clock_offset_ms"] == 12.5
    assert parsed["manager_agent_delta_ms"] == 1000
    assert (
        apply_clock_status(
            parsed,
            tolerance_ms=1000,
            max_age_minutes=0,
        )
        == "Synchronized"
    )


def test_match_clock_evidence_keeps_missing_assets_visible() -> None:
    assets = [
        {"ip": "192.0.2.5", "hostname": "srv01"},
        {"ip": "192.0.2.6", "hostname": "srv02"},
    ]
    evidence = [
        {
            "asset_ip": "192.0.2.5",
            "clock_synchronized": True,
            "clock_offset_ms": 5,
            "clock_source": "time.corp",
            "clock_evidence_source": "Wazuh endpoint command",
        }
    ]
    merged = match_clock_evidence_to_assets(assets, evidence)
    assert merged[0]["clock_sync_status"] == "Synchronized"
    assert merged[1]["clock_sync_status"] == "No evidence"

    summary = fleet_clock_summary(merged)
    assert summary["assets_total"] == 2
    assert summary["assets_with_endpoint_evidence"] == 1
    assert summary["status"] == "Partial evidence"


def test_a817_requires_full_endpoint_evidence() -> None:
    assets = [
        {
            "ip": "192.0.2.5",
            "clock_sync_status": "Synchronized",
            "clock_source": "time.corp",
            "clock_evidence_source": "Wazuh endpoint command",
        },
        {
            "ip": "192.0.2.6",
            "clock_sync_status": "Synchronized",
            "clock_source": "time.corp",
            "clock_evidence_source": "Wazuh endpoint command",
        },
    ]
    assessments = evaluate_a8_controls(assets, [], [])
    clock = next(item for item in assessments if item["control_id"] == "A.8.17")
    assert clock["automated_status"] == "Likely implemented"
    assert clock["confidence"] == "High"

    assets[1]["clock_sync_status"] = "No evidence"
    assets[1]["clock_evidence_source"] = ""
    assessments = evaluate_a8_controls(assets, [], [])
    clock = next(item for item in assessments if item["control_id"] == "A.8.17")
    assert clock["automated_status"] == "Partially implemented"


def test_manager_clock_delta_can_detect_a_gap() -> None:
    evidence = {
        "clock_synchronized": True,
        "clock_offset_ms": None,
        "manager_agent_delta_ms": 7000,
    }
    assert (
        apply_clock_status(
            evidence,
            manager_delta_tolerance_ms=5000,
            max_age_minutes=0,
        )
        == "Out of tolerance"
    )


def test_old_wazuh_evidence_is_stale() -> None:
    evidence = {
        "clock_synchronized": True,
        "clock_offset_ms": 1,
        "wazuh_received_epoch_ms": 1_700_000_000_000,
    }
    assert (
        apply_clock_status(
            evidence,
            max_age_minutes=5,
            now_epoch_ms=1_700_000_000_000 + 6 * 60_000,
        )
        == "Stale evidence"
    )


def test_clock_persistence_rejects_far_future_timestamp() -> None:
    from securescope.persistence.clock_evidence_persistence import _safe_timestamp

    assert _safe_timestamp("9999-12-31T23:59:59Z") is None
    assert _safe_timestamp("2026-07-27T12:00:00Z") is not None
