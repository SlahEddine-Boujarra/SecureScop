"""Behavioral regression cases for verified Wazuh monitoring facts."""

from datetime import datetime, timedelta, timezone

import pytest

from securescope.integrations.wazuh_monitoring import evaluate_monitoring, observation_time

NOW = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)


def snapshot(**updates):
    """Return synthetic exact-identity source facts; updates override fields."""
    row = dict(
        schema_version=2,
        identity_verified=True,
        asset_id=7,
        binding_id=4,
        connector_id="connector",
        manager_name="manager",
        wazuh_agent_id="007",
        wazuh_status="active",
        wazuh_last_keep_alive=NOW,
        collected_at=NOW,
        source_health="healthy",
        api_verified=True,
        heartbeat_max_age_seconds=300,
        telemetry_max_age_seconds=3600,
        telemetry={
            "authenticated": True,
            "kind": "security_event",
            "agent_id": "007",
            "manager_name": "manager",
            "source_event_id": "alerts:event-1",
            "observed_at": NOW,
            "rule_id": "1001",
        },
    )
    row.update(updates)
    return row


def test_current_exact_event_verifies_monitoring():
    """An authenticated relevant current event and heartbeat establish coverage."""
    result = evaluate_monitoring(snapshot(), now=NOW)
    assert result["monitoring_state"] == "verified"
    assert result["monitoring_status"] == "Monitoring verified"
    assert result["verified_until"] == NOW + timedelta(seconds=300)


@pytest.mark.parametrize(
    "updates,state",
    [
        ({"identity_verified": False}, "not_verified"),
        ({"wazuh_agent_id": ""}, "not_verified"),
        ({"telemetry": {}}, "active_unverified"),
        ({"wazuh_status": "disconnected"}, "disconnected"),
        ({"wazuh_status": "never_connected"}, "registered"),
        ({"wazuh_status": "pending"}, "registered"),
        ({"source_health": "unavailable"}, "source_unavailable"),
        ({"api_verified": False}, "source_unavailable"),
        ({"schema_version": 1}, "not_verified"),
        ({"heartbeat_max_age_seconds": 0}, "not_verified"),
        ({"wazuh_last_keep_alive": NOW + timedelta(seconds=1)}, "not_verified"),
        ({"wazuh_last_keep_alive": NOW - timedelta(seconds=301)}, "stale"),
    ],
)
def test_states_do_not_overclaim(updates, state):
    """Unavailable, legacy, ambiguous and non-current facts do not become proof."""
    assert evaluate_monitoring(snapshot(**updates), now=NOW)["monitoring_state"] == state


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "999"),
        ("manager_name", "foreign"),
        ("authenticated", False),
        ("kind", "heartbeat"),
        ("source_event_id", ""),
        ("rule_id", ""),
        ("observed_at", NOW + timedelta(seconds=1)),
    ],
)
def test_wrong_or_incomplete_event_is_unverified(field, value):
    """A query response must independently match the bound identity and time."""
    row = snapshot()
    row["telemetry"][field] = value
    assert evaluate_monitoring(row, now=NOW)["monitoring_state"] == "active_unverified"


def test_old_event_is_stale_and_expiry_boundary_is_exclusive():
    """Old proof stays visible but cannot count as current coverage."""
    row = snapshot()
    row["telemetry"]["observed_at"] = NOW - timedelta(seconds=3600)
    assert evaluate_monitoring(row, now=NOW)["monitoring_state"] == "stale"
    assert (
        evaluate_monitoring(snapshot(), now=NOW + timedelta(seconds=300))["monitoring_state"]
        == "stale"
    )


def test_no_alerts_does_not_claim_failed_monitoring():
    """Empty search results are incomplete verification, not a security failure."""
    result = evaluate_monitoring(snapshot(telemetry={}), now=NOW)
    assert result["monitoring_state"] == "active_unverified"
    assert "not monitored" not in result["monitoring_status"].lower()


def test_explicit_collection_health_can_verify_without_alerts():
    """Only a source-specific authenticated health observation qualifies."""
    row = snapshot()
    row["telemetry"].update(kind="collection_health", healthy=True, collection_verified=True)
    assert evaluate_monitoring(row, now=NOW)["monitoring_state"] == "verified"


@pytest.mark.parametrize("value", [None, "garbage", "9999-12-31T23:59:59Z", "2026-10-15T12:00:00"])
def test_bad_or_naive_times_are_unknown(value):
    """Missing, sentinel and timezone-ambiguous dates never become current."""
    assert observation_time(value) is None


def test_api_only_retains_active_but_unverified_status():
    """An absent optional Indexer does not claim that the agent is disconnected."""
    assert (
        evaluate_monitoring(snapshot(source_health="api_only"), now=NOW)["monitoring_state"]
        == "active_unverified"
    )


def test_bridge_payload_is_json_serializable_and_health_is_not_logging():
    """Source facts can be persisted as JSON; health-only evidence is not a log event."""
    import json

    from securescope.evidence.wazuh_bridge import normalized_source

    row = snapshot(id=13, asset_tag="TEST")
    payload, _ = normalized_source(row, "monitoring", now=NOW)
    json.dumps(payload)
    row["telemetry"].update(kind="collection_health", healthy=True, collection_verified=True)
    assert normalized_source(row, "logging", now=NOW) is None
    assert normalized_source(row, "monitoring", now=NOW) is not None


def test_legacy_system_monitoring_cannot_reenter_via_approved_mapping():
    """Previously approved mappings do not make active-only facts verified telemetry."""
    from securescope.evidence.automated_checks import usable_evidence

    row = dict(
        tool_id="wazuh",
        validation_status="Validated",
        mapping_approved=True,
        verification_origin="System collector",
        normalized_payload={
            "metadata": {"automated_checks": [{"check_id": "wazuh.monitoring.coverage"}]}
        },
    )
    assert not usable_evidence(row, {"wazuh"})


def test_failed_latest_collection_disqualifies_retained_evidence():
    """A source outage overrides the apparent age of retained source evidence."""
    from securescope.evidence.automated_checks import usable_evidence

    assert not usable_evidence(
        dict(
            validation_status="Validated",
            tool_id="wazuh",
            mapping_approved=True,
            source_verification_current=False,
        ),
        {"wazuh"},
    )
