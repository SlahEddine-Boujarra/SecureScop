"""Pure monitoring truth rules shared by collection, evidence and presentation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

MONITORING_SCHEMA_VERSION = 2
LABELS = {
    "verified": "Monitoring verified",
    "active_unverified": "Agent active — telemetry unverified",
    "stale": "Monitoring stale",
    "disconnected": "Agent disconnected",
    "registered": "Agent registered — not active",
    "not_verified": "Monitoring not verified",
    "source_unavailable": "Source unavailable — monitoring not verified",
}


def observation_time(value: Any) -> datetime | None:
    """Parse an aware source timestamp, rejecting sentinel and ambiguous dates.

    Args:
        value: A datetime or ISO 8601 string with a timezone.
    Returns:
        UTC datetime, or None for unsupported/invalid values.
    Raises:
        No expected exceptions.
    """
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.year >= 2099:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def evaluate_monitoring(row: dict, *, now: datetime | None = None) -> dict:
    """Derive coverage without changing raw facts or any human assessment.

    Args:
        row: Persisted bound-asset facts with explicit freshness policy.
        now: Aware evaluation clock, defaulting to current UTC time.
    Returns:
        State, display label, reason and last verification/expiry timestamps.
    Raises:
        ValueError: If the evaluation clock lacks a timezone.
    """
    clock = observation_time(now or datetime.now(timezone.utc))
    if clock is None:
        raise ValueError("Monitoring evaluation requires an aware clock.")
    result = dict(last_verified_at=None, verified_until=None)

    def state(code: str, reason: str) -> dict:
        """Return an explainable state using only this evaluation's facts."""
        return dict(
            result, monitoring_state=code, monitoring_status=LABELS[code], monitoring_reason=reason
        )

    if (
        row.get("schema_version") != MONITORING_SCHEMA_VERSION
        or not row.get("identity_verified")
        or not all(
            row.get(k)
            for k in ("asset_id", "binding_id", "connector_id", "manager_name", "wazuh_agent_id")
        )
    ):
        return state(
            "not_verified", "An administrator-approved exact agent/asset binding is required."
        )
    try:
        heartbeat_age = int(row.get("heartbeat_max_age_seconds") or 0)
        telemetry_age = int(row.get("telemetry_max_age_seconds") or 0)
    except (ValueError, TypeError):
        return state("not_verified", "The monitoring freshness policy is invalid.")
    if not 1 <= heartbeat_age <= 604800 or not 1 <= telemetry_age <= 31536000:
        return state("not_verified", "Configure the monitoring freshness policy.")
    telemetry = row.get("telemetry") or {}
    if not isinstance(telemetry, dict):
        telemetry = {}
    observed = observation_time(telemetry.get("observed_at"))
    relevant = (telemetry.get("kind") == "security_event" and bool(telemetry.get("rule_id"))) or (
        telemetry.get("kind") == "collection_health"
        and telemetry.get("healthy") is True
        and telemetry.get("collection_verified") is True
    )
    if row.get("m2_collection") and telemetry.get("kind") == "collection_health":
        received = observation_time(telemetry.get("received_at"))
        relevant = bool(
            relevant
            and telemetry.get("health_contract_version") == 1
            and telemetry.get("policy_sha256") == row.get("health_policy_sha256")
            and received
            and observed
            and observed <= received <= clock
            and telemetry.get("channel")
            and telemetry.get("document_id")
        )
        try:
            telemetry_age = min(telemetry_age, int(row.get("health_max_age_seconds", 0)))
        except (ValueError, TypeError):
            relevant = False
        relevant = relevant and telemetry_age > 0
    exact_event = bool(
        telemetry.get("authenticated") is True
        and relevant
        and telemetry.get("agent_id") == row["wazuh_agent_id"]
        and telemetry.get("manager_name") == row["manager_name"]
        and telemetry.get("source_event_id")
        and observed
        and observed <= clock
    )
    if exact_event:
        result["last_verified_at"] = observed
    if (
        row.get("source_health") not in {"healthy", "api_only"}
        or row.get("api_verified") is not True
    ):
        return state(
            "source_unavailable",
            row.get("source_error")
            or "Source health is unavailable; retained observations are not current proof.",
        )
    status = str(row.get("wazuh_status") or "").lower()
    if status == "disconnected":
        return state("disconnected", "The bound agent is explicitly reported disconnected.")
    if status in {"pending", "never_connected"}:
        return state("registered", "The bound agent is registered but has no active connection.")
    if status != "active":
        return state("not_verified", "The source has not established an active agent state.")
    heartbeat = observation_time(row.get("wazuh_last_keep_alive"))
    collected = observation_time(row.get("collected_at"))
    if not heartbeat or not collected or heartbeat > clock or collected > clock:
        return state("not_verified", "Heartbeat or collection timestamp is missing or invalid.")
    fresh_until = min(heartbeat, collected) + timedelta(seconds=heartbeat_age)
    if clock >= fresh_until:
        return state("stale", "The last verified agent/collection state is outside policy.")
    if row.get("source_health") == "api_only":
        return state(
            "active_unverified", "API heartbeat available; Indexer telemetry is not configured."
        )
    if not exact_event:
        return state(
            "active_unverified", "Heartbeat available; relevant telemetry is not verified."
        )
    fresh_until = min(fresh_until, observed + timedelta(seconds=telemetry_age))
    if clock >= fresh_until:
        return state("stale", "The retained telemetry is outside the configured freshness policy.")
    result["verified_until"] = fresh_until
    return state(
        "verified", "Exact bound agent, recent heartbeat and authenticated telemetry verified."
    )
