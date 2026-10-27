"""Read-only SIEM presentation data; monitoring rules remain in the existing service."""

from datetime import datetime, timezone

from securescope.integrations.wazuh_monitoring import LABELS, observation_time

SOURCE_FIELDS = (
    "binding_id",
    "connector_id",
    "manager_name",
    "wazuh_agent_id",
    "wazuh_agent_name",
    "wazuh_status",
    "source_health",
    "collected_at",
    "wazuh_last_keep_alive",
    "last_verified_at",
    "verified_until",
    "heartbeat_max_age_seconds",
    "telemetry_max_age_seconds",
    "payload_sha256",
    "source_key",
    "match_type",
    "last_action",
    "last_alert_time",
    "wazuh_os",
)
TELEMETRY_FIELDS = (
    "kind",
    "source_event_id",
    "observed_at",
    "received_at",
    "channel",
    "document_id",
    "rule_id",
    "collection_verified",
    "healthy",
)


def _display_value(value) -> str:
    """Convert one scalar to safe display text without exposing nested source payloads.

    Args:
        value: A repository scalar, datetime or absent value.
    Returns:
        Plain string, bounded at 4,000 characters; empty for unsupported values.
    Raises:
        No expected exceptions for repository scalar values.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:4000]
    return ""


def monitoring_view(rows: list[dict], client_name: str, *, now=None) -> dict:
    """Project authorized workspace facts into an explicit, secret-free UI field allowlist.

    Args:
        rows: Current rows from load_latest_wazuh_status for the selected workspace.
        client_name: Server-selected workspace name, never a component-supplied selector.
        now: Optional aware datetime for deterministic presentation tests.
    Returns:
        JSON-compatible workspace, observation time and stable asset rows.
    Raises:
        ValueError: Missing workspace, duplicate/invalid asset IDs or an invalid clock.
    """
    clock = observation_time(now or datetime.now(timezone.utc))
    if not client_name or clock is None:
        raise ValueError("A workspace and an aware presentation time are required.")
    seen, assets = set(), []
    for row in rows:
        asset_id = row.get("asset_id")
        if type(asset_id) is not int or asset_id <= 0 or asset_id in seen:
            raise ValueError("Monitoring rows require distinct canonical asset identities.")
        seen.add(asset_id)
        state = row.get("monitoring_state", "not_verified")
        if state not in LABELS:
            state = "not_verified"
        reason = _display_value(row.get("monitoring_reason")) or "Monitoring has not been verified."
        expiry = observation_time(row.get("verified_until"))
        if state == "verified" and (expiry is None or expiry <= clock):
            state = "stale" if expiry else "not_verified"
            reason = "Retained verification is expired or has no expiry. Refresh source status."
        telemetry = row.get("telemetry")
        telemetry = telemetry if isinstance(telemetry, dict) else {}
        assets.append(
            dict(
                asset_id=asset_id,
                asset_tag=_display_value(row.get("asset_tag")) or f"Asset #{asset_id}",
                asset_ip=_display_value(row.get("asset_ip")),
                asset_hostname=_display_value(row.get("asset_hostname")),
                monitoring_state=state,
                monitoring_status=LABELS[state],
                monitoring_reason=reason,
                binding_status=(
                    "Approved binding"
                    if row.get("identity_verified") is True and row.get("binding_id")
                    else "Needs mapping"
                ),
                source={key: _display_value(row.get(key)) for key in SOURCE_FIELDS},
                telemetry={key: _display_value(telemetry.get(key)) for key in TELEMETRY_FIELDS},
            )
        )
    return dict(workspace=client_name, evaluated_at=clock.isoformat(), rows=assets)
