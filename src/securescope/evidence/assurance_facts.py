"""Allowlisted provider facts used by requirement rules; absence never implies success."""

from __future__ import annotations

from typing import Any

CAPABILITIES = {
    "nmap": {"complete", "asset_ids", "asset_ips"},
    "nuclei": {"complete", "asset_ids", "asset_ips"},
    "openvas": {"complete", "asset_ids", "asset_ips"},
    "wazuh": {"logging", "tests", "asset_ids", "asset_ips", "safety"},
    "siem": {"logging", "tests", "asset_ids", "asset_ips", "safety"},
    "asset_inventory": {"complete", "classification", "asset_ids", "asset_ips"},
    "classification": {"classification", "asset_ids", "asset_ips"},
    "openscap": {"tests", "asset_ids", "asset_ips"},
    "prowler": {"tests", "asset_ids", "asset_ips"},
}


def normalize_assurance_facts(provider: str, raw: Any) -> dict:
    """Retain supported typed facts from an explicit provider assurance envelope.

    Args:
        provider: Canonical evidence tool ID.
        raw: Explicit assurance object supplied by the provider/connector.
    Returns:
        Bounded normalized facts; unknown providers/fields produce no proof.
    Raises:
        No exceptions are raised for malformed source facts.
    """
    if not isinstance(raw, dict):
        return {}
    result = {}
    for key in CAPABILITIES.get(provider.lower(), set()):
        value = raw.get(key)
        if key == "complete" and type(value) is bool:
            result[key] = value
        elif key in {"asset_ids", "asset_ips"} and isinstance(value, list):
            expected_type = int if key == "asset_ids" else str
            result[key] = sorted(set(v for v in value[:10000] if type(v) is expected_type))
        elif key in {"logging", "classification"} and isinstance(value, dict):
            result[key] = {
                field: sorted(set(i for i in value.get(field, [])[:10000] if type(i) is int))
                for field in ("evaluated_asset_ids", "satisfied_asset_ids")
                if isinstance(value.get(field), list)
            }
        elif key == "tests" and isinstance(value, dict):
            result[key] = {str(k)[:200]: v for k, v in list(value.items())[:200] if type(v) is bool}
        elif key == "safety" and isinstance(value, dict):
            result[key] = {
                k: value[k]
                for k in (
                    "exceptions_present",
                    "critical_remediation_overdue",
                    "contradictory_findings_present",
                )
                if type(value.get(k)) is bool
            }
            assets = value.get("evaluated_asset_ids")
            if isinstance(assets, list):
                result[key]["evaluated_asset_ids"] = sorted(
                    set(i for i in assets[:10000] if type(i) is int)
                )
    return result
