"""SecureScope NTP and clock-synchronization evidence service.

Two evidence types are deliberately separated:

1. Network server evidence
   A direct SNTP request checks whether an asset answers as an NTP server.
   This does not prove that the asset itself is synchronized.

2. Endpoint evidence
   Wazuh command monitoring reports the configured source, synchronization
   state and offset from Windows/Linux endpoints.

Only endpoint evidence can prove client clock synchronization.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Iterable

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

from securescope.paths import ENV_FILE, PROJECT_ROOT

APP_DIR = PROJECT_ROOT
LOGGER = logging.getLogger(__name__)
load_dotenv(dotenv_path=ENV_FILE, override=False)

NTP_EPOCH = 2_208_988_800
NTP_PORT = 123
NTP_PACKET_SIZE = 48
DEFAULT_TIMEOUT = float(os.getenv("NTP_QUERY_TIMEOUT_SECONDS", "2.5"))
DEFAULT_TOLERANCE_MS = float(os.getenv("NTP_OFFSET_TOLERANCE_MS", "1000"))
DEFAULT_MANAGER_DELTA_TOLERANCE_MS = float(os.getenv("NTP_MANAGER_DELTA_TOLERANCE_MS", "5000"))
DEFAULT_EVIDENCE_MAX_AGE_MINUTES = float(os.getenv("NTP_EVIDENCE_MAX_AGE_MINUTES", "15"))
WAZUH_NTP_MARKER = "SECURESCOPE_NTP"


class NtpAuditError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp_ms(value: Any) -> int | None:
    """Convert ISO timestamps or epoch values to milliseconds."""
    if value in {None, ""}:
        return None
    try:
        numeric = float(value)
        return int(numeric if numeric > 10_000_000_000 else numeric * 1000)
    except (TypeError, ValueError):
        pass
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value not in {None, ""} else None
    except (TypeError, ValueError):
        return None


def _unix_to_ntp(value: float) -> tuple[int, int]:
    ntp_value = value + NTP_EPOCH
    seconds = int(ntp_value)
    fraction = int((ntp_value - seconds) * (2**32))
    return seconds, fraction


def _ntp_to_unix(data: bytes) -> float:
    seconds, fraction = struct.unpack("!II", data)
    return float(seconds - NTP_EPOCH) + float(fraction) / float(2**32)


def _reference_id(raw: bytes, stratum: int) -> str:
    if len(raw) != 4:
        return ""

    if stratum <= 1:
        try:
            return raw.decode("ascii", errors="ignore").strip("\x00")
        except Exception:
            return raw.hex()

    try:
        return socket.inet_ntoa(raw)
    except OSError:
        return raw.hex()


def query_ntp_server(
    ip_address: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send one standard SNTP request and calculate server clock offset."""
    ip = str(ip_address or "").strip()
    checked_at = utc_now()

    result: dict[str, Any] = {
        "ip": ip,
        "ntp_server_detected": False,
        "ntp_role": "Unknown",
        "ntp_server_stratum": None,
        "ntp_server_refid": "",
        "ntp_server_offset_ms": None,
        "ntp_server_delay_ms": None,
        "ntp_server_version": None,
        "ntp_server_mode": None,
        "ntp_server_leap": None,
        "ntp_server_last_checked": checked_at,
        "ntp_server_error": "",
    }

    if not ip or ip.lower() in {"unknown", "not detected", "n/a"}:
        result["ntp_server_error"] = "Missing usable IP address."
        return result

    packet = bytearray(NTP_PACKET_SIZE)
    # LI=0, Version=4, Mode=3 (client).
    packet[0] = 0x23

    t1 = time.time()
    seconds, fraction = _unix_to_ntp(t1)
    packet[40:48] = struct.pack("!II", seconds, fraction)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, float(timeout)))

    try:
        sock.sendto(packet, (ip, NTP_PORT))
        response, _address = sock.recvfrom(512)
        t4 = time.time()
    except socket.timeout:
        result["ntp_server_error"] = "No NTP response before timeout."
        return result
    except OSError as exc:
        result["ntp_server_error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        sock.close()

    if len(response) < NTP_PACKET_SIZE:
        result["ntp_server_error"] = f"Invalid NTP response length: {len(response)} bytes."
        return result

    first = int(response[0])
    leap = (first >> 6) & 0x03
    version = (first >> 3) & 0x07
    mode = first & 0x07
    stratum = int(response[1])

    try:
        originate = _ntp_to_unix(response[24:32])
        receive = _ntp_to_unix(response[32:40])
        transmit = _ntp_to_unix(response[40:48])

        # Some devices do not copy the client transmit timestamp correctly.
        effective_t1 = originate if originate > 0 else t1
        offset_seconds = ((receive - effective_t1) + (transmit - t4)) / 2.0
        delay_seconds = (t4 - effective_t1) - (transmit - receive)
    except Exception as exc:
        result["ntp_server_error"] = f"NTP timestamp parsing failed: {type(exc).__name__}: {exc}"
        return result

    role = {
        1: "Symmetric active peer",
        2: "Symmetric passive peer",
        4: "NTP server",
        5: "Broadcast server",
    }.get(mode, f"NTP mode {mode}")

    result.update(
        {
            "ntp_server_detected": mode in {1, 2, 4, 5},
            "ntp_role": role,
            "ntp_server_stratum": stratum,
            "ntp_server_refid": _reference_id(response[12:16], stratum),
            "ntp_server_offset_ms": round(offset_seconds * 1000.0, 3),
            "ntp_server_delay_ms": round(max(0.0, delay_seconds) * 1000.0, 3),
            "ntp_server_version": version,
            "ntp_server_mode": mode,
            "ntp_server_leap": leap,
            "ntp_server_error": "",
        }
    )
    return result


def audit_ntp_servers(
    assets: Iterable[dict[str, Any]],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 16,
) -> list[dict[str, Any]]:
    """Check assets concurrently for an NTP server response."""
    asset_list = list(assets)
    if not asset_list:
        return []

    results: list[dict[str, Any]] = []
    workers = max(1, min(int(max_workers), len(asset_list)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                query_ntp_server,
                str(asset.get("ip") or ""),
                timeout=timeout,
            ): asset
            for asset in asset_list
        }

        for future in as_completed(future_map):
            asset = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "ip": str(asset.get("ip") or ""),
                    "ntp_server_detected": False,
                    "ntp_role": "Unknown",
                    "ntp_server_last_checked": utc_now(),
                    "ntp_server_error": f"{type(exc).__name__}: {exc}",
                }

            result["asset_tag"] = str(asset.get("asset_tag") or "")
            result["hostname"] = str(asset.get("hostname") or "")
            results.append(result)

    return sorted(results, key=lambda item: str(item.get("ip") or ""))


def _walk_strings(value: Any) -> list[str]:
    strings: list[str] = []

    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for nested in value.values():
            strings.extend(_walk_strings(nested))
    elif isinstance(value, list):
        for nested in value:
            strings.extend(_walk_strings(nested))

    return strings


def parse_ntp_evidence_text(
    text: str,
    *,
    fallback_ip: str = "",
    fallback_hostname: str = "",
    fallback_agent_id: str = "",
    fallback_timestamp: str = "",
) -> dict[str, Any] | None:
    """Parse one SECURESCOPE_NTP JSON line."""
    raw = str(text or "")
    marker_index = raw.find(WAZUH_NTP_MARKER)
    if marker_index < 0:
        return None

    payload_text = raw[marker_index + len(WAZUH_NTP_MARKER) :].strip()
    if payload_text.startswith(":"):
        payload_text = payload_text[1:].strip()

    first_brace = payload_text.find("{")
    last_brace = payload_text.rfind("}")
    if first_brace < 0 or last_brace <= first_brace:
        return None

    try:
        payload = json.loads(payload_text[first_brace : last_brace + 1])
    except json.JSONDecodeError:
        return None

    synchronized_raw = payload.get("synchronized")
    if isinstance(synchronized_raw, str):
        synchronized = synchronized_raw.strip().lower() in {
            "1",
            "true",
            "yes",
            "synchronized",
            "sync",
        }
    else:
        synchronized = bool(synchronized_raw)

    try:
        offset_ms = (
            float(payload.get("offset_ms")) if payload.get("offset_ms") not in {None, ""} else None
        )
    except (TypeError, ValueError):
        offset_ms = None

    try:
        stratum = int(payload.get("stratum")) if payload.get("stratum") not in {None, ""} else None
    except (TypeError, ValueError):
        stratum = None

    agent_epoch_ms = _timestamp_ms(payload.get("epoch_ms") or payload.get("epoch"))
    manager_received_ms = _timestamp_ms(fallback_timestamp)
    manager_agent_delta_ms = None
    if agent_epoch_ms is not None and manager_received_ms is not None:
        manager_agent_delta_ms = manager_received_ms - agent_epoch_ms

    return {
        "asset_ip": str(payload.get("ip") or fallback_ip or "").strip(),
        "asset_hostname": str(payload.get("hostname") or fallback_hostname or "").strip(),
        "wazuh_agent_id": str(payload.get("agent_id") or fallback_agent_id or "").strip(),
        "clock_source": str(payload.get("source") or "").strip(),
        "clock_synchronized": synchronized,
        "clock_offset_ms": offset_ms,
        "clock_stratum": stratum,
        "clock_service": str(payload.get("service") or "").strip(),
        "clock_os": str(payload.get("os") or "").strip(),
        "clock_epoch_ms": agent_epoch_ms,
        "wazuh_received_epoch_ms": manager_received_ms,
        "manager_agent_delta_ms": manager_agent_delta_ms,
        "clock_evidence_source": "Wazuh endpoint command",
        "clock_last_checked": str(payload.get("collected_at") or fallback_timestamp or utc_now()),
        "clock_raw": payload,
    }


def collect_wazuh_ntp_evidence(
    *,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Read latest SECURESCOPE_NTP command outputs from Wazuh Indexer."""
    from securescope.integrations.credential_store import CredentialStoreError
    from securescope.integrations.wazuh_service import restore_wazuh_settings

    try:
        restore_wazuh_settings()
    except CredentialStoreError as exc:
        raise NtpAuditError("The saved Indexer connection could not be loaded.") from exc
    indexer_url = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
    username = os.getenv("WAZUH_INDEXER_USER", "")
    password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    verify_tls = os.getenv(
        "WAZUH_INDEXER_VERIFY_TLS",
        os.getenv("WAZUH_VERIFY_TLS", "true"),
    ).strip().lower() in {"1", "true", "yes", "on"}
    index_pattern = os.getenv(
        "WAZUH_INDEXER_ALERT_INDEX",
        "wazuh-alerts-*",
    )

    if not indexer_url:
        raise NtpAuditError("Missing WAZUH_INDEXER_URL in .env.")
    if not username or not password:
        raise NtpAuditError("Missing WAZUH_INDEXER_USER or WAZUH_INDEXER_PASSWORD in .env.")

    if not verify_tls:
        LOGGER.warning("Indexer TLS verification is disabled by explicit configuration")

    query = {
        "size": max(1, min(int(limit), 5000)),
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": True,
        "query": {
            "query_string": {
                "query": f'"{WAZUH_NTP_MARKER}"',
                "default_operator": "AND",
            }
        },
    }

    url = f"{indexer_url}/{index_pattern}/_search"

    try:
        response = requests.post(
            url,
            json=query,
            auth=HTTPBasicAuth(username, password),
            verify=verify_tls,
            timeout=int(os.getenv("WAZUH_TIMEOUT_SECONDS", "30")),
        )
    except requests.RequestException as exc:
        raise NtpAuditError(f"Wazuh Indexer request failed: {exc}") from exc

    if response.status_code >= 400:
        raise NtpAuditError(
            f"Wazuh Indexer returned HTTP {response.status_code}: " f"{response.text[:700]}"
        )

    payload = response.json()
    hits = payload.get("hits", {}).get("hits", []) or []
    evidence: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for hit in hits:
        source = hit.get("_source") or {}
        agent = source.get("agent") or {}
        fallback_ip = str(agent.get("ip") or source.get("agent_ip") or "")
        fallback_hostname = str(
            agent.get("name") or source.get("hostname") or source.get("agent_name") or ""
        )
        fallback_agent_id = str(agent.get("id") or "")
        timestamp = str(source.get("@timestamp") or source.get("timestamp") or "")

        parsed = None
        for candidate in _walk_strings(source):
            parsed = parse_ntp_evidence_text(
                candidate,
                fallback_ip=fallback_ip,
                fallback_hostname=fallback_hostname,
                fallback_agent_id=fallback_agent_id,
                fallback_timestamp=timestamp,
            )
            if parsed:
                break

        if not parsed:
            continue

        key = parsed.get("asset_ip") or parsed.get("asset_hostname") or parsed.get("wazuh_agent_id")
        key = str(key or "").strip().lower()
        if not key or key in seen_keys:
            continue

        seen_keys.add(key)
        evidence.append(parsed)

    return evidence


def match_clock_evidence_to_assets(
    assets: Iterable[dict[str, Any]],
    evidence_rows: Iterable[dict[str, Any]],
    *,
    agent_rows: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merge latest Wazuh clock evidence into the Nmap inventory.

    Matching priority is IP, exact hostname, then Wazuh agent identity resolved
    from ``match_agents_to_assets`` output. Unmatched assets remain visible with
    ``No evidence`` so missing agent coverage cannot look compliant.
    """
    evidence = list(evidence_rows)
    by_ip = {
        str(row.get("asset_ip") or "").strip().lower(): row
        for row in evidence
        if str(row.get("asset_ip") or "").strip()
    }
    by_host = {
        str(row.get("asset_hostname") or "").strip().lower(): row
        for row in evidence
        if str(row.get("asset_hostname") or "").strip()
    }
    by_agent = {
        str(row.get("wazuh_agent_id") or "").strip(): row
        for row in evidence
        if str(row.get("wazuh_agent_id") or "").strip()
    }

    asset_to_agent: dict[str, str] = {}
    for row in agent_rows or []:
        asset_key = str(row.get("asset_ip") or "").strip().lower()
        agent_id = str(row.get("wazuh_agent_id") or "").strip()
        if asset_key and agent_id:
            asset_to_agent[asset_key] = agent_id

    merged = []
    for asset in assets:
        item = dict(asset)
        ip_key = str(item.get("ip") or "").strip().lower()
        host_key = str(item.get("hostname") or item.get("name") or "").strip().lower()
        row = by_ip.get(ip_key) or by_host.get(host_key)
        if row is None and ip_key in asset_to_agent:
            row = by_agent.get(asset_to_agent[ip_key])

        if row:
            item.update(row)
            item["clock_sync_status"] = apply_clock_status(row)
        else:
            item.update(
                {
                    "clock_sync_status": "No evidence",
                    "clock_evidence_source": "",
                    "clock_source": "",
                    "clock_offset_ms": None,
                    "manager_agent_delta_ms": None,
                }
            )
        merged.append(item)
    return merged


def clock_evidence_table(
    assets: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a display-safe clock-assurance table."""
    rows = []
    for asset in assets:
        rows.append(
            {
                "Asset": asset.get("asset_tag") or asset.get("hostname") or "Asset",
                "IP": asset.get("ip") or asset.get("asset_ip"),
                "Wazuh agent": asset.get("wazuh_agent_id") or "",
                "Status": asset.get("clock_sync_status") or "No evidence",
                "Source": asset.get("clock_source") or "",
                "Offset (ms)": asset.get("clock_offset_ms"),
                "Manager/agent delta (ms)": asset.get("manager_agent_delta_ms"),
                "Stratum": asset.get("clock_stratum"),
                "Service": asset.get("clock_service") or "",
                "Last evidence": asset.get("clock_last_checked") or "",
            }
        )
    return rows


def apply_clock_status(
    evidence: dict[str, Any],
    *,
    tolerance_ms: float = DEFAULT_TOLERANCE_MS,
    manager_delta_tolerance_ms: float = DEFAULT_MANAGER_DELTA_TOLERANCE_MS,
    max_age_minutes: float = DEFAULT_EVIDENCE_MAX_AGE_MINUTES,
    now_epoch_ms: int | None = None,
) -> str:
    """Convert endpoint evidence into a clock-assurance state.

    The endpoint time-service result is the primary signal.  SecureScope also
    compares the endpoint epoch embedded in the event with the Wazuh manager
    receipt timestamp.  That second comparison includes network/indexing delay,
    so it uses a wider tolerance and is supporting evidence rather than a
    precision NTP measurement.
    """
    if not evidence:
        return "Unknown"

    received_ms = _timestamp_ms(evidence.get("wazuh_received_epoch_ms"))
    if received_ms is not None and max_age_minutes > 0:
        reference_ms = now_epoch_ms or int(time.time() * 1000)
        age_ms = reference_ms - received_ms
        if age_ms > float(max_age_minutes) * 60_000:
            return "Stale evidence"

    synchronized = bool(evidence.get("clock_synchronized"))
    if not synchronized:
        return "Not synchronized"

    offset = _float_or_none(evidence.get("clock_offset_ms"))
    if offset is not None and abs(offset) > float(tolerance_ms):
        return "Out of tolerance"

    manager_delta = _float_or_none(evidence.get("manager_agent_delta_ms"))
    if manager_delta is not None and abs(manager_delta) > float(manager_delta_tolerance_ms):
        return "Out of tolerance"

    return "Synchronized"


def fleet_clock_summary(
    assets: Iterable[dict[str, Any]],
    *,
    tolerance_ms: float = DEFAULT_TOLERANCE_MS,
) -> dict[str, Any]:
    """Assess whether all assets have comparable endpoint clock evidence."""
    asset_list = list(assets)
    total = len(asset_list)

    evidence_assets = [
        asset
        for asset in asset_list
        if str(asset.get("clock_evidence_source") or "").strip()
        and str(asset.get("clock_sync_status") or "").strip() not in {"", "Unknown", "No evidence"}
    ]
    synchronized_assets = [
        asset
        for asset in evidence_assets
        if str(asset.get("clock_sync_status") or "") == "Synchronized"
    ]
    out_of_tolerance = [
        asset
        for asset in evidence_assets
        if str(asset.get("clock_sync_status") or "")
        in {"Out of tolerance", "Not synchronized", "Stale evidence"}
    ]

    sources = sorted(
        {
            str(asset.get("clock_source") or "").strip()
            for asset in evidence_assets
            if str(asset.get("clock_source") or "").strip()
        }
    )

    offsets = []
    manager_deltas = []
    for asset in evidence_assets:
        try:
            value = asset.get("clock_offset_ms")
            if value not in {None, ""}:
                offsets.append(abs(float(value)))
        except (TypeError, ValueError):
            pass
        try:
            value = asset.get("manager_agent_delta_ms")
            if value not in {None, ""}:
                manager_deltas.append(abs(float(value)))
        except (TypeError, ValueError):
            pass

    if total == 0:
        status = "No assets"
    elif len(evidence_assets) < total:
        status = "Partial evidence"
    elif out_of_tolerance:
        status = "Synchronization gap"
    elif len(sources) > 1:
        status = "Multiple time sources"
    elif len(synchronized_assets) == total:
        status = "Synchronized"
    else:
        status = "Not verified"

    return {
        "status": status,
        "assets_total": total,
        "assets_with_endpoint_evidence": len(evidence_assets),
        "synchronized_assets": len(synchronized_assets),
        "gap_assets": len(out_of_tolerance),
        "sources": sources,
        "common_source": sources[0] if len(sources) == 1 else "",
        "max_absolute_offset_ms": max(offsets) if offsets else None,
        "max_manager_agent_delta_ms": (max(manager_deltas) if manager_deltas else None),
        "tolerance_ms": float(tolerance_ms),
        "manager_delta_tolerance_ms": float(DEFAULT_MANAGER_DELTA_TOLERANCE_MS),
        "evidence_max_age_minutes": float(DEFAULT_EVIDENCE_MAX_AGE_MINUTES),
        "all_assets_verified": total > 0 and len(evidence_assets) == total,
        "all_assets_synchronized": (
            total > 0 and len(synchronized_assets) == total and not out_of_tolerance
        ),
    }
