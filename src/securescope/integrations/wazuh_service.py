"""
SecureScope Wazuh SIEM connector.

Required .env:
    WAZUH_API_URL=https://192.168.100.19:55000
    WAZUH_API_USER=wazuh
    WAZUH_API_PASSWORD=YOUR_WAZUH_API_PASSWORD
    WAZUH_VERIFY_TLS=true
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

from securescope.integrations.credential_store import load_configuration, store_configuration
from securescope.integrations.wazuh_monitoring import evaluate_monitoring
from securescope.paths import ENV_FILE, PROJECT_ROOT
from securescope.persistence.evidence_repository import EvidenceRepositoryError, get_workspace_role

LOGGER = logging.getLogger(__name__)

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)


class WazuhError(RuntimeError):
    """Signal a bounded Wazuh connector failure without exposing credentials."""

    def __init__(self, message, *, retry_after=0):
        """Initialize a safe message and capped delay; invalid delay values become zero."""
        super().__init__(message)
        from securescope.integrations.wazuh_collection_health import retry_delay

        self.retry_after = retry_delay(retry_after)


class WazuhTelemetryNotConfigured(WazuhError):
    """Signal API-only operation with no configured Indexer telemetry source."""


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def require_connector_admin(client_name: str, actor: str) -> None:
    """Require host authorization and current Administrator membership.

    Args:
        client_name: Active workspace.
        actor: Server-configured identity, never a form value.
    Returns:
        None.
    Raises:
        WazuhError: If membership or host authorization cannot be confirmed.
    """
    allowed = {
        email.strip().lower()
        for email in os.getenv("SECURESCOPE_CONNECTOR_ADMINS", "").split(",")
        if email.strip()
    }
    if (
        not actor
        or actor != os.getenv("SECURESCOPE_CURRENT_USER_EMAIL", "").strip().lower()
        or actor not in allowed
    ):
        raise WazuhError(
            "The host administrator must authorize this identity to manage shared connectors."
        )
    try:
        role = get_workspace_role(client_name, actor)
    except EvidenceRepositoryError as exc:
        raise WazuhError("Administrator membership could not be verified.") from exc
    if role != "Administrator":
        raise WazuhError("Only an active workspace Administrator may change connector settings.")


def restore_wazuh_settings() -> None:
    """Apply encrypted persisted settings to the server runtime.

    Returns:
        None.
    Raises:
        CredentialStoreError: If an existing encrypted configuration is unreadable.
    """
    for key, value in load_configuration().items():
        if key.startswith("WAZUH_"):
            os.environ[key] = str(value)


def save_wazuh_config(
    api_url: str,
    api_user: str,
    api_password: str,
    verify_tls: bool = True,
    indexer_url: str = "",
    indexer_user: str = "",
    indexer_password: str = "",
    *,
    client_name: str,
    actor: str,
    verify_indexer_tls: bool = True,
) -> None:
    """Validate and atomically save encrypted settings after authorization.

    Args:
        api_url: HTTPS Wazuh manager URL.
        api_user: Manager account.
        api_password: Replacement secret; empty keeps the current value.
        verify_tls: Whether server certificate verification is enabled.
        indexer_url: Optional HTTPS indexer URL.
        indexer_user: Optional indexer account.
        indexer_password: Replacement indexer secret; empty preserves it.
        client_name: Workspace whose Administrator is authorizing this action.
        actor: Server-configured identity.
        verify_indexer_tls: Verify the separate Indexer server certificate.
    Returns:
        None; runtime updates occur only after a successful encrypted write.
    Raises:
        WazuhError: If authorization or input validation fails.
        CredentialStoreError: If encryption or persistence fails.
    """
    require_connector_admin(client_name, actor)
    for endpoint in (api_url, indexer_url):
        parsed = urlsplit(endpoint.strip())
        if endpoint and (
            parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        ):
            raise WazuhError("Use an HTTPS URL without embedded credentials.")
    if not api_url.strip() or not api_user.strip():
        raise WazuhError("Wazuh API URL and username are required.")
    if not isinstance(verify_tls, bool) or not isinstance(verify_indexer_tls, bool):
        raise WazuhError("TLS verification must be a boolean.")
    persisted = load_configuration()
    password = api_password or persisted.get(
        "WAZUH_API_PASSWORD",
        os.getenv("WAZUH_API_PASSWORD", ""),
    )
    if not password:
        raise WazuhError("A Wazuh API password is required.")
    updates = {
        "WAZUH_API_URL": api_url.strip().rstrip("/"),
        "WAZUH_API_USER": api_user.strip(),
        "WAZUH_API_PASSWORD": password,
        "WAZUH_VERIFY_TLS": "true" if verify_tls else "false",
        "WAZUH_INDEXER_VERIFY_TLS": "true" if verify_indexer_tls else "false",
        "WAZUH_INDEXER_URL": indexer_url.strip().rstrip("/"),
        "WAZUH_INDEXER_USER": indexer_user.strip(),
        "WAZUH_INDEXER_PASSWORD": indexer_password
        or persisted.get(
            "WAZUH_INDEXER_PASSWORD",
            os.getenv("WAZUH_INDEXER_PASSWORD", ""),
        ),
    }
    store_configuration(updates)
    os.environ.update(updates)
    LOGGER.info("Wazuh connector settings updated by %s in workspace %s", actor, client_name)


def configured_connector_id() -> str:
    """Identify the configured endpoints without authentication or network access.

    Restores the existing encrypted configuration before comparing provenance.
    Credentials are excluded; an endpoint or alert-index change invalidates proof.
    """
    restore_wazuh_settings()
    identity = "|".join(
        (
            os.getenv("WAZUH_API_URL", "").rstrip("/"),
            os.getenv("WAZUH_INDEXER_URL", "").rstrip("/"),
            os.getenv("WAZUH_INDEXER_ALERT_INDEX", "wazuh-alerts-*"),
            str(env_bool("WAZUH_VERIFY_TLS", True)),
            str(env_bool("WAZUH_INDEXER_VERIFY_TLS", True)),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()


class WazuhClient:
    def __init__(self) -> None:
        restore_wazuh_settings()
        self.api_url = os.getenv("WAZUH_API_URL", "").rstrip("/")
        self.api_user = os.getenv("WAZUH_API_USER", "wazuh")
        self.api_password = os.getenv("WAZUH_API_PASSWORD", "")
        self.verify_tls = env_bool("WAZUH_VERIFY_TLS", True)
        self.timeout = int(os.getenv("WAZUH_TIMEOUT_SECONDS", "30"))
        self.token: Optional[str] = None
        self.before_request = None

        if not self.api_url:
            raise WazuhError("Missing WAZUH_API_URL in the host connector configuration.")

        if not self.api_password:
            raise WazuhError("Missing WAZUH_API_PASSWORD in the host connector configuration.")

        if not self.verify_tls:
            LOGGER.warning(
                "Wazuh TLS certificate verification is disabled by explicit configuration"
            )

    def _admit_request(self) -> None:
        """Invoke the optional M2 request budget; return None; propagate lease/rate failures."""
        if self.before_request is not None:
            self.before_request()

    def authenticate(self) -> str:
        self._admit_request()
        url = f"{self.api_url}/security/user/authenticate?raw=true"

        try:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.api_user, self.api_password),
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise WazuhError("Cannot connect to Wazuh API.") from exc

        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh authentication failed: HTTP {response.status_code}",
                retry_after=getattr(response, "headers", {}).get("Retry-After", "0"),
            )

        token = response.text.strip().strip('"')

        if not token:
            raise WazuhError("Wazuh API returned an empty token.")

        self.token = token
        return token

    def headers(self) -> Dict[str, str]:
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = self.headers()
        self._admit_request()
        url = f"{self.api_url}{path}"

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise WazuhError("Wazuh API request failed.") from exc

        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh API request failed: HTTP {response.status_code}",
                retry_after=getattr(response, "headers", {}).get("Retry-After", "0"),
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhError("Wazuh API returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise WazuhError("Wazuh API returned an invalid response shape.")
        return payload

    def put(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send one authenticated Wazuh API PUT request.

        Args:
            path: Fixed Wazuh API path beginning with ``/``.
            params: Optional query parameters.
            payload: Optional JSON body.

        Returns:
            Decoded Wazuh API response.

        Raises:
            WazuhError: If the path is invalid, transport fails, or Wazuh
                rejects the request.
        """

        if not path.startswith("/") or ".." in path:
            raise WazuhError("Invalid Wazuh API path.")
        url = f"{self.api_url}{path}"
        try:
            response = requests.put(
                url,
                headers=self.headers(),
                params=params,
                json=payload or {},
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise WazuhError(f"Wazuh API PUT failed for {path}: {exc}") from exc
        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh API PUT {path} failed: HTTP {response.status_code} - "
                f"{response.text[:500]}"
            )
        try:
            return response.json()
        except requests.JSONDecodeError as exc:
            raise WazuhError("Wazuh API returned invalid JSON.") from exc

    def run_active_response(
        self,
        *,
        command_id: str,
        agent_id: str,
    ) -> Dict[str, Any]:
        """Dispatch one configured Active Response command to one agent.

        Args:
            command_id: Preconfigured Wazuh command identifier.
            agent_id: Exact numeric Wazuh agent identifier.

        Returns:
            Decoded Wazuh API dispatch response.

        Raises:
            WazuhError: If identifiers are unsafe or dispatch fails.
        """

        command = str(command_id).strip()
        agent = str(agent_id).strip()
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}", command):
            raise WazuhError("Active Response command is not allow-list compatible.")
        if not re.fullmatch(r"\d{3,}", agent) or agent == "000":
            raise WazuhError("Active Response requires one non-manager agent ID.")
        return self.put(
            "/active-response",
            params={"agents_list": agent},
            payload={"command": command, "arguments": []},
        )

    @property
    def connector_id(self) -> str:
        """Return a non-secret stable API/Indexer endpoint identity.

        Returns:
            SHA-256 identifier; credentials are excluded.
        Raises:
            No expected exceptions.
        """
        return configured_connector_id()

    def list_agents(
        self, limit: int = 500, *, agent_ids: list[str] | None = None
    ) -> List[Dict[str, Any]]:
        """Read only explicitly authorized agents, with bounded pagination.

        Args:
            limit: Page size, capped at 500.
            agent_ids: Workspace-bound agent IDs; None/empty fetches nothing.
        Returns:
            Complete matching agent records or an empty list.
        Raises:
            WazuhError: On partial, malformed or inconsistent responses.
        """
        identities = sorted(set(agent_ids or []))
        if any(not re.fullmatch(r"[0-9]{3,}", value) or value == "000" for value in identities):
            raise WazuhError("Use exact non-manager agent IDs.")
        rows = []
        page_size = max(1, min(int(limit), 500))
        for start in range(0, len(identities), 100):
            allowed = identities[start : start + 100]
            offset = 0
            while True:
                payload = self.get(
                    "/agents",
                    params={
                        "agents_list": ",".join(allowed),
                        "limit": page_size,
                        "offset": offset,
                        "sort": "+id",
                    },
                )
                data = payload.get("data") or {}
                if not isinstance(data, dict):
                    raise WazuhError("Wazuh returned an invalid agent response.")
                page = data.get("affected_items") or []
                total = data.get("total_affected_items")
                if (
                    payload.get("error")
                    or data.get("total_failed_items")
                    or not isinstance(total, int)
                    or not isinstance(page, list)
                    or total > len(allowed)
                    or total < 0
                    or any(
                        not isinstance(a, dict) or str(a.get("id", "")) not in allowed for a in page
                    )
                    or offset + len(page) > total
                ):
                    raise WazuhError("Wazuh returned incomplete or unauthorized agent data.")
                rows.extend(page)
                offset += len(page)
                if offset >= total:
                    break
                if not page or offset > len(allowed):
                    raise WazuhError("Wazuh agent pagination was incomplete.")
        return rows

    def search_last_alert_for_agent(self, *, agent_id: str, manager_name: str) -> dict:
        """Read the latest relevant event for one explicitly bound source identity.

        Args:
            agent_id: Exact authorized agent ID.
            manager_name: Exact administrator-bound manager name.
        Returns:
            Minimal authenticated event metadata, or {} when there are no alerts.
        Raises:
            WazuhError: On missing configuration, source failure or identity mismatch.
        """
        self._admit_request()
        if not re.fullmatch(r"[0-9]{3,}", agent_id) or agent_id == "000" or not manager_name:
            raise WazuhError("An exact manager and endpoint agent are required.")
        endpoint = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
        user = os.getenv("WAZUH_INDEXER_USER", "")
        password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
        if not all((endpoint, user, password)):
            raise WazuhTelemetryNotConfigured("Indexer not configured; telemetry is not verified.")
        pattern = os.getenv("WAZUH_INDEXER_ALERT_INDEX", "wazuh-alerts-*")
        if not re.fullmatch(r"[A-Za-z0-9_.*-]+", pattern):
            raise WazuhError("Invalid alert index pattern.")
        query = {
            "size": 1,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": ["agent.id", "manager.name", "timestamp", "rule.id", "rule.level"],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"agent.id": agent_id}},
                        {"term": {"manager.name": manager_name}},
                        {"exists": {"field": "rule.id"}},
                    ]
                }
            },
        }
        try:
            response = requests.post(
                f"{endpoint}/{pattern}/_search",
                json=query,
                auth=HTTPBasicAuth(user, password),
                verify=env_bool("WAZUH_INDEXER_VERIFY_TLS", True),
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                raise WazuhError(
                    f"Indexer query failed: HTTP {response.status_code}",
                    retry_after=getattr(response, "headers", {}).get("Retry-After", "0"),
                )
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise WazuhError("Indexer query or response decoding failed.") from exc
        if not isinstance(payload, dict):
            raise WazuhError("Indexer returned an invalid response shape.")
        if not isinstance(payload.get("_shards", {}), dict) or not isinstance(
            payload.get("hits", {}), dict
        ):
            raise WazuhError("Indexer returned an invalid search response.")
        if payload.get("timed_out") or (payload.get("_shards") or {}).get("failed"):
            raise WazuhError("Indexer search was incomplete.")
        hits = (payload.get("hits") or {}).get("hits")
        if not isinstance(hits, list):
            raise WazuhError("Indexer returned an invalid search response.")
        if not hits:
            return {}
        hit = hits[0]
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            raise WazuhError("Indexer returned an invalid event shape.")
        source = hit["_source"]
        if any(not isinstance(source.get(key), dict) for key in ("agent", "manager", "rule")):
            raise WazuhError("Indexer returned invalid event identity fields.")
        if (
            str((source.get("agent") or {}).get("id")) != agent_id
            or (source.get("manager") or {}).get("name") != manager_name
            or not hit.get("_id")
            or not hit.get("_index")
        ):
            raise WazuhError("Indexer response did not match the bound agent identity.")
        return {
            "authenticated": env_bool("WAZUH_INDEXER_VERIFY_TLS", True),
            "kind": "security_event",
            "agent_id": agent_id,
            "manager_name": manager_name,
            "source_event_id": f"{hit['_index']}:{hit['_id']}",
            "observed_at": source.get("timestamp"),
            "rule_id": str((source.get("rule") or {}).get("id") or ""),
            "rule_level": (source.get("rule") or {}).get("level"),
        }

    def test_connection(self) -> Dict[str, Any]:
        """Authenticate without retrieving other clients' agent inventories.

        Returns:
            A timestamped connection result without tokens or agent data.
        Raises:
            WazuhError: If authentication fails.
        """
        self.authenticate()
        return {"ok": True, "checked_at": datetime.now(timezone.utc).isoformat()}


def normalize_agent(agent: Dict[str, Any]) -> Dict[str, Any]:
    os_info = agent.get("os") or {}
    if not isinstance(os_info, dict):
        os_info = {}
    group = agent.get("group")

    if isinstance(group, list):
        group_text = ", ".join(str(x) for x in group)
    else:
        group_text = str(group or "")

    return {
        "agent_id": str(agent.get("id", "")),
        "agent_name": str(agent.get("name", "")),
        "agent_ip": str(agent.get("ip", "")),
        "status": str(agent.get("status", "")),
        "last_keep_alive": agent.get("lastKeepAlive"),
        "date_added": agent.get("dateAdd"),
        "manager": agent.get("manager"),
        "group": group_text,
        "os_name": os_info.get("name"),
        "os_version": os_info.get("version"),
        "os_platform": os_info.get("platform"),
        "os_arch": os_info.get("arch"),
        "raw": agent,
    }


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def asset_ip(asset: Dict[str, Any]) -> str:
    return str(asset.get("ip") or asset.get("ip_address") or asset.get("address") or "").strip()


def asset_hostname(asset: Dict[str, Any]) -> str:
    return str(asset.get("hostname") or asset.get("name") or asset.get("asset_name") or "").strip()


def build_os_label(agent: Optional[Dict[str, Any]]) -> Optional[str]:
    if not agent:
        return None

    parts = [
        agent.get("os_name"),
        agent.get("os_version"),
        agent.get("os_arch"),
    ]
    return " ".join(str(p) for p in parts if p)


def monitoring_status(agent: Optional[Dict[str, Any]]) -> str:
    """Describe agent availability without claiming verified monitoring.

    Args:
        agent: Normalized source agent or None.
    Returns:
        Conservative display label.
    Raises:
        No expected exceptions.
    """
    if not agent:
        return "Monitoring not verified"
    status = normalize_text(agent.get("status"))
    if status == "active":
        return "Agent active — telemetry unverified"
    if status == "disconnected":
        return "Agent disconnected"
    if status in {"pending", "never_connected"}:
        return "Agent registered — not active"
    return "Monitoring not verified"


def match_agents_to_assets(
    assets: Iterable[Dict[str, Any]],
    agents: Iterable[Dict[str, Any]],
    include_unmatched_agents: bool = False,
    *,
    bindings: Iterable[dict] = (),
) -> List[Dict[str, Any]]:
    """Resolve exact approved bindings; other exact matches are candidates only.

    Args:
        assets: Inventory already restricted to the active workspace.
        agents: Agent records fetched using that workspace's authorized IDs.
        include_unmatched_agents: Legacy argument; unmatched agents are not published.
        bindings: Administrator-approved records for this workspace/connector.
    Returns:
        One row per inventory asset; no fuzzy or ambiguous verified identity.
    Raises:
        No expected exceptions for repository-shaped dictionaries.
    """
    inventory = list(assets)
    normalized = [normalize_agent(a) for a in agents]
    binding_list = list(bindings)
    counts = Counter(a.get("agent_id") for a in normalized)
    asset_counts = Counter(a.get("id") or a.get("asset_id") for a in inventory)
    rows = []
    for asset in inventory:
        identity = asset.get("id") or asset.get("asset_id")
        approved = [b for b in binding_list if b["asset_id"] == identity]
        candidates = []
        if len(approved) == 1:
            binding = approved[0]
            candidates = [
                a
                for a in normalized
                if a["agent_id"] == binding["agent_id"]
                and a.get("manager") == binding["manager_name"]
            ]
        else:
            binding = {}
        verified = bool(
            len(candidates) == 1
            and counts[candidates[0]["agent_id"]] == 1
            and asset_counts[identity] == 1
        )
        agent = candidates[0] if verified else None
        if not binding:
            exact = [
                a
                for a in normalized
                if (asset_ip(asset) and a["agent_ip"] == asset_ip(asset))
                or (
                    asset_hostname(asset)
                    and normalize_text(a["agent_name"]) == normalize_text(asset_hostname(asset))
                )
            ]
            match_type = "candidate" if len(exact) == 1 else "ambiguous" if exact else "none"
        else:
            match_type = "binding" if verified else "ambiguous" if candidates else "none"
        rows.append(
            {
                "asset_id": identity,
                "asset_tag": asset.get("asset_tag"),
                "asset_ip": asset_ip(asset),
                "asset_hostname": asset_hostname(asset),
                "match_type": match_type,
                "identity_verified": verified,
                "monitoring_status": monitoring_status(agent),
                "wazuh_agent_id": agent["agent_id"] if agent else binding.get("agent_id"),
                "wazuh_agent_name": agent.get("agent_name") if agent else None,
                "wazuh_agent_ip": agent.get("agent_ip") if agent else None,
                "wazuh_status": agent.get("status") if agent else "unknown",
                "wazuh_last_keep_alive": agent.get("last_keep_alive") if agent else None,
                "wazuh_os": build_os_label(agent),
                "wazuh_group": agent.get("group") if agent else None,
                "binding_id": binding.get("id"),
                "connector_id": binding.get("connector_id"),
                "manager_name": binding.get("manager_name"),
                "heartbeat_max_age_seconds": binding.get("heartbeat_max_age_seconds"),
                "telemetry_max_age_seconds": binding.get("telemetry_max_age_seconds"),
            }
        )
    return rows


def iso_monitoring_evidence(monitoring_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize technical coverage without generating an ISO assessment.

    Args:
        monitoring_rows: Workspace inventory monitoring facts.
    Returns:
        Coverage counts and an explicit non-assessment summary.
    Raises:
        ValueError: For invalid evaluation timestamps.
    """
    rows = [r for r in monitoring_rows if r.get("asset_id")]
    verified = sum(evaluate_monitoring(r)["monitoring_state"] == "verified" for r in rows)
    return {
        "control_id": "A.8.16",
        "control_name": "Monitoring activities",
        "status": (
            "Current evidence"
            if rows and verified == len(rows)
            else "Partial coverage" if verified else "Not verified"
        ),
        "total_assets": len(rows),
        "monitored_assets": verified,
        "evidence": f"{verified}/{len(rows)} inventory assets have verified monitoring telemetry. "
        "Inventory coverage is not approved-scope coverage or a human ISO assessment.",
    }


build_iso_evidence_from_wazuh = iso_monitoring_evidence
