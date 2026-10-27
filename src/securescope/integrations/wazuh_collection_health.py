"""Read-only, exact-source collection-health proof; never installs or executes probes."""

import fnmatch
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from requests.auth import HTTPBasicAuth

from securescope.integrations.wazuh_monitoring import observation_time


def retry_delay(value, *, now=None):
    """Return a 0–300 second Retry-After delay for seconds or HTTP dates; invalid values return zero."""
    try:
        return min(300, max(0, float(value)))
    except (TypeError, ValueError):
        try:
            stamp = parsedate_to_datetime(str(value))
            return min(300, max(0, (stamp - (now or datetime.now(timezone.utc))).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return 0


class CollectionFailure(RuntimeError):
    """Carry a credential-safe error code and bounded retry decision.

    Args:
        code: Safe internal category; retryable: Transient status; retry_after: Delay hint.
    """

    def __init__(self, code, *, retryable=False, retry_after=0):
        """Initialize safe diagnostics; return None; raise ValueError for malformed delay."""
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.retry_after = retry_delay(retry_after)


def policy_hash(policy):
    """Hash a non-secret policy dictionary; return SHA-256; raise TypeError for invalid JSON."""
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_health_policy(policy):
    """Validate the fixed, read-only archive contract.

    Args:
        policy: Reviewed channel, index pattern, mode, age and schema version.
    Returns:
        None.
    Raises:
        ValueError: For unknown fields, unsafe index names or unsupported modes.
    """
    if (
        not isinstance(policy, dict)
        or set(policy) != {"schema_version", "mode", "index_pattern", "channel", "max_age_seconds"}
        or policy["schema_version"] != 1
        or policy["mode"] not in {"archive", "canary"}
        or not re.fullmatch(r"[A-Za-z0-9_.-]+\*?", str(policy["index_pattern"]))
        or policy["index_pattern"] in {"*", "."}
        or not isinstance(policy["channel"], str)
        or not 1 <= len(policy["channel"]) <= 512
        or type(policy["max_age_seconds"]) is not int
        or not 1 <= policy["max_age_seconds"] <= 86400
    ):
        raise ValueError("Unsupported collection-health policy.")


def validate_hit(hit, policy, *, agent_id, manager_name, now=None):
    """Validate an archive hit independently of query filters; retain only allowlisted facts.

    Args:
        hit: Indexer document; policy: Approved contract; agent_id, manager_name: Exact binding.
        now: Aware validation time.
    Returns:
        Minimal verifiable health observation.
    Raises:
        CollectionFailure: On malformed, foreign, stale or future-dated facts.
        ValueError: On invalid policy.
    """
    validate_health_policy(policy)
    now = observation_time(now or datetime.now(timezone.utc))
    source = hit.get("_source") if isinstance(hit, dict) else None
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("agent"), dict)
        or not isinstance(source.get("manager"), dict)
        or source["agent"].get("id") != agent_id
        or source["manager"].get("name") != manager_name
        or source.get("location") != policy["channel"]
        or not hit.get("_id")
        or not fnmatch.fnmatchcase(str(hit.get("_index", "")), policy["index_pattern"])
    ):
        raise CollectionFailure("health_identity_mismatch")
    received = observation_time(source.get("timestamp"))
    observed, event_id, sequence = received, f"{hit['_index']}:{hit['_id']}", None
    if policy["mode"] == "canary":
        data = source.get("data") or {}
        canary = data.get("securescope_health") if isinstance(data, dict) else None
        if (
            not isinstance(canary, dict)
            or canary.get("version") != 1
            or canary.get("channel") != policy["channel"]
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", str(canary.get("event_id", "")))
            or type(canary.get("sequence")) is not int
            or canary["sequence"] < 1
        ):
            raise CollectionFailure("invalid_canary")
        observed = observation_time(canary.get("observed_at"))
        event_id, sequence = "canary:" + canary["event_id"], canary["sequence"]
    if (
        not now
        or not observed
        or not received
        or observed > received
        or received > now
        or (now - observed).total_seconds() >= policy["max_age_seconds"]
    ):
        raise CollectionFailure("health_timestamp_invalid")
    return dict(
        authenticated=True,
        kind="collection_health",
        healthy=True,
        collection_verified=True,
        agent_id=agent_id,
        manager_name=manager_name,
        source_event_id=event_id,
        observed_at=observed.isoformat(),
        received_at=received.isoformat(),
        health_contract_version=1,
        policy_sha256=policy_hash(policy),
        channel=policy["channel"],
        mode=policy["mode"],
        sequence=sequence,
        index=hit["_index"],
        document_id=hit["_id"],
    )


def acquire_health(client, binding, policy):
    """Query one approved source channel without returning raw logs or secrets.

    Args:
        client: Existing Wazuh client; binding: Approved manager/agent; policy: Reviewed contract.
    Returns:
        Valid health observation, or an empty dictionary when no proof exists.
    Raises:
        CollectionFailure: On missing configuration, failed request or invalid response.
    """
    validate_health_policy(policy)
    endpoint = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
    user, password = os.getenv("WAZUH_INDEXER_USER", ""), os.getenv("WAZUH_INDEXER_PASSWORD", "")
    if not endpoint or not user or not password:
        raise CollectionFailure("health_not_configured")
    if (
        not endpoint.startswith("https://")
        or os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").lower() != "true"
        or not client.verify_tls
    ):
        raise CollectionFailure("tls_verification_required")
    query = dict(
        size=1,
        sort=[{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        _source=["agent.id", "manager.name", "timestamp", "location", "data.securescope_health"],
        query={
            "bool": {
                "filter": [
                    {"term": {"agent.id": binding["agent_id"]}},
                    {"term": {"manager.name": binding["manager_name"]}},
                    {"term": {"location": policy["channel"]}},
                ]
            }
        },
    )
    if getattr(client, "before_request", None) is not None:
        client.before_request()
    try:
        with requests.post(
            f"{endpoint}/{policy['index_pattern']}/_search",
            json=query,
            auth=HTTPBasicAuth(user, password),
            verify=True,
            timeout=min(client.timeout, 30),
            stream=True,
        ) as response:
            if response.status_code >= 400:
                transient = response.status_code == 429 or response.status_code in {
                    500,
                    502,
                    503,
                    504,
                }
                raise CollectionFailure(
                    f"health_http_{response.status_code}",
                    retryable=transient,
                    retry_after=retry_delay(response.headers.get("Retry-After", "0")),
                )
            content = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                content.extend(chunk)
                if len(content) > 256_000:
                    raise CollectionFailure("health_response_too_large")
            payload = json.loads(content)
    except requests.exceptions.SSLError as exc:
        raise CollectionFailure("tls_verification_failed") from exc
    except requests.RequestException as exc:
        raise CollectionFailure("health_transport", retryable=True) from exc
    except ValueError as exc:
        raise CollectionFailure("health_invalid_json") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("_shards"), dict)
        or not isinstance(payload.get("hits"), dict)
        or payload.get("timed_out")
        or payload["_shards"].get("failed")
        or not isinstance(payload["hits"].get("hits"), list)
    ):
        raise CollectionFailure("health_incomplete_response", retryable=True)
    hits = payload["hits"]["hits"]
    if not hits:
        return {}
    return validate_hit(
        hits[0], policy, agent_id=binding["agent_id"], manager_name=binding["manager_name"]
    )
