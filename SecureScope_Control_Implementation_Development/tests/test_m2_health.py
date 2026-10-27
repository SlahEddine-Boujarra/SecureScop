"""Quiet-agent proof, protection and conservative freshness regression tests."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import requests
from cryptography.fernet import Fernet

from securescope.evidence import storage
from securescope.evidence.automated_checks import usable_evidence
from securescope.evidence.wazuh_bridge import normalized_source
from securescope.evidence.wazuh_scheduled import classify_error
from securescope.integrations import wazuh_collection_health as health
from securescope.integrations.wazuh_monitoring import evaluate_monitoring
from securescope.integrations.wazuh_service import WazuhError
from tests.test_wazuh_monitoring import snapshot

NOW = datetime(2026, 10, 19, 8, tzinfo=timezone.utc)
POLICY = dict(
    schema_version=1,
    mode="canary",
    index_pattern="wazuh-archives-*",
    channel="/var/log/health",
    max_age_seconds=120,
)


def hit():
    """Return a minimal synthetic indexed source document."""
    return dict(
        _index="wazuh-archives-test",
        _id="document-1",
        _source=dict(
            agent=dict(id="007"),
            manager=dict(name="manager"),
            timestamp=NOW.isoformat(),
            location=POLICY["channel"],
            data=dict(
                securescope_health=dict(
                    version=1,
                    channel=POLICY["channel"],
                    event_id="test-event-000001",
                    sequence=1,
                    observed_at=NOW.isoformat(),
                )
            ),
        ),
    )


def validate(document, policy=None):
    """Validate a synthetic source at a fixed clock using the public adapter contract."""
    return health.validate_hit(
        document, policy or POLICY, agent_id="007", manager_name="manager", now=NOW
    )


@pytest.mark.parametrize(
    "path,value",
    [
        (("agent", "id"), "008"),
        (("manager", "name"), "foreign"),
        (("location",), "other"),
        (("timestamp",), (NOW + timedelta(seconds=1)).isoformat()),
        (("data", "securescope_health", "observed_at"), (NOW - timedelta(seconds=120)).isoformat()),
        (("data", "securescope_health", "observed_at"), (NOW + timedelta(seconds=1)).isoformat()),
        (("data", "securescope_health", "sequence"), 0),
        (("data", "securescope_health", "version"), 2),
        (("data", "securescope_health", "event_id"), "short"),
        (("data", "securescope_health", "channel"), "other"),
    ],
)
def test_health_rejects_foreign_malformed_future_and_stale(path, value):
    """Query filters alone never establish identity or freshness."""
    document = hit()
    source = document["_source"]
    for part in path[:-1]:
        source = source[part]
    source[path[-1]] = value
    with pytest.raises(health.CollectionFailure):
        validate(document)


def test_health_only_proves_approved_path_and_expires_at_source_time():
    """Health proof covers monitoring only; polling does not extend the source deadline."""
    telemetry = validate(hit())
    row = snapshot(
        id=1,
        m2_collection=True,
        collected_at=NOW,
        wazuh_last_keep_alive=NOW,
        telemetry=telemetry,
        health_policy_sha256=health.policy_hash(POLICY),
        health_max_age_seconds=120,
    )
    assert evaluate_monitoring(row, now=NOW)["monitoring_state"] == "verified"
    assert normalized_source(row, "logging", now=NOW) is None
    assert normalized_source(row, "monitoring", now=NOW)
    refreshed = dict(
        row,
        collected_at=NOW + timedelta(seconds=120),
        wazuh_last_keep_alive=NOW + timedelta(seconds=120),
    )
    assert (
        evaluate_monitoring(refreshed, now=NOW + timedelta(seconds=120))["monitoring_state"]
        == "stale"
    )
    assert (
        evaluate_monitoring(dict(row, telemetry={}), now=NOW)["monitoring_state"]
        == "active_unverified"
    )
    forged = dict(row, telemetry=dict(telemetry, health_contract_version=0))
    assert evaluate_monitoring(forged, now=NOW)["monitoring_state"] == "active_unverified"


def test_archive_has_receipt_time_and_no_invented_endpoint_timestamp():
    """Natural archive proof explicitly identifies its receipt timestamp semantics."""
    proof = validate(hit(), dict(POLICY, mode="archive"))
    assert proof["observed_at"] == proof["received_at"]
    assert proof["sequence"] is None
    assert proof["source_event_id"] == "wazuh-archives-test:document-1"


@pytest.mark.parametrize(
    "policy",
    [
        dict(POLICY, index_pattern="*"),
        dict(POLICY, index_pattern="../secret"),
        dict(POLICY, max_age_seconds=True),
        dict(POLICY, command="anything"),
    ],
)
def test_policy_is_bounded_and_not_an_execution_language(policy):
    """Only fixed read-only health contracts are accepted."""
    with pytest.raises(ValueError):
        health.validate_health_policy(policy)


@pytest.mark.parametrize(
    "status,retry", [(401, False), (403, False), (429, True), (500, True), (503, True)]
)
def test_api_error_categories_are_safe_and_bounded(status, retry):
    """Only supported transient HTTP failures can retry."""
    failure = classify_error(WazuhError(f"Wazuh API failed: HTTP {status}"))
    assert failure.retryable is retry
    assert str(failure) == f"wazuh_http_{status}"


def test_tls_failure_is_not_retried():
    """A certificate failure never degrades to an unauthenticated collection."""
    error = WazuhError("Request failed")
    error.__cause__ = requests.exceptions.SSLError("secret certificate details")
    failure = classify_error(error)
    assert failure.code == "tls_verification_failed"
    assert not failure.retryable


def test_protected_artifacts_fail_closed_and_preserve_legacy_reads(tmp_path, monkeypatch):
    """Encryption, tenant path and expected SHA are independently enforced."""
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_STORAGE_ROOT", str(tmp_path))
    monkeypatch.delenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", raising=False)
    with pytest.raises(storage.EvidenceStorageError):
        storage.store_protected_artifact(1, "proof.json", b"{}")
    legacy = storage.store_artifact(1, "legacy.txt", b"legacy")
    assert (
        storage.read_artifact(1, legacy.storage_reference, expected_sha256=legacy.sha256)
        == b"legacy"
    )
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", Fernet.generate_key().decode())
    artifact = storage.store_protected_artifact(1, "proof.json", b'{"fact":true}')
    path = tmp_path / artifact.storage_reference
    assert b"fact" not in path.read_bytes()
    assert (
        storage.read_artifact(1, artifact.storage_reference, expected_sha256=artifact.sha256)
        == b'{"fact":true}'
    )
    with pytest.raises(storage.EvidenceStorageError):
        storage.read_artifact(2, artifact.storage_reference)
    with pytest.raises(storage.EvidenceStorageError):
        storage.read_artifact(1, artifact.storage_reference, expected_sha256="0" * 64)
    path.write_bytes(path.read_bytes()[:-1] + b"X")
    with pytest.raises(storage.EvidenceStorageError):
        storage.read_artifact(1, artifact.storage_reference, expected_sha256=artifact.sha256)


def test_legacy_health_boolean_does_not_gain_m2_assurance():
    """A historical health boolean cannot acquire the new source-backed contract."""
    now = datetime.now(timezone.utc)
    row = snapshot(
        id=1,
        collected_at=now,
        wazuh_last_keep_alive=now,
        telemetry=dict(
            authenticated=True,
            kind="collection_health",
            agent_id="007",
            manager_name="manager",
            source_event_id="old",
            observed_at=now,
            healthy=True,
            collection_verified=True,
        ),
    )
    payload, _ = normalized_source(row, "monitoring", now=now)
    assert not usable_evidence(
        dict(
            tool_id="wazuh",
            validation_status="Validated",
            verification_origin="System collector",
            consultant_approved=True,
            normalized_payload=payload,
        ),
        {"wazuh"},
    )


@pytest.mark.parametrize("status,retry", [(401, False), (403, False), (429, True), (503, True)])
def test_health_adapter_classifies_http_and_caps_retry(monkeypatch, status, retry):
    """The actual adapter respects safe Retry-After and never logs response bodies."""
    from unittest.mock import MagicMock

    response = MagicMock(status_code=status, headers={"Retry-After": "99999"})
    response.__enter__.return_value = response
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.invalid")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "fixture")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "fixture")
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "true")
    post = MagicMock(return_value=response)
    monkeypatch.setattr(health.requests, "post", post)
    with pytest.raises(health.CollectionFailure) as caught:
        health.acquire_health(
            SimpleNamespace(verify_tls=True, timeout=30),
            dict(agent_id="007", manager_name="manager"),
            POLICY,
        )
    assert caught.value.retryable is retry
    assert caught.value.retry_after == 300
    assert post.call_args.kwargs["stream"] is True


def test_retry_after_http_date_is_respected():
    """HTTP-date Retry-After is bounded relative to an explicit clock."""
    from email.utils import format_datetime

    assert health.retry_delay(format_datetime(NOW + timedelta(seconds=90)), now=NOW) == 90
    assert health.retry_delay("invalid", now=NOW) == 0
    assert health.retry_delay(-1, now=NOW) == 0


def test_adapter_rejects_oversized_response_before_publication(monkeypatch):
    """A health source response has a real byte bound while streaming."""
    from unittest.mock import MagicMock

    response = MagicMock(status_code=200)
    response.__enter__.return_value = response
    response.iter_content.return_value = iter([b"x" * 8192] * 40)
    for key, value in {
        "WAZUH_INDEXER_URL": "https://indexer.invalid",
        "WAZUH_INDEXER_USER": "fixture",
        "WAZUH_INDEXER_PASSWORD": "fixture",
        "WAZUH_INDEXER_VERIFY_TLS": "true",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(health.requests, "post", lambda *args, **kwargs: response)
    with pytest.raises(health.CollectionFailure, match="too_large"):
        health.acquire_health(
            SimpleNamespace(verify_tls=True, timeout=30),
            dict(agent_id="007", manager_name="manager"),
            POLICY,
        )
