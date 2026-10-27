"""Persistence and orchestration boundaries for tenant-owned Wazuh facts."""

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from securescope.integrations import wazuh_collection as collector
from securescope.integrations import wazuh_service as service
from securescope.persistence import db_wazuh_service as repository
from tests.test_wazuh_monitoring import snapshot
from tests.test_wazuh_monitoring_connector import binding


@pytest.mark.parametrize("name,result", [("", None), ("Missing", None)])
def test_read_unknown_workspace_never_creates_it(name, result):
    """A missing tenant fails without an upsert or implicit Default Client."""
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = result
    with pytest.raises(repository.WazuhDatabaseError):
        repository.existing_client_id(connection, name)
    assert all(call.args[0].startswith("SELECT") for call in cursor.execute.call_args_list)


@pytest.mark.parametrize(
    "revoked,connector,state",
    [
        (None, "connector", "verified"),
        (datetime.now(timezone.utc), "connector", "not_verified"),
        (None, "changed", "not_verified"),
    ],
)
def test_source_revocation_or_connector_change_invalidates_current_proof(
    monkeypatch, revoked, connector, state
):
    """Historical observations remain stored but stop counting after identity changes."""
    now = datetime.now(timezone.utc)
    row = snapshot(wazuh_last_keep_alive=now)
    row["telemetry"]["observed_at"] = now
    cursor = MagicMock()
    cursor.fetchall.return_value = [
        dict(
            payload=row,
            id=1,
            source_key="key",
            payload_sha256="a" * 64,
            collected_at=now,
            revoked_at=revoked,
        )
    ]
    monkeypatch.setattr(service, "configured_connector_id", lambda: connector)
    assert repository.load_monitoring_rows(cursor, 1)[0]["monitoring_state"] == state
    assert cursor.fetchall.return_value[0]["payload"]["identity_verified"] is True


@pytest.fixture
def collection(monkeypatch):
    """Isolate external services while exercising the real collection orchestration."""
    from securescope.evidence import wazuh_bridge

    now = datetime.now(timezone.utc)
    client = MagicMock(connector_id="source", verify_tls=True)
    client.list_agents.return_value = [
        {
            "id": "007",
            "manager": "manager",
            "status": "active",
            "lastKeepAlive": now,
            "ip": "192.0.2.1",
        }
    ]
    event = snapshot()["telemetry"]
    event["observed_at"] = now
    client.search_last_alert_for_agent.return_value = event
    monkeypatch.setattr(collector, "WazuhClient", lambda: client)
    start = MagicMock(return_value=11)
    finish = MagicMock()
    ingest = MagicMock(return_value=[42])
    monkeypatch.setattr(collector, "start_monitoring_collection", start)
    monkeypatch.setattr(collector, "finish_monitoring_collection", finish)
    monkeypatch.setattr(collector, "list_monitoring_bindings", lambda *a: [binding()])
    monkeypatch.setattr(collector, "existing_client_id", lambda *a: 1)
    monkeypatch.setattr(collector, "load_latest_wazuh_status", lambda *a: [])
    monkeypatch.setattr(wazuh_bridge, "ingest_wazuh_evidence", ingest)
    cursor = MagicMock()
    cursor.fetchall.return_value = [{"id": 1, "ip": "192.0.2.1", "asset_tag": "TEST"}]
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    @contextmanager
    def connect():
        yield connection

    monkeypatch.setattr(collector, "connect", connect)
    return client, start, finish, ingest


def test_unauthorized_collection_fails_before_network(collection):
    """Workspace permission is checked before any outbound collection."""
    client, start, finish, ingest = collection
    start.side_effect = repository.WazuhDatabaseError("Not authorized")
    with pytest.raises(repository.WazuhDatabaseError):
        collector.collect_monitoring("Workspace", "viewer")
    client.list_agents.assert_not_called()
    finish.assert_not_called()
    ingest.assert_not_called()


def test_foreign_collection_origin_fails_before_network(collection):
    """A context from another workspace cannot trigger collection in this one."""
    client, start, _, _ = collection
    with pytest.raises(service.WazuhError):
        collector.collect_monitoring("Workspace", "consultant", {"client": "Other"})
    start.assert_not_called()
    client.list_agents.assert_not_called()


def test_bound_collection_persists_before_canonical_ingestion(collection):
    """Only bound IDs are requested; source facts precede canonical evidence."""
    client, _, finish, ingest = collection
    parent = MagicMock()
    parent.attach_mock(finish, "finish")
    parent.attach_mock(ingest, "ingest")
    result = collector.collect_monitoring("Workspace", "consultant")
    assert result["outcome"] == "succeeded"
    assert result["rows"][0]["monitoring_state"] == "verified"
    client.list_agents.assert_called_once_with(agent_ids=["007"])
    assert [call[0] for call in parent.mock_calls] == ["finish", "ingest"]


def test_failed_api_keeps_history_but_disqualifies_current_evidence(collection, monkeypatch):
    """An outage preserves prior event identity without claiming current verification."""
    client, _, finish, _ = collection
    now = datetime.now(timezone.utc)
    old = snapshot(asset_id=1, binding_id=1, connector_id="source", wazuh_last_keep_alive=now)
    old["telemetry"]["observed_at"] = now
    monkeypatch.setattr(collector, "load_latest_wazuh_status", lambda *a: [old])
    client.list_agents.side_effect = service.WazuhError("Unavailable")
    result = collector.collect_monitoring("Workspace", "consultant")
    row = result["rows"][0]
    assert result["outcome"] == "failed"
    assert row["monitoring_state"] == "source_unavailable"
    assert row["telemetry"]["source_event_id"] == old["telemetry"]["source_event_id"]
    assert finish.call_args.args[4] == "failed"
    client.search_last_alert_for_agent.assert_not_called()


def test_current_source_metrics_do_not_make_iso_conclusions():
    """Legacy active-only rows do not imply logging or monitoring implementation."""
    from securescope.compliance.iso_control_assessment_service import (
        build_environment_metrics,
        evaluate_a8_controls,
    )

    assets = [{"ip": "192.0.2.1"}]
    rows = [{"asset_ip": "192.0.2.1", "monitoring_status": "Monitored", "wazuh_status": "active"}]
    assert build_environment_metrics(assets, [], rows)["wazuh_coverage"] == 0
    assessments = evaluate_a8_controls(assets, [], rows)
    for item in assessments:
        if item["control_id"] in {"A.8.15", "A.8.16"}:
            assert item["automated_status"] == "Not verified"
            assert item["score"] is None
            assert item["assessment_basis"] == "Source coverage"


def test_repeat_collection_keeps_stable_source_identity(monkeypatch):
    """Changing only retrieval time does not manufacture a different source snapshot."""
    from securescope.persistence import evidence_repository

    cursor = MagicMock()
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    @contextmanager
    def connect():
        yield connection

    monkeypatch.setattr(repository, "connect", connect)
    monkeypatch.setattr(repository, "existing_client_id", lambda *a: 1)
    monkeypatch.setattr(repository, "_monitoring_actor", lambda *a, **k: None)
    monkeypatch.setattr(evidence_repository, "_append_audit_event", MagicMock())
    bound = dict(binding(), id=4, asset_id=7)
    row = snapshot(connector_id="source")
    keys = []
    for run_id in (11, 12):
        cursor.reset_mock()
        cursor.fetchone.side_effect = [
            dict(outcome="running", connector_id="source"),
            bound,
            {"id": 9},
        ]
        row["collected_at"] = datetime.now(timezone.utc)
        repository.finish_monitoring_collection(
            "Workspace", "consultant", run_id, [row], "succeeded"
        )
        insert = next(
            c
            for c in cursor.execute.call_args_list
            if c.args[0].startswith("INSERT INTO securescope_wazuh_observations")
        )
        keys.append(insert.args[1][3:5])
    assert keys[0] == keys[1]
    assert len(keys[0][1]) == 64
    cursor.reset_mock()
    cursor.fetchone.side_effect = [dict(outcome="succeeded", connector_id="source")]
    repository.finish_monitoring_collection("Workspace", "consultant", 12, [row], "succeeded")
    assert all(c.args[0].startswith("SELECT") for c in cursor.execute.call_args_list)
    cursor.reset_mock()
    cursor.fetchone.side_effect = [dict(outcome="running", connector_id="source"), None]
    with pytest.raises(repository.WazuhDatabaseError, match="unauthorized"):
        repository.finish_monitoring_collection("Workspace", "consultant", 13, [row], "succeeded")
    assert all(c.args[0].startswith("SELECT") for c in cursor.execute.call_args_list)


def test_human_review_survives_legacy_monitoring_disqualification():
    """Re-evaluation changes the source summary, not an existing human conclusion."""
    from securescope.compliance.iso_control_assessment_service import (
        add_maturity,
        evaluate_a8_controls,
        merge_reviews,
    )

    assessments = evaluate_a8_controls([], [], [])
    reviews = {
        "A.8.16": dict(
            applicability="Applicable",
            validated_status="Implemented",
            reviewed_by="consultant",
            evidence_notes="Existing approved decision",
        )
    }
    merged = add_maturity(merge_reviews(assessments, reviews))
    monitoring = next(row for row in merged if row["control_id"] == "A.8.16")
    assert monitoring["final_status"] == "Implemented"
    assert monitoring["automated_status"] == "Not verified"
    assert monitoring["Maturity"] == "Human assessment required"
    assert monitoring["Score"] is None
