"""HTTP and identity contracts using synthetic records and mocked transports."""

from unittest.mock import MagicMock

import pytest

from securescope.integrations import wazuh_service as service


@pytest.fixture
def client(monkeypatch):
    """Create a configured connector without reading secrets or contacting a service."""
    monkeypatch.setattr(service, "restore_wazuh_settings", lambda: None)
    for key, value in {
        "WAZUH_API_URL": "https://manager.invalid:55000",
        "WAZUH_API_PASSWORD": "test",
        "WAZUH_INDEXER_URL": "https://indexer.invalid:9200",
        "WAZUH_INDEXER_USER": "test",
        "WAZUH_INDEXER_PASSWORD": "test",
        "WAZUH_VERIFY_TLS": "true",
        "WAZUH_INDEXER_VERIFY_TLS": "true",
    }.items():
        monkeypatch.setenv(key, value)
    return service.WazuhClient()


def test_unbound_collection_does_not_fetch_an_inventory(client, monkeypatch):
    """Missing authorization scope must not default to every manager agent."""
    request = MagicMock()
    monkeypatch.setattr(client, "get", request)
    assert client.list_agents() == []
    request.assert_not_called()


def test_agent_query_paginates_with_authorized_ids(client, monkeypatch):
    """A second page is requested without widening the authorized agent filter."""
    request = MagicMock(
        side_effect=[
            {"data": {"affected_items": [{"id": "001"}], "total_affected_items": 2}},
            {"data": {"affected_items": [{"id": "002"}], "total_affected_items": 2}},
        ]
    )
    monkeypatch.setattr(client, "get", request)
    assert len(client.list_agents(limit=1, agent_ids=["001", "002"])) == 2
    assert [c.kwargs["params"]["offset"] for c in request.call_args_list] == [0, 1]
    assert all(c.kwargs["params"]["agents_list"] == "001,002" for c in request.call_args_list)


@pytest.mark.parametrize(
    "data",
    [
        {"affected_items": [{"id": "999"}], "total_affected_items": 1},
        {"affected_items": [], "total_affected_items": 1},
        {"affected_items": [], "total_affected_items": 1, "total_failed_items": 1},
        {"affected_items": [None], "total_affected_items": 1},
        {"affected_items": [{"id": "001"}], "total_affected_items": 0},
        ["invalid"],
    ],
)
def test_foreign_or_partial_agent_responses_fail(client, monkeypatch, data):
    """Partial or unauthorized data cannot produce a successful collection."""
    monkeypatch.setattr(client, "get", lambda *a, **k: {"data": data})
    with pytest.raises(service.WazuhError):
        client.list_agents(agent_ids=["001"])


def test_connection_test_does_not_expose_agents_or_token(client, monkeypatch):
    """Connection health requires no inventory listing or token preview."""
    monkeypatch.setattr(client, "authenticate", lambda: "secret-test-token")
    monkeypatch.setattr(
        client, "list_agents", MagicMock(side_effect=AssertionError("No inventory"))
    )
    response = client.test_connection()
    assert response["ok"]
    assert "secret" not in str(response)


def event_response(agent="007", manager="manager"):
    """Build a minimal synthetic Indexer hit for response-validation cases."""
    return {
        "hits": {
            "hits": [
                {
                    "_id": "event",
                    "_index": "alerts",
                    "_source": {
                        "agent": {"id": agent},
                        "manager": {"name": manager},
                        "timestamp": "2026-10-15T12:00:00Z",
                        "rule": {"id": "1001", "level": 3},
                    },
                }
            ]
        }
    }


def test_event_query_is_exact_and_checks_response(client, monkeypatch):
    """Both the query and returned event must identify the authorized agent/manager."""
    request = MagicMock(return_value=MagicMock(status_code=200, json=lambda: event_response()))
    monkeypatch.setattr(service.requests, "post", request)
    event = client.search_last_alert_for_agent(agent_id="007", manager_name="manager")
    assert event["source_event_id"] == "alerts:event"
    assert event["authenticated"] is True
    filters = request.call_args.kwargs["json"]["query"]["bool"]["filter"]
    assert {"term": {"agent.id": "007"}} in filters
    assert {"term": {"manager.name": "manager"}} in filters
    assert request.call_args.kwargs["verify"] is True


@pytest.mark.parametrize(
    "payload",
    [
        event_response(agent="999"),
        event_response(manager="other"),
        {"timed_out": True},
        {"_shards": {"failed": 1}},
        {},
        [],
        {"hits": []},
        {"hits": {"hits": [None]}},
        {"hits": {"hits": [{"_source": []}]}},
        {"_shards": "invalid"},
    ],
)
def test_unusable_indexer_response_is_not_verified(client, monkeypatch, payload):
    """Wrong identity, malformed responses and partial searches are source failures."""
    monkeypatch.setattr(
        service.requests, "post", lambda *a, **k: MagicMock(status_code=200, json=lambda: payload)
    )
    with pytest.raises(service.WazuhError):
        client.search_last_alert_for_agent(agent_id="007", manager_name="manager")


def test_no_alerts_and_missing_indexer_are_distinct(client, monkeypatch):
    """An empty healthy query is not the same as an unavailable source."""
    monkeypatch.setattr(
        service.requests,
        "post",
        lambda *a, **k: MagicMock(status_code=200, json=lambda: {"hits": {"hits": []}}),
    )
    assert client.search_last_alert_for_agent(agent_id="007", manager_name="manager") == {}
    monkeypatch.delenv("WAZUH_INDEXER_URL")
    with pytest.raises(service.WazuhTelemetryNotConfigured):
        client.search_last_alert_for_agent(agent_id="007", manager_name="manager")


def test_source_errors_do_not_echo_credentials(client, monkeypatch):
    """HTTP exception details may contain secrets and must not be propagated."""
    monkeypatch.setattr(
        service.requests,
        "post",
        MagicMock(side_effect=service.requests.ConnectionError("password=do-not-display")),
    )
    with pytest.raises(service.WazuhError) as error:
        client.search_last_alert_for_agent(agent_id="007", manager_name="manager")
    assert "do-not-display" not in str(error.value)


def binding():
    """Return an approved synthetic binding for asset 1."""
    return dict(
        id=1,
        asset_id=1,
        agent_id="007",
        manager_name="manager",
        connector_id="source",
        heartbeat_max_age_seconds=300,
        telemetry_max_age_seconds=3600,
    )


def test_explicit_binding_survives_an_ip_change_without_inference():
    """Stable source identity remains authoritative when IP target data changes."""
    rows = service.match_agents_to_assets(
        [{"id": 1, "ip": "192.0.2.1"}],
        [
            {
                "id": "007",
                "name": "host",
                "ip": "192.0.2.2",
                "manager": "manager",
                "status": "active",
            }
        ],
        bindings=[binding()],
    )
    assert rows[0]["identity_verified"]
    assert rows[0]["match_type"] == "binding"
    assert rows[0]["monitoring_status"] != "Monitoring verified"


def test_duplicate_agent_or_foreign_manager_rejects_binding():
    """Duplicate stable IDs or foreign managers cannot be arbitrarily selected."""
    agent = {"id": "007", "ip": "192.0.2.1", "manager": "manager", "status": "active"}
    for agents in ([agent, agent], [dict(agent, manager="foreign")]):
        row = service.match_agents_to_assets(
            [{"id": 1, "ip": "192.0.2.1"}], agents, bindings=[binding()]
        )[0]
        assert not row["identity_verified"]


def test_duplicate_ip_and_substring_hostname_never_establish_identity():
    """Unapproved candidates and ambiguous IPs cannot qualify as evidence."""
    agents = [
        {"id": "001", "name": "host-a", "ip": "192.0.2.1", "status": "active"},
        {"id": "002", "name": "host-b", "ip": "192.0.2.1", "status": "active"},
    ]
    row = service.match_agents_to_assets(
        [{"id": 1, "ip": "192.0.2.1", "hostname": "host"}], agents
    )[0]
    assert row["match_type"] == "ambiguous"
    assert not row["identity_verified"]
    assert len(service.match_agents_to_assets([], agents, include_unmatched_agents=True)) == 0


def test_disabled_indexer_tls_does_not_authenticate_source_identity(client, monkeypatch):
    """Lab connectivity without server verification cannot become trusted evidence."""
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "false")
    monkeypatch.setattr(
        service.requests,
        "post",
        lambda *a, **k: MagicMock(status_code=200, json=lambda: event_response()),
    )
    event = client.search_last_alert_for_agent(agent_id="007", manager_name="manager")
    assert event["authenticated"] is False


def test_connector_identity_changes_with_source_but_not_password(client, monkeypatch):
    """Proof binds to endpoints/index/trust settings, without storing credentials."""
    original = client.connector_id
    monkeypatch.setenv("WAZUH_API_PASSWORD", "rotated-test-password")
    assert client.connector_id == original
    monkeypatch.setenv("WAZUH_INDEXER_ALERT_INDEX", "different-alerts-*")
    assert client.connector_id != original
