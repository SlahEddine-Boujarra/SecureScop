"""Presentation and action guards for the first ATLAS slice; no source calls."""

import ast
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.ui.siem_presentation import monitoring_view

NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)


def record(**changes):
    """Return a synthetic repository row; overrides are scalars; no exceptions expected."""
    return dict(
        dict(
            asset_id=42,
            asset_tag="PROD-WEB-01",
            asset_ip="192.0.2.42",
            monitoring_state="active_unverified",
            monitoring_reason="Heartbeat, no qualifying telemetry",
            identity_verified=True,
            binding_id=7,
            wazuh_agent_id="007",
            wazuh_status="active",
        ),
        **changes,
    )


def test_active_agent_is_not_promoted_and_inputs_remain_unchanged():
    """Active status and zero alerts never become telemetry verification in the view."""
    rows = [record(last_alert_time=None)]
    before = copy.deepcopy(rows)
    view = monitoring_view(rows, "Alpha", now=NOW)
    assert view["rows"][0]["monitoring_state"] == "active_unverified"
    assert view["rows"][0]["source"]["last_alert_time"] == ""
    assert rows == before


@pytest.mark.parametrize(
    "expiry,expected",
    [
        (NOW, "stale"),
        (NOW - timedelta(seconds=1), "stale"),
        (None, "not_verified"),
        (NOW + timedelta(seconds=60), "verified"),
    ],
)
def test_expiry_is_conservative(expiry, expected):
    """Expired or unspecified verification cannot be presented as current."""
    view = monitoring_view(
        [record(monitoring_state="verified", verified_until=expiry)], "Alpha", now=NOW
    )
    assert view["rows"][0]["monitoring_state"] == expected


def test_payload_allowlist_excludes_secrets_and_raw_logs():
    """Only explicit source fields reach the component; arbitrary nested values are omitted."""
    row = record(
        password="secret",
        raw_event={"token": "secret"},
        telemetry={"kind": "collection_health", "authorization": "secret"},
    )
    view = monitoring_view([row], "Alpha", now=NOW)
    assert "secret" not in str(view)
    assert view["rows"][0]["telemetry"]["kind"] == "collection_health"


@pytest.mark.parametrize(
    "rows", [[record(asset_id=0)], [record(asset_id="42")], [record(), record()]]
)
def test_ambiguous_ui_identity_is_rejected(rows):
    """The view never aliases duplicated, missing or noncanonical inventory identities."""
    with pytest.raises(ValueError, match="distinct canonical"):
        monitoring_view(rows, "Alpha", now=NOW)


def test_empty_workspace_has_no_invented_coverage():
    """An empty inventory remains empty and has an explicit snapshot timestamp."""
    assert monitoring_view([], "Alpha", now=NOW) == dict(
        workspace="Alpha", evaluated_at=NOW.isoformat(), rows=[]
    )


@pytest.mark.parametrize("can_collect,connected", [(False, True), (True, False)])
def test_native_action_menu_disables_collection_when_gates_are_missing(can_collect, connected):
    """Native controls retain role and tested-configuration preconditions."""
    app = AppTest.from_string(
        "from securescope.ui.wazuh_monitoring_ui import render_wazuh_actions\n"
        f"render_wazuh_actions('Alpha', configured=True, connected={connected}, "
        f"can_collect={can_collect}, can_configure=False)"
    ).run()
    assert not app.exception
    buttons = {b.label: b for b in app.button}
    assert buttons["Collect Wazuh evidence"].disabled
    assert buttons["Configure integration"].disabled
    assert not buttons["Refresh status"].disabled


@pytest.fixture
def route(monkeypatch):
    """Execute the actual SIEM route function with synthetic services and no database/network.

    Args:
        monkeypatch: Pytest dependency boundary isolation.
    Returns:
        Callable running Streamlit AppTest and mocks for collection/source reads.
    Raises:
        AssertionError: If the actual route fails to render.
    """
    from securescope.integrations import wazuh_collection, wazuh_service
    from securescope.persistence import evidence_repository
    from securescope.ui import evidence_collection_context, wazuh_monitoring_ui
    from securescope.ui.components_v2 import monitoring_workbench
    from securescope.ui.grc_workspace import context

    collect = MagicMock(return_value=dict(outcome="succeeded", evidence_ids=[1]))
    monkeypatch.setattr(wazuh_collection, "collect_monitoring", collect)
    monkeypatch.setattr(wazuh_service, "restore_wazuh_settings", lambda: None)
    monkeypatch.setattr(context, "current_actor", lambda: "reader@example.invalid")
    monkeypatch.setattr(evidence_collection_context, "render_collection_return", lambda *a: None)
    monkeypatch.setattr(wazuh_monitoring_ui, "render_wazuh_action_panel", lambda *a: None)
    monkeypatch.setattr(monitoring_workbench, "monitoring_workbench", lambda *a: None)
    path = Path(__file__).parents[1] / "src/securescope/app.py"
    tree = ast.parse(path.read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "render_siem_wazuh_page"
    )
    source = ast.unparse(node)

    def run(role, action, failed_read=False):
        """Run the route for a chosen role/action and return its Streamlit element tree."""
        monkeypatch.setattr(evidence_repository, "get_workspace_role", lambda *a: role)
        monkeypatch.setattr(wazuh_monitoring_ui, "render_wazuh_actions", lambda *a, **k: action)
        setup = """
import logging, os, streamlit as st
import hashlib
from securescope.persistence.db_service import DatabaseError
from securescope.persistence.db_wazuh_service import WazuhDatabaseError
logger = logging.getLogger('m4-route-test')
WAZUH_INTEGRATION_AVAILABLE = True
WAZUH_IMPORT_ERROR = ''
st.session_state['wazuh_verified::Alpha'] = hashlib.sha256('|'.join(os.getenv(n,'') for n in (
    'WAZUH_API_URL','WAZUH_API_USER','WAZUH_API_PASSWORD','WAZUH_VERIFY_TLS',
    'WAZUH_INDEXER_URL','WAZUH_INDEXER_USER','WAZUH_INDEXER_PASSWORD','WAZUH_INDEXER_VERIFY_TLS',
)).encode()).hexdigest()
def get_active_client_name():
    return 'Alpha'
def load_latest_wazuh_status(client):
    READER_BODY
""".replace(
            "READER_BODY",
            ("raise WazuhDatabaseError('fixture failure')" if failed_read else "return []"),
        )
        app = AppTest.from_string(setup + "\n" + source + "\nrender_siem_wazuh_page()\n").run()
        assert not app.exception
        return app

    return run, collect


def test_forged_disabled_action_does_not_bypass_server_guard(route):
    """An action returned despite a disabled widget cannot authorize collection."""
    run, collect = route
    run("Auditor", "collect")
    collect.assert_not_called()


def test_nonmember_cannot_load_monitoring(route):
    """The page exits before source/configuration reads when membership is absent."""
    run, collect = route
    app = run(None, "collect")
    assert any("membership is required" in w.value for w in app.warning)
    collect.assert_not_called()


def test_authorized_collection_retains_existing_service_and_context(route):
    """An authorized tested session invokes the existing collector exactly once."""
    run, collect = route
    app = run("Consultant", "collect")
    collect.assert_called_once_with("Alpha", "reader@example.invalid", {})
    assert any("canonical evidence records" in message.value for message in app.success)


def test_database_error_is_not_an_empty_successful_inventory(route):
    """Source read failures explicitly block a current-coverage conclusion."""
    run, _ = route
    app = run("Auditor", None, failed_read=True)
    assert any("No current coverage" in e.value for e in app.error)


@pytest.mark.parametrize(
    "workspace,asset_id,nonce,handled,expected",
    [
        ("Alpha", 42, "new", None, True),
        ("Other", 42, "new", None, False),
        ("Alpha", 99, "new", None, False),
        ("Alpha", True, "new", None, False),
        ("Alpha", 42, "seen", "seen", False),
    ],
)
def test_component_navigation_rejects_foreign_rows_and_replayed_events(
    monkeypatch, workspace, asset_id, nonce, handled, expected
):
    """Only a fresh event for an authorized row may navigate; no domain write occurs."""
    from securescope.ui.components_v2 import monitoring_workbench as bridge

    event = dict(type="open_evidence", workspace=workspace, asset_id=asset_id, nonce=nonce)
    monkeypatch.setattr(
        bridge.st.components.v2, "component", lambda **kwargs: lambda **kw: {"action": event}
    )
    monkeypatch.setattr(
        bridge.st, "session_state", {"monitoring_workbench::Alpha::handled": handled}
    )
    navigate, rerun = MagicMock(), MagicMock()
    monkeypatch.setattr(bridge, "navigate_to", navigate)
    monkeypatch.setattr(bridge.st, "rerun", rerun)
    bridge.monitoring_workbench([record()], "Alpha")
    assert navigate.called is expected
    assert rerun.called is expected
    if expected:
        navigate.assert_called_once_with("ISO Evidence Hub")
