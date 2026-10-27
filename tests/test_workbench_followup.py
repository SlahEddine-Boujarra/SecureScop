"""Regression checks for selected registers, inventory boundaries and calendar routing."""

from unittest.mock import Mock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.persistence import risk_links
from securescope.persistence.foundation_repository import FoundationError
from securescope.ui import assurance_workbench as ui


def test_new_scenario_retains_selected_register(monkeypatch):
    """Creating a scenario in a named register keeps that register in draft state."""
    monkeypatch.setattr(ui.st, "session_state", {"risk::Client:group": "finance"})
    ui.dispatch_risk(
        "Client",
        "actor",
        "risk::Client",
        {"action": "risk_new", "payload": {}, "selected": None},
        [],
        {},
        [],
        None,
    )
    assert ui.st.session_state["risk::Client:new"]["group"] == "finance"


def transactional_mock(monkeypatch, *, group_exists=True, asset_exists=True, old_revision=0):
    """Supply a cursor for both callbacks; return cursor and recorded operation order."""
    cursor = Mock()
    cursor.fetchone.side_effect = [
        {"exists": 1} if group_exists else None,
        {"revision": old_revision, "payload": {}} if old_revision else None,
    ]
    cursor.fetchall.side_effect = [
        [],
        [{"id": 7, "ip": "192.0.2.7"}] if asset_exists else [],
        [{"ip": "192.0.2.7"}],
    ]
    monkeypatch.setattr(risk_links, "member_role", lambda *args: "Administrator")
    order = []

    def save(client, record, **kwargs):
        """Execute validation and link persistence on the same transaction cursor."""
        kwargs["authorize"](cursor, 3)
        order.append("risk")
        kwargs["after_save"](cursor, 3, {1: 1})
        order.append("links")

    monkeypatch.setattr(risk_links, "save_risk_record", save)
    return cursor, order


def test_named_register_and_assets_saved_in_transaction(monkeypatch):
    """The same canonical save persists named-group placement and stable IP links."""
    cursor, order = transactional_mock(monkeypatch)
    risk_links.save_assessment(
        "Client",
        {"risk_ref": 1, "threat": "Outage"},
        actor="actor",
        revision=0,
        group="finance",
        metadata_revision=0,
        asset_ids=[7],
    )
    assert order == ["risk", "links"]
    payload = cursor.execute.call_args.args[1][2].adapted
    assert payload["group"] == "finance" and payload["asset_ips"] == ["192.0.2.7"]
    assert payload["review_state"] == "Draft"


@pytest.mark.parametrize(
    "group_exists,asset_exists,message",
    [(False, True, "register no longer"), (True, False, "does not belong")],
)
def test_foreign_links_never_reach_risk_write(monkeypatch, group_exists, asset_exists, message):
    """Invalid register or inventory ownership prevents the canonical write."""
    _, order = transactional_mock(monkeypatch, group_exists=group_exists, asset_exists=asset_exists)
    with pytest.raises(FoundationError, match=message):
        risk_links.save_assessment(
            "Client",
            {"risk_ref": 1, "threat": "Outage"},
            actor="actor",
            revision=0,
            group="finance",
            metadata_revision=0,
            asset_ids=[7],
        )
    assert not order


def test_stale_link_revision_never_writes(monkeypatch):
    """Concurrent supporting-record edits must not be overwritten."""
    _, order = transactional_mock(monkeypatch, old_revision=2)
    with pytest.raises(FoundationError, match="another session"):
        risk_links.save_assessment(
            "Client",
            {"risk_ref": 1, "threat": "Outage"},
            actor="actor",
            revision=0,
            group="finance",
            metadata_revision=1,
            asset_ids=[7],
        )
    assert not order


def test_calendar_actual_route_renders_authorized_data():
    """The real Calendar route renders the new component with authorized clients."""
    app = AppTest.from_string(
        (
            "\nfrom types import SimpleNamespace\nfrom unittest.mock "
            "import patch\nimport streamlit as st\nfrom securescope.ui "
            "import calendar_workbench as ui\nfrom "
            "securescope.ui.calendar_workspace import "
            "render_calendar_page\ndef component(data,**kwargs):\n    "
            "st.text(data['mode'])\n    assert [c['name'] for c in "
            "data['clients']]==['Allowed client']\n    return "
            "SimpleNamespace(action=None)\nwith "
            "patch.object(ui,'authorized_clients',return_value=[{'name':'"
            "Allowed client','role':'Auditor'}]),patch.object(ui,'calenda"
            "r_events',return_value=[]),patch.object(ui,'assurance_workbe"
            "nch',side_effect=component):\n    "
            "render_calendar_page('Allowed "
            "client')\n"
        )
    ).run()
    assert not app.exception and not app.error
    assert app.text[0].value == "calendar"
