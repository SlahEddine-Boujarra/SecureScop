"""Validate profile drawer writes at the server and transaction boundaries."""

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from securescope.persistence import grc_repository as repository
from securescope.ui import control_profiles_workbench as drawer


def edit_payload():
    """Return the complete editable fields for a valid versioned change."""
    return {
        "expected_version": 3,
        "fields": {
            "control_owner": "owner@example.test",
            "assessment_owner": "assessor@example.test",
            "scope": "Production servers",
            "measurement_model": "checklist",
            "automation_level": "Manual",
            "assessment_methods": "Review\n Interview ",
            "evidence_requirements": "Approved procedure",
        },
    }


def test_drawer_ignores_client_actor_and_hidden_fields_from_browser(monkeypatch):
    """Write only allowed fields using the resolved workspace and server identity."""
    saved = MagicMock(return_value=4)
    monkeypatch.setattr(drawer, "create_profile_version", saved)
    profile = {
        "control_id": "A.8.8",
        "assessment_scope": {"unit_ids": [7]},
        "supported_data_sources": ["nuclei"],
    }
    payload = edit_payload()
    payload.update(client="Other client", actor="administrator", control_id="A.5.1")
    payload["fields"].update(approval_status="Approved", supported_data_sources=["forged"])
    assert drawer.save_profile_edit("Authorized", profile, payload, "real@example.test") == 4
    args, values = saved.call_args
    assert args == ("Authorized", "A.8.8")
    assert values["actor"] == "real@example.test"
    assert values["assessment_scope"]["unit_ids"] == [7]
    assert values["supported_data_sources"] == ["nuclei"]
    assert values["expected_profile_version"] == 3
    assert values["assessment_methods"] == ["Review", "Interview"]
    assert "approval_status" not in values


@pytest.mark.parametrize("version", [None, "3", True, 3.0])
def test_opened_version_is_required(monkeypatch, version):
    """Reject malformed concurrency metadata before persistence."""
    saved = MagicMock()
    monkeypatch.setattr(drawer, "create_profile_version", saved)
    payload = edit_payload()
    payload["expected_version"] = version
    with pytest.raises(ValueError):
        drawer.save_profile_edit("Authorized", {"control_id": "A.8.8"}, payload, "actor")
    saved.assert_not_called()


def test_stale_profile_fails_inside_locked_client_transaction(monkeypatch):
    """A newer saved version cannot be overwritten by the drawer's older revision."""
    cursor = MagicMock()
    cursor.__enter__.return_value = cursor
    cursor.fetchone.side_effect = [{"role": "Consultant"}, {"profile_version": 4}]
    connection = MagicMock()
    connection.cursor.return_value = cursor

    @contextmanager
    def connect():
        """Provide a transaction-scoped cursor without an external database."""
        yield connection

    monkeypatch.setattr(repository, "connect", connect)
    monkeypatch.setattr(repository, "seed_control_profiles", lambda *args: None)
    monkeypatch.setattr(repository, "_client_id", lambda *args: 12)
    with pytest.raises(repository.GrcRepositoryError, match="another session"):
        repository.create_profile_version(
            "Authorized",
            "A.8.8",
            measurement_model="checklist",
            control_owner="Owner",
            assessment_owner="Assessor",
            assessment_scope={"description": "Production"},
            assessment_methods=["Review"],
            evidence_requirements=["Procedure"],
            automation_level="Manual",
            supported_data_sources=[],
            actor="real@example.test",
            expected_profile_version=3,
        )
    calls = cursor.execute.call_args_list
    assert "FOR UPDATE" in calls[0].args[0]
    assert calls[0].args[1] == (12,)
    assert calls[1].args[1] == (12, "real@example.test")
    assert calls[2].args[1] == (12, "A.8.8")
    assert all("INSERT" not in call.args[0] for call in calls)


@pytest.mark.parametrize("role,control", [("Auditor", "A.8.8"), ("Consultant", "foreign-control")])
def test_forged_component_writes_are_rejected(monkeypatch, role, control):
    """Read-only roles and foreign control IDs cannot reach the save service."""
    from types import SimpleNamespace

    saved = MagicMock()
    session = {}
    event = {
        "action": "profile_save",
        "nonce": "attempt",
        "payload": {
            **edit_payload(),
            "control_id": control,
        },
    }

    class Rerun(Exception):
        """Stop the fake render after its error response is prepared."""

    def rerun():
        """Emulate Streamlit's control-flow exception."""
        raise Rerun()

    monkeypatch.setattr(drawer, "st", SimpleNamespace(session_state=session, rerun=rerun))
    monkeypatch.setattr(drawer, "_identity", lambda *args: ("real@example.test", role))
    monkeypatch.setattr(drawer, "assurance_workbench", lambda *args, **kwargs: None)
    monkeypatch.setattr(drawer, "_event", lambda *args: event)
    monkeypatch.setattr(drawer, "save_profile_edit", saved)
    with pytest.raises(Rerun):
        drawer.render_control_profiles("Authorized", [{"control_id": "A.8.8"}], [{}])
    saved.assert_not_called()
    assert session["control_drawers::Authorized::response"]["error"]


def test_local_wording_is_versioned_without_replacing_reference(monkeypatch):
    saved = MagicMock(return_value=4)
    monkeypatch.setattr(drawer, "create_profile_version", saved)
    payload = edit_payload()
    payload["fields"].update(
        organization_name="Production patching",
        implementation_description="Weekly review",
        control_name="Forged reference",
    )
    drawer.save_profile_edit(
        "Client", {"control_id": "A.8.8", "assessment_scope": {"unit_ids": [7]}}, payload, "actor"
    )
    values = saved.call_args.kwargs
    assert values["assessment_scope"]["organization_name"] == "Production patching"
    assert values["assessment_scope"]["unit_ids"] == [7]
    assert "control_name" not in values
