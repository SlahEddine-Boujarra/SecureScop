"""Exercise consolidated record actions and cross-module navigation."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.persistence import grc_repository, grc_workspace_repository
from securescope.ui import risk_management
from securescope.ui.grc_workspace import record_tools, scope_editor, stitch_records


def _foundation(monkeypatch, action, section="scope", role="Administrator"):
    monkeypatch.setattr(stitch_records, "current_actor", lambda: "admin@example.test")
    monkeypatch.setattr(stitch_records, "get_workspace_role", lambda *a: role)
    monkeypatch.setattr(stitch_records, "versions", lambda *a: [])
    monkeypatch.setattr(
        stitch_records,
        "assurance_workbench",
        lambda *a, **k: SimpleNamespace(
            action={
                "action": action,
                "nonce": "event-1",
                "payload": {},
                "expected": 0,
            }
        ),
    )
    return AppTest.from_string(
        f"""
from securescope.ui.grc_workspace.stitch_records import render_stitch_records
render_stitch_records("Client", {{"selected_engagement_id": 7, "selected_scope_id": 9,
 "scopes": [{{"id": 9, "name": "Production", "scope_code": "PROD"}}]}}, {section!r}, {{}})
"""
    ).run()


def test_scope_edit_opens_existing_editor_for_selected_context(monkeypatch):
    started = MagicMock()
    monkeypatch.setattr(scope_editor, "start_scope_editor", started)
    app = _foundation(monkeypatch, "foundation_scope_edit")
    assert not app.exception
    started.assert_called_once_with(
        "Client", 7, {"id": 9, "name": "Production", "scope_code": "PROD"}
    )
    assert app.session_state["stitch::Client::7::9::scope:response"]["nonce"] == "event-1"


def test_scope_history_uses_selected_scope_and_acknowledges_event(monkeypatch):
    history = MagicMock(return_value=[{"id": 11, "version_number": 2, "status": "Approved"}])
    monkeypatch.setattr(record_tools, "get_workspace_role", lambda *a: "Auditor")
    monkeypatch.setattr(record_tools, "list_scope_versions", history)
    app = _foundation(monkeypatch, "foundation_history", role="Auditor")
    assert not app.exception
    history.assert_called_once_with("Client", 7, 9)
    assert app.selectbox[0].label == "View version"
    assert not app.get("json")
    assert app.session_state["stitch::Client::7::9::scope:response"]["nonce"] == "event-1"


def test_readonly_edit_failure_is_acknowledged(monkeypatch):
    started = MagicMock()
    monkeypatch.setattr(scope_editor, "start_scope_editor", started)
    app = _foundation(monkeypatch, "foundation_scope_edit", role="Auditor")
    assert not app.exception
    started.assert_not_called()
    assert "editable Scope" in app.session_state["stitch::Client::7::9::scope:response"]["error"]


def test_risk_link_executes_navigation_in_render_and_keeps_context(monkeypatch):
    navigate = MagicMock()
    monkeypatch.setattr(risk_management, "navigate_to", navigate)
    app = AppTest.from_string(
        """
import streamlit as st
from securescope.ui.risk_management import risk_entry_actions
st.session_state.setdefault("grc_selected_engagement::Client", 7)
st.session_state.setdefault("grc_selected_scope::Client", 9)
risk_entry_actions("Client", True)
"""
    ).run()
    app.button[0].click().run()
    assert not app.exception
    navigate.assert_called_once_with("Risk")
    assert app.session_state["grc_selected_engagement::Client"] == 7
    assert app.session_state["grc_selected_scope::Client"] == 9
    assert app.session_state["risk_management::Client::pending"] == "Registers & assessment"


def test_objective_review_does_not_render_another_editor(monkeypatch):
    monkeypatch.setattr(record_tools, "get_workspace_role", lambda *a: "Administrator")
    monkeypatch.setattr(
        record_tools,
        "versions",
        lambda *a: [{"version": 3, "status": "Draft", "records": [{"title": "Restore services"}]}],
    )
    saved = MagicMock()
    monkeypatch.setattr(record_tools, "save_version", saved)
    app = _foundation(monkeypatch, "foundation_review", section="objectives")
    assert not app.exception
    assert len(app.text_area) == 1
    app.text_area[0].input("Reviewed with service owners")
    app.checkbox[0].check()
    app.button[1].click().run()
    assert not app.exception
    assert saved.call_args.kwargs["expected_version"] == 3
    assert saved.call_args.kwargs["status"] == "In review"


def _cursor(monkeypatch, repository):
    cursor = MagicMock()
    connection = MagicMock()
    connection.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(repository, "connect", lambda: connection)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    monkeypatch.setattr(repository, "_client_id", lambda *a: 42)
    return cursor


def test_scope_review_rejects_stale_version_before_mutation(monkeypatch):
    repo = grc_workspace_repository
    cursor = _cursor(monkeypatch, repo)
    monkeypatch.setattr(repo, "_engagement", lambda *a, **k: {})
    monkeypatch.setattr(repo, "_scope", lambda *a, **k: {})
    monkeypatch.setattr(
        repo, "_workspace_member", lambda *a, **k: {"workspace_role": "Administrator"}
    )
    cursor.fetchone.return_value = {"id": 99, "status": "Draft"}
    with pytest.raises(repo.GrcWorkspaceRepositoryError, match="Scope changed"):
        repo.submit_scope_review("Client", 7, 9, 98, actor="admin@example.test", note="Reviewed")
    assert not any(
        call.args[0].lstrip().startswith("UPDATE") for call in cursor.execute.call_args_list
    )
    assert cursor.execute.call_args.args[1] == (42, 7, 9)


def test_target_risk_refs_reject_foreign_or_missing_risk(monkeypatch):
    repo = grc_repository
    cursor = _cursor(monkeypatch, repo)
    cursor.fetchall.return_value = [(1,)]
    from datetime import date

    with pytest.raises(repo.GrcRepositoryError, match="outside this workspace"):
        repo.create_control_target(
            "Client",
            7,
            target_description="Target",
            target_value=None,
            unit="",
            target_date=date.today(),
            rationale="Reviewed",
            risk_basis="",
            risk_refs=[1, 999],
            remaining_scope_justification="",
            required_evidence=[],
            required_effectiveness_test="",
            approver="admin@example.test",
            approval_date=date.today(),
        )
    assert not any("INSERT" in call.args[0] for call in cursor.execute.call_args_list)


@pytest.mark.parametrize(
    "method,field",
    [
        ("create_context_issue", "title"),
        ("create_interested_party", "name"),
        ("create_party_requirement", "requirement"),
    ],
)
def test_discovery_retries_reuse_existing_records_without_overwriting(monkeypatch, method, field):
    repo = grc_workspace_repository
    cursor = _cursor(monkeypatch, repo)
    lock = MagicMock()
    monkeypatch.setattr(repo, "_engagement", lock)
    monkeypatch.setattr(repo, "_scope", lambda *a: {})
    cursor.fetchone.return_value = {"id": 23}
    draft = MagicMock()
    draft.validate.return_value = SimpleNamespace(**{field: "Reviewed suggestion"})
    args = ("Client", 7, 8, draft) if method == "create_party_requirement" else ("Client", 7, draft)
    assert (
        getattr(repo, method)(*args, actor="admin@example.test", scope_id=9, reuse_existing=True)
        == 23
    )
    lock.assert_called_once_with(cursor, 42, 7, for_update=True)
    assert not any(
        call.args[0].lstrip().startswith("INSERT") for call in cursor.execute.call_args_list
    )
    assert "scope_id IS NOT DISTINCT FROM" in cursor.execute.call_args.args[0]
