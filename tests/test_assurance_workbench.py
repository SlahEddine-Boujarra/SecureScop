"""Workbench adapter boundaries and saved-document approval transitions."""

import base64
import uuid
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.persistence import workspace_planning as planning
from securescope.persistence.foundation_repository import FoundationError
from securescope.policies import repository as repo
from securescope.policies.documents import extract_document
from securescope.policies.suggestions import TOPICS, policy_template
from securescope.ui import assurance_workbench as ui


@pytest.mark.parametrize("action", ["policy_save", "policy_approve", "comment", "export"])
def test_policy_foreign_selection_never_dispatches(monkeypatch, action):
    monkeypatch.setattr(ui.st, "session_state", {"k::selected": "local"})
    save = Mock()
    monkeypatch.setattr(ui, "save_policy", save)
    with pytest.raises(repo.PolicyError, match="selected policy changed"):
        ui.dispatch_policy(
            "Client",
            1,
            2,
            "admin",
            [],
            1,
            "k",
            {"action": action, "payload": {}, "selected": "foreign", "expected": 1},
        )
    save.assert_not_called()


def test_policy_stale_event_never_writes(monkeypatch):
    monkeypatch.setattr(ui.st, "session_state", {"k::selected": "local"})
    save = Mock()
    monkeypatch.setattr(ui, "save_policy", save)
    with pytest.raises(repo.PolicyError, match="another session"):
        ui.dispatch_policy(
            "Client",
            1,
            2,
            "admin",
            [],
            2,
            "k",
            {"action": "policy_save", "payload": {}, "selected": "local", "expected": 1},
        )
    save.assert_not_called()


def test_upload_decodes_browser_contract(monkeypatch):
    monkeypatch.setattr(ui.st, "session_state", {})
    upload = Mock(return_value="saved")
    monkeypatch.setattr(ui, "upload_policy", upload)
    ui.dispatch_policy(
        "Client",
        1,
        2,
        "admin",
        [],
        0,
        "k",
        {
            "action": "upload",
            "payload": {
                "filename": "policy.txt",
                "content": base64.b64encode(b"Policy content").decode(),
            },
            "selected": None,
            "expected": 0,
        },
    )
    assert upload.call_args.kwargs["content"] == b"Policy content"
    assert ui.st.session_state["k::selected"] == "saved"


def test_large_and_invalid_uploads_rejected():
    for value in ["?" * 20, "a" * 2_800_001]:
        with pytest.raises(ValueError):
            ui.decode_upload({"content": value})


def approval_cursor(monkeypatch, policy, role="Administrator"):
    cursor = Mock()
    cursor.fetchone.side_effect = [{"exists": 1}, {"version": 3, "records": [policy]}]

    @contextmanager
    def transaction(client):
        assert client == "Client"
        yield cursor, 7

    monkeypatch.setattr(repo, "workspace_cursor", transaction)
    monkeypatch.setattr(repo, "member_role", lambda *args: role)
    return cursor


def approve(policy, actor):
    repo.save_policy(
        "Client",
        1,
        2,
        actor=actor,
        policy_id=policy["policy_id"],
        expected_version=3,
        status="Approved",
        note="Reviewed saved version",
        metadata={},
    )


def test_policy_requires_every_assigned_approval(monkeypatch):
    policy = dict(
        policy_id=str(uuid.uuid4()), status="In review", approvers=["a", "b"], approvals={}
    )
    cursor = approval_cursor(monkeypatch, policy)
    approve(policy, "a")
    saved = cursor.execute.call_args.args[1][5].adapted[0]
    assert saved["status"] == "In review" and set(saved["approvals"]) == {"a"}
    cursor = approval_cursor(monkeypatch, saved)
    approve(saved, "b")
    saved = cursor.execute.call_args.args[1][5].adapted[0]
    assert saved["status"] == "Approved" and set(saved["approvals"]) == {"a", "b"}


@pytest.mark.parametrize("actor,approvals", [("other", {}), ("a", {"a": {"at": "earlier"}})])
def test_unassigned_and_repeat_policy_approvals_rejected(monkeypatch, actor, approvals):
    policy = dict(
        policy_id=str(uuid.uuid4()), status="In review", approvers=["a", "b"], approvals=approvals
    )
    cursor = approval_cursor(monkeypatch, policy)
    with pytest.raises(repo.PolicyError, match="assigned approver"):
        approve(policy, actor)
    assert not any("INSERT" in c.args[0] for c in cursor.execute.call_args_list)


def test_risk_comment_rejects_cross_risk_reply():
    cursor = Mock()
    cursor.fetchone.side_effect = [{"exists": 1}, {"payload": {"risk_ref": 2}}]
    with pytest.raises(FoundationError, match="same risk"):
        planning.validate_payload(
            cursor,
            7,
            "risk_comment",
            "uuid",
            {"risk_ref": 1, "body": "Hello", "parent": "other"},
            "Administrator",
        )


def test_risk_transition_checks_exact_assessment_revision():
    cursor = Mock()
    cursor.fetchone.return_value = {"revision": 4}
    with pytest.raises(FoundationError, match="assessment changed"):
        planning.validate_payload(
            cursor,
            7,
            "risk_detail",
            "1",
            {"risk_ref": 1, "expected_risk_revision": 3, "review_state": "In review"},
            "Administrator",
        )


def test_review_history_cannot_be_client_written(monkeypatch):
    cursor = Mock()

    @contextmanager
    def transaction(client):
        yield cursor, 7

    monkeypatch.setattr(planning, "workspace_cursor", transaction)
    monkeypatch.setattr(planning, "member_role", lambda *args: "Administrator")
    with pytest.raises(FoundationError, match="generated"):
        planning.put_record("Client", "risk_review", "", {"state": "Approved"}, actor="admin")
    cursor.execute.assert_not_called()


def test_templates_have_unique_content_and_word_roundtrip():
    from securescope.reporting.policy_docx import policy_docx

    bodies = []
    for name in TOPICS:
        draft = policy_template(name, "Client")
        assert len(draft["blocks"]) >= 10
        assert "[Draft guidance]" not in str(draft)
        bodies.append(str(draft["blocks"][5]))
    assert len(set(bodies)) == 25
    draft = policy_template("Access Control", "Client")
    content = policy_docx(draft, draft["blocks"])
    extracted = extract_document("Access.docx", content)
    assert "Access authorization" in str(extracted["blocks"])
    assert "Password policy" in str(extracted["blocks"])


@pytest.mark.parametrize("kind", ["policy", "risk"])
def test_actual_page_routes_to_custom_component_without_database(kind):
    script = (
        "\nfrom types import SimpleNamespace\nfrom unittest.mock "
        "import patch\nimport streamlit as st\nfrom securescope.ui "
        "import assurance_workbench as ui\nfrom "
        "securescope.persistence import risk_register_repository as "
        "risks\nseen=[]\ndef component(data,**kwargs):\n    "
        "seen.append(data)\n    st.text(data['mode'])\n    return "
        "SimpleNamespace(action=None)\nwith "
        "patch.object(ui,'get_workspace_role',return_value='Auditor')"
        ",patch.object(ui,'_members',return_value=[]),patch.object(ui"
        ",'list_control_overview',return_value=[]),patch.object(ui,'l"
        "ist_records',return_value=[]),patch.object(ui,'load_policies"
        "',return_value=([],[])),patch.object(risks,'list_risk_regist"
        "er',return_value=[]),patch.object(ui,'assurance_workbench',s"
        "ide_effect=component):\n"
    )
    if kind == "policy":
        script += (
            "    from securescope.ui.policy_workspace import "
            "render_policy_workspace\n    "
            "render_policy_workspace('Client',{'selected_engagement_id':1"
            ",'selected_scope_id':2})\n"
        )
    else:
        script += (
            "    from securescope.ui.risk_workspace import "
            "render_risk_page\n    from securescope.ui import risk_management as management\n"
            "    with patch.object(management, 'get_workspace_role', "
            "return_value='Auditor'), "
            "patch('securescope.persistence.risk_links.risk_scope_options', "
            "return_value=[]):\n"
            "        render_risk_page('Client')\n"
        )
    script += "assert not seen[0]['can_edit']\n"
    app = AppTest.from_string(script).run()
    assert not app.exception and not app.error
    assert app.text[0].value == ("policy_list" if kind == "policy" else "risk_overview")
