"""Security boundaries and real persistence calls for the planning release."""

from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from streamlit.testing.v1 import AppTest

from securescope.persistence import workspace_deletion as deletion
from securescope.persistence.foundation_repository import FoundationError
from securescope.policies import repository as policies


def install_cursor(monkeypatch):
    cursor = Mock()
    cursor.fetchone.side_effect = [{"role": "Administrator"}, {"exists": 1}, None]
    cursor.fetchall.return_value = []

    @contextmanager
    def transaction(client):
        yield cursor, 7

    monkeypatch.setattr(policies, "workspace_cursor", transaction)
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    return cursor


@pytest.mark.parametrize("first,second", [(False, False), (True, False), (False, True), (1, True)])
def test_delete_requires_two_literal_confirmations(first, second):
    with pytest.raises(FoundationError, match="Both"):
        deletion.delete_workspace(
            "Client", actor="admin", expected_id=7, confirm_data=first, confirm_permanent=second
        )


def deletion_cursor(monkeypatch, role="Administrator", rows=None):
    cursor = Mock()
    cursor.fetchone.side_effect = rows or [{"relation": None}] * 3
    cursor.fetchall.return_value = [{"name": "Other"}]
    cursor.rowcount = 1

    @contextmanager
    def transaction(client):
        assert client == "Client"
        yield cursor, 7

    monkeypatch.setattr(deletion, "workspace_cursor", transaction)
    monkeypatch.setattr(deletion, "member_role", lambda *args: role)
    return cursor


@pytest.mark.parametrize("role", ["Consultant", "Client contributor", "Auditor", None])
def test_non_admin_cannot_delete(monkeypatch, role):
    cursor = deletion_cursor(monkeypatch, role)
    with pytest.raises(FoundationError, match="Administrator"):
        deletion.delete_workspace(
            "Client", actor="user", expected_id=7, confirm_data=True, confirm_permanent=True
        )
    cursor.execute.assert_not_called()


def test_delete_checks_target_and_active_jobs(monkeypatch):
    cursor = deletion_cursor(monkeypatch, rows=[{"relation": "jobs"}, {"id": 1}])
    with pytest.raises(FoundationError, match="active/queued"):
        deletion.delete_workspace(
            "Client", actor="admin", expected_id=7, confirm_data=True, confirm_permanent=True
        )
    assert not any("DELETE FROM" in str(call) for call in cursor.execute.call_args_list)


def test_delete_retains_audit_and_cleans_only_target_directory(monkeypatch, tmp_path):
    cursor = deletion_cursor(monkeypatch)
    (tmp_path / "7").mkdir()
    (tmp_path / "8").mkdir()
    monkeypatch.setattr(deletion, "evidence_root", lambda: tmp_path)
    result = deletion.delete_workspace(
        "Client", actor="admin", expected_id=7, confirm_data=True, confirm_permanent=True
    )
    assert result.remaining == ["Other"]
    assert not (tmp_path / "7").exists()
    assert (tmp_path / "8").exists()
    calls = cursor.execute.call_args_list
    assert "admin_audit_events" in calls[3].args[0]
    assert calls[4].args[1] == (7, "Client")


@pytest.mark.parametrize(
    "filename,content",
    [("policy.txt", b"Protect information."), ("policy.md", b"# Purpose\nProtect information.")],
)
def test_upload_creates_encrypted_saved_policy(monkeypatch, filename, content):
    cursor = install_cursor(monkeypatch)
    policy_id = policies.upload_policy(
        "Client", 1, 2, actor="admin", expected_version=0, filename=filename, content=content
    )
    inserted = cursor.execute.call_args.args[1][5].adapted
    assert inserted[0]["policy_id"] == policy_id
    assert inserted[0]["status"] == "Draft"
    assert "Protect information" not in inserted[0]["document_ciphertext"]
    assert policies.document_payload(inserted[0])["blocks"]
    assert inserted[0]["source_name"] == filename


@pytest.mark.parametrize(
    "page,module,function",
    [
        ("Risk", "risk_workspace", "render_risk_page_legacy"),
        ("Calendar", "calendar_workspace", "render_calendar_page_legacy"),
    ],
)
def test_new_pages_render_empty_workspace(page, module, function):
    script = f"""
from unittest.mock import patch
import securescope.ui.{module} as ui
with patch.object(ui, "get_workspace_role", return_value="Auditor"):
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in ("list_risk_register", "list_records", "calendar_events"):
            if hasattr(ui,name):
                stack.enter_context(patch.object(ui,name,return_value=[]))
        ui.{function}("Client")
"""
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert app.title[0].value == page


def test_risk_detail_and_review_form_render():
    script = (
        "\nimport streamlit as st\nfrom unittest.mock import "
        "patch\nimport securescope.ui.risk_workspace as "
        "ui\nst.session_state['risk::Client::selected'] = 1\nrow = "
        "{'risk_ref': 1, 'revision': 2, 'threat': 'Loss of service', "
        "'risk_owner': 'Owner', 'pre_risk_score': 12}\nwith "
        "patch.object(ui,'list_risk_register',return_value=[row]), "
        "patch.object(ui,'list_records',return_value=[]), "
        "patch.object(ui,'get_workspace_role',return_value='Administr"
        "ator'):\n    ui.render_risk_page_legacy('Client')\n"
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert any(b.label == "Save assessment draft" for b in app.button)


def test_calendar_event_opens_details():
    script = (
        "\nfrom datetime import date\nfrom unittest.mock import "
        "patch\nimport securescope.ui.calendar_workspace as ui\nwith "
        "patch.object(ui,'calendar_events',return_value=[{'title':'Bo"
        "ard review','starts_at':date.today().isoformat(),'source':'M"
        "anual','notes':'Review decisions'}]), "
        "patch.object(ui,'get_workspace_role',return_value='Auditor')"
        ":\n    ui.render_calendar_page_legacy('Client')\n"
    )
    app = AppTest.from_string(script).run()
    next(b for b in app.button if b.label == "Board review").click().run()
    assert not app.exception
    assert any(h.value == "Board review" for h in app.subheader)


def test_stale_risk_approval_is_rejected():
    from securescope.persistence.workspace_planning import validate_payload

    cursor = Mock()
    cursor.fetchone.side_effect = [
        {"revision": 3, "risk_owner": "Owner", "pre_likelihood": 3, "pre_impact": 4},
        {"role": "Administrator"},
        {"payload": {"review_state": "In review", "reviewed_revision": 2}},
    ]
    with pytest.raises(FoundationError, match="current submitted"):
        validate_payload(
            cursor,
            7,
            "risk_detail",
            "1",
            {"risk_ref": 1, "review_state": "Approved", "approver": "admin"},
            "Administrator",
        )


def test_cross_workspace_task_link_is_rejected():
    from securescope.persistence.workspace_planning import validate_payload

    cursor = Mock()
    cursor.fetchone.return_value = None
    with pytest.raises(FoundationError, match="this workspace"):
        validate_payload(cursor, 7, "risk_task", "", {"risk_ref": 123}, "Administrator")
    assert cursor.execute.call_args.args[1] == (7, 123)


def test_docx_upload_is_saved_with_original(monkeypatch):
    import io
    from zipfile import ZipFile

    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(
            "word/document.xml",
            (
                (
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordp'
                    'rocessingml/2006/main"><w:body><w:p><w:r><w:t>Policy '
                    "purpose</w:t></w:r></w:p></w:body></w:document>"
                )
            ),
        )
    cursor = install_cursor(monkeypatch)
    policies.upload_policy(
        "Client",
        1,
        2,
        actor="admin",
        expected_version=0,
        filename="policy.docx",
        content=buffer.getvalue(),
    )
    row = cursor.execute.call_args.args[1][5].adapted[0]
    assert policies.document_payload(row)["source_base64"]
    assert row["status"] == "Draft"


def test_upload_ui_calls_persistence_and_opens_saved_document():
    script = (
        "\nimport streamlit as st\nfrom types import "
        "SimpleNamespace\nfrom unittest.mock import patch\nfrom "
        "securescope.ui import policy_workspace as ui\nsaved = "
        "{'policy_id':'saved-policy','policy_version':1,'status':'Dra"
        "ft','title':'Uploaded','owner':'admin','policy_text':'Policy"
        " purpose','controls':[]}\nclass Upload:\n    name = "
        "'policy.txt'\n    def getvalue(self): return b'Policy "
        "purpose'\ndef persist(*args, **kwargs):\n    "
        "st.session_state['uploaded_bytes'] = kwargs['content']\n    "
        "st.session_state['persisted'] = True\n    return "
        "'saved-policy'\nwith patch.object(ui,'load_policies',side_eff"
        "ect=lambda *a: ([saved],[{'version':1,'records':[saved]}]) "
        "if st.session_state.get('persisted') else ([],[])), "
        "patch.object(ui,'get_workspace_role',return_value='Administr"
        "ator'), patch.object(ui,'list_control_overview',return_value"
        "=[]), patch.object(ui,'upload_policy',side_effect=persist), "
        "patch.object(ui,'policy_editor',return_value=SimpleNamespace"
        "(save=None)), patch.object(st,'file_uploader',side_effect=la"
        "mbda *a,**k: [] if k.get('accept_multiple_files') else "
        "Upload()):\n    ui.render_policy_workspace_legacy('Client', "
        "{'selected_engagement_id':1,'selected_scope_id':2})\n"
    )
    app = AppTest.from_string(script).run()
    next(b for b in app.button if b.label == "Upload and save draft").click().run()
    assert not app.exception
    assert app.session_state["uploaded_bytes"] == b"Policy purpose"
    assert app.session_state["policies::Client::1::2::selected"] == "saved-policy"


def test_guided_builder_preserves_untouched_sections():
    from securescope.policies.builder import apply_section_edits

    blocks = [
        {"kind": "h1", "runs": [{"text": "Purpose"}]},
        {"kind": "p", "runs": [{"text": "Old purpose"}]},
        {"kind": "h2", "runs": [{"text": "Responsibilities"}]},
        {"kind": "p", "runs": [{"text": "Owner", "bold": True}]},
    ]
    result = apply_section_edits(blocks, {"0": "New purpose"})
    assert result[1]["runs"][0]["text"] == "New purpose"
    assert result[3]["runs"][0]["bold"]
    assert len(result) == 4


def test_calendar_foreign_asset_link_is_rejected():
    from securescope.persistence.workspace_planning import validate_payload

    cursor = Mock()
    cursor.fetchone.return_value = None
    with pytest.raises(FoundationError, match="this workspace"):
        validate_payload(
            cursor,
            7,
            "calendar_event",
            "",
            {
                "title": "Review",
                "starts_at": "2026-09-14T12:00:00+00:00",
                "linked_type": "Asset",
                "linked_reference": "10.1.1.1",
            },
            "Administrator",
        )


def test_supporting_narratives_are_encrypted(monkeypatch):
    from securescope.persistence.workspace_planning import protect_text

    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    payload = {"policy_id": "p1", "body": "Confidential reviewer note", "parent": ""}
    encrypted = protect_text(payload)
    assert "body" not in encrypted
    assert "Confidential" not in str(encrypted)
    assert encrypted["policy_id"] == "p1"
    assert protect_text(encrypted, decrypt=True) == payload
