"""Document safety, per-policy review, encryption and UI regression tests."""

import io
import json
from contextlib import contextmanager
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from cryptography.fernet import Fernet
from streamlit.testing.v1 import AppTest

from securescope.policies import repository as repo
from securescope.policies.documents import extract_document, render_document, validate_blocks

BLOCKS = [
    {"kind": "h1", "runs": [{"text": "Purpose"}]},
    {"kind": "p", "runs": [{"text": "Protect information.", "bold": True}]},
]
POLICY_ID = "ebd27b01-5afd-407b-a4ce-034c5bda87d1"


def test_text_document_is_not_executable_html():
    """Verify text document is not executable html.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    extracted = extract_document("policy.md", b"# Purpose\n<script>alert(1)</script>")
    assert extracted["blocks"][0]["kind"] == "h1"
    assert "<script>" not in render_document(extracted["blocks"])
    assert "&lt;script&gt;" in render_document(extracted["blocks"])


def test_docx_heading_and_bold_are_extracted():
    """Verify docx heading and bold are extracted.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(
            "word/document.xml",
            (
                (
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordp'
                    'rocessingml/2006/main"><w:body><w:p><w:pPr><w:pStyle '
                    'w:val="Heading1"/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t>Pur'
                    "pose</w:t></w:r></w:p></w:body></w:document>"
                )
            ),
        )
    result = extract_document("policy.docx", buffer.getvalue())
    assert result["blocks"][0]["kind"] == "h1"
    assert result["blocks"][0]["runs"][0]["bold"]


@pytest.mark.parametrize(
    "name,content",
    [
        ("bad.docx", b"not a zip"),
        ("policy.pdf", b"%PDF"),
        ("policy.txt", b"\xff"),
        ("empty.txt", b""),
    ],
)
def test_bad_uploads_fail_clearly(name, content):
    """Verify bad uploads fail clearly.

    Args:
        name: Test fixture or scenario input.
        content: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    with pytest.raises(ValueError):
        extract_document(name, content)


@pytest.mark.parametrize(
    "blocks", [[], [{"kind": "script", "runs": []}], [{"kind": "p", "runs": [{"text": 5}]}]]
)
def test_invalid_editor_events_are_rejected(blocks):
    """Verify invalid editor events are rejected.

    Args:
        blocks: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    with pytest.raises(ValueError):
        validate_blocks(blocks)


def install_cursor(monkeypatch, role="Administrator", snapshot=None):
    """Install cursor.

    Args:
        monkeypatch: Test fixture or scenario input.
        role: Test fixture or scenario input.
        snapshot: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    cursor = Mock()
    cursor.fetchone.side_effect = [{"role": role}, {"exists": 1}, snapshot]
    cursor.fetchall.return_value = [{"control_id": "A.5.1"}]

    @contextmanager
    def transaction(_client):
        """Transaction.

        Args:
            _client: Test fixture or scenario input.
        Returns:
            Test result or configured fixture.
        Raises:
            AssertionError: If the expected contract fails.
        """
        yield cursor, 7

    monkeypatch.setattr(repo, "workspace_cursor", transaction)
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    return cursor


def save(**kwargs):
    """Save.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    args = dict(
        actor="admin@example.com",
        policy_id=POLICY_ID,
        expected_version=0,
        status="Draft",
        note="Initial content",
        metadata={
            "title": "Policy",
            "owner": "Owner",
            "controls": ["A.5.1"],
            "reviewer": "Reviewer",
            "review_date": "2027-01-01",
        },
        blocks=BLOCKS,
    )
    args.update(kwargs)
    return repo.save_policy("Client", 1, 2, **args)


def test_draft_encrypts_content_and_original(monkeypatch):
    """Verify draft encrypts content and original.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    cursor = install_cursor(monkeypatch)
    assert save(source=b"Original source") == 1
    rows = cursor.execute.call_args.args[1][5].adapted
    assert "Protect information" not in json.dumps(rows)
    payload = repo.document_payload(rows[0])
    assert payload["blocks"][1]["runs"][0]["text"] == "Protect information."
    assert payload["source_base64"]


def test_auditor_cannot_write(monkeypatch):
    """Verify auditor cannot write.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    install_cursor(monkeypatch, role="Auditor")
    with pytest.raises(repo.PolicyError, match="contributor"):
        save()


def test_stale_policy_revision_is_rejected(monkeypatch):
    """Verify stale policy revision is rejected.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    install_cursor(monkeypatch, snapshot={"version": 2, "records": []})
    with pytest.raises(repo.PolicyError, match="another session"):
        save()


def test_approval_does_not_accept_edited_content(monkeypatch):
    """Verify approval does not accept edited content.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    install_cursor(monkeypatch)
    with pytest.raises(repo.PolicyError, match="Save content"):
        save(status="Approved")


def test_individual_approval_preserves_other_policy(monkeypatch):
    """Verify individual approval preserves other policy.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    first = dict(
        policy_id=POLICY_ID, policy_version=2, status="In review", title="Policy", owner="Owner"
    )
    other = dict(
        policy_id="other", policy_version=5, status="Draft", title="Other", owner="Other owner"
    )
    cursor = install_cursor(monkeypatch, snapshot={"version": 7, "records": [first, other]})
    assert save(status="Approved", expected_version=7, blocks=None, metadata={}) == 8
    values = cursor.execute.call_args.args[1]
    rows = values[5].adapted
    assert rows[0]["status"] == "Approved"
    assert rows[0]["approved_by"] == "admin@example.com"
    assert rows[1] == other | {"controls": []}
    assert values[4] == "Draft"


def test_policy_workspace_empty_and_readonly_renders():
    """Verify policy workspace empty and readonly renders.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    script = (
        "\nfrom unittest.mock import patch\nfrom securescope.ui import "
        "policy_workspace as ui\nwith patch.object(ui, "
        '"load_policies", return_value=([], [])), patch.object(ui, '
        '"get_workspace_role", return_value="Auditor"), '
        'patch.object(ui, "list_control_overview", '
        "return_value=[]):\n    "
        'ui.render_policy_workspace_legacy("Client", '
        '{"selected_engagement_id":1,"selected_scope_id":2})\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert all(item.disabled for item in app.button)


def test_policy_document_detail_and_history_render():
    """Verify policy document detail and history render.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    script = (
        "\nimport streamlit as st\nfrom types import "
        "SimpleNamespace\nfrom unittest.mock import patch\nfrom "
        "securescope.ui import policy_workspace as ui\nrow = "
        '{"policy_id":"abc","policy_version":1,"status":"Draft","titl'
        'e":"Policy","owner":"Owner","policy_text":"Existing policy '
        'content","controls":[]}\nst.session_state["policies::Client::'
        '1::2::selected"]="abc"\nwith '
        'patch.object(ui,"load_policies",return_value=([row],[{"versi'
        'on":1,"records":[row]}])), '
        'patch.object(ui,"get_workspace_role",return_value="Auditor")'
        ', patch.object(ui,"list_control_overview",return_value=[]), '
        'patch.object(ui,"policy_editor",return_value=SimpleNamespace'
        '(save=None)):\n    ui.render_policy_workspace_legacy("Client"'
        ', {"selected_engagement_id":1,"selected_scope_id":2})\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert [tab.label.split(": ", 1)[-1] for tab in app.tabs] == [
        "Policy versions",
        "Review",
        "Mapped elements",
        "Version history",
        "Guided builder",
        "Audits and comments",
    ]


def test_risk_matrix_excludes_unassessed_values():
    """Verify risk matrix excludes unassessed values.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    script = (
        "\nfrom securescope.ui.security_visuals import "
        'risk_matrix\nrisk_matrix([{"pre_likelihood":4,"pre_impact":5}'
        ', {"pre_likelihood":None,"pre_impact":4}], '
        'key="matrix")\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert "1 without complete ratings" in app.caption[0].value


def test_shared_reading_table_search_filters_rows():
    """Verify shared reading table search filters rows.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    script = (
        "\nfrom securescope.ui.components.primitives import "
        'readable_table\nreadable_table([{"Asset":f"Server-{number}","'
        'Risk":number} for number in range(6)], '
        'key="assets-test")\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    app.text_input[0].input("Server-3").run()
    assert not app.exception
    assert any(
        "Server-3" in item.proto.body and "Server-4" not in item.proto.body
        for item in app.get("html")
    )


def test_pdf_export_escapes_markup_and_marks_draft():
    """Verify pdf export escapes markup and marks draft.

    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    from securescope.reporting.policy_export import policy_pdf

    row = dict(title="<Policy>", policy_version=1, status="Draft", owner="Owner", controls=[])
    result = policy_pdf(
        row, [{"kind": "p", "runs": [{"text": "<script>not markup</script> & text"}]}]
    )
    assert result.startswith(b"%PDF")


def test_review_requires_assigned_reviewer_and_date(monkeypatch):
    """Verify review requires assigned reviewer and date.

    Args:
        monkeypatch: Test fixture or scenario input.
    Returns:
        Test result or configured fixture.
    Raises:
        AssertionError: If the expected contract fails.
    """
    row = dict(policy_id=POLICY_ID, policy_version=1, status="Draft", title="Policy", owner="Owner")
    install_cursor(monkeypatch, snapshot={"version": 1, "records": [row]})
    with pytest.raises(repo.PolicyError, match="reviewer and review date"):
        save(status="In review", expected_version=1, blocks=None, metadata={})


def test_rich_editor_registers_with_structured_data():
    """Verify component registration without pretending to run browser JavaScript.

    Returns:
        None.
    Raises:
        AssertionError: If Streamlit rejects the editor declaration.
    """
    app = AppTest.from_string(
        (
            "\nfrom securescope.ui.components_v2.policy_editor import "
            'policy_editor\npolicy_editor([{"kind":"p","runs":[{"text":"<b'
            '>plain text</b>"}]}], key="editor", read_only=False, '
            "saved=False)\n"
        )
    ).run()
    assert not app.exception
