"""State transitions, non-destructive composition and tenant-owned scope links."""

from unittest.mock import MagicMock

import pytest

from securescope.grc.scope_workflow import (
    compose_scope_proposal,
    display_person,
    filter_scope_risks,
    scope_changes,
)
from securescope.persistence import grc_workspace_repository as repository
from securescope.persistence import risk_links
from securescope.persistence.foundation_repository import FoundationError


def repository_cursor(monkeypatch, version, role="Administrator"):
    """Provide a locked repository cursor without a live database."""
    cursor = MagicMock()
    cursor.fetchone.return_value = version
    connection = MagicMock()
    connection.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(repository, "connect", lambda: connection)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    monkeypatch.setattr(repository, "_client_id", lambda *a: 42)
    monkeypatch.setattr(repository, "_engagement", lambda *a, **k: {})
    monkeypatch.setattr(repository, "_scope", lambda *a, **k: {})
    monkeypatch.setattr(repository, "_workspace_member", lambda *a, **k: {"workspace_role": role})
    monkeypatch.setattr(repository, "_append_audit_event", lambda *a, **k: None)
    return cursor


@pytest.mark.parametrize("status", ["Draft", "Under review", "Changes requested"])
def test_approval_cannot_skip_recorded_review(monkeypatch, status):
    """Drafts and submitted versions cannot jump to approval."""
    cursor = repository_cursor(monkeypatch, {"id": 4, "status": status})
    with pytest.raises(repository.GrcWorkspaceRepositoryError, match="cannot be approved"):
        repository.approve_scope_version(
            "Client", 7, 9, 4, approver_email="admin", comment="Approved"
        )
    assert not any(
        "UPDATE" in c.args[0] and "SET status" in c.args[0] for c in cursor.execute.call_args_list
    )


@pytest.mark.parametrize(
    "status,role",
    [("Draft", "Administrator"), ("Approved", "Administrator"), ("Under review", "Auditor")],
)
def test_review_requires_submission_and_reviewer_permission(monkeypatch, status, role):
    """Review rejects both wrong states and read-only roles."""
    repository_cursor(monkeypatch, {"id": 4, "status": status}, role)
    with pytest.raises(repository.GrcWorkspaceRepositoryError):
        repository.record_scope_review(
            "Client", 7, 9, 4, actor="reviewer", note="Evidence checked", decision="Reviewed"
        )


def test_review_records_identity_date_and_rationale(monkeypatch):
    """Successful review stores an explicit, distinct decision."""
    cursor = repository_cursor(monkeypatch, {"id": 4, "status": "Under review"})
    repository.record_scope_review(
        "Client", 7, 9, 4, actor="Reviewer", note="Evidence checked", decision="Reviewed"
    )
    query, params = cursor.execute.call_args.args
    assert "reviewed_at=NOW()" in query
    assert params == ("Reviewed", "reviewer", "Evidence checked", 42, 4)


def test_approval_rejects_superseded_review(monkeypatch):
    """A newer draft invalidates an action on an older reviewed version."""
    repository_cursor(monkeypatch, {"id": 5, "status": "Draft"})
    with pytest.raises(repository.GrcWorkspaceRepositoryError, match="Scope changed"):
        repository.approve_scope_version(
            "Client", 7, 9, 4, approver_email="admin", comment="Approved"
        )


def test_composer_retains_manual_fields_and_unions_lists():
    """Generated scope facts cannot erase manual statement or boundaries by default."""
    original = {
        "scope_statement": "Manual",
        "boundaries": "Agreed",
        "locations": ["Tunis"],
        "exclusions": "Factory",
        "interfaces_and_dependencies": "Supplier",
        "owner": "ISMS manager",
        "review_notes": "Reviewed",
    }
    proposed = compose_scope_proposal(
        original,
        {
            "scope_statement": "Generated",
            "boundaries": "Generated",
            "locations": ["Tunis", "Sousse"],
        },
    )
    assert proposed == dict(original, locations=["Tunis", "Sousse"])
    assert original["locations"] == ["Tunis"]
    assert scope_changes(original, proposed)[0]["Added"] == "Sousse"
    assert display_person("migration-005") == "System migration"


def test_composer_explicit_replacement_is_visible_in_diff():
    """Opting into replacement reports removals and new text."""
    original = {"scope_statement": "Manual", "locations": ["Old"]}
    proposed = compose_scope_proposal(
        original,
        {"scope_statement": "New", "locations": ["New"]},
        replace_text=True,
        replace_lists=True,
    )
    assert proposed == {"scope_statement": "New", "locations": ["New"]}
    assert scope_changes(original, proposed)[1]["Removed"] == "Old"


def test_risk_filter_never_guesses_legacy_scope():
    """Current-scope views exclude unassigned and other scopes."""
    rows = [
        {"risk_ref": 1},
        {"risk_ref": 2, "primary_scope_id": 9},
        {"risk_ref": 3, "primary_scope_id": 10},
    ]
    assert filter_scope_risks(rows, "Current ISMS Scope", 9) == [rows[1]]
    assert filter_scope_risks(rows, "Current ISMS Scope", None) == []
    assert filter_scope_risks(rows, "Unassigned scope", 9) == [rows[0]]
    assert filter_scope_risks(rows, "All client risks", 9) == rows


@pytest.mark.parametrize("scope_id", [True, "9", 0, -1])
def test_invalid_scope_identifiers_rejected(scope_id):
    """Risk links require a positive typed scope ID or null."""
    with pytest.raises(FoundationError, match="valid ISMS scope"):
        risk_links.save_assessment(
            "Client",
            {"risk_ref": 1, "primary_scope_id": scope_id},
            actor="actor",
            revision=0,
            group="default",
            metadata_revision=0,
            asset_ids=[],
        )


def test_foreign_scope_rejected_before_canonical_write(monkeypatch):
    """Client ownership is checked inside the canonical save transaction."""
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    monkeypatch.setattr(risk_links, "member_role", lambda *a: "Consultant")

    def save(client, record, **kwargs):
        kwargs["authorize"](cursor, 42)

    monkeypatch.setattr(risk_links, "save_risk_record", save)
    with pytest.raises(FoundationError, match="outside this client"):
        risk_links.save_assessment(
            "Client",
            {"risk_ref": 1, "primary_scope_id": 9},
            actor="actor",
            revision=0,
            group="default",
            metadata_revision=0,
            asset_ids=[],
        )
    assert cursor.execute.call_args.args[1] == (42, 9, 1)


def test_scope_link_and_audit_share_canonical_save_transaction(monkeypatch):
    """Explicit scope changes update the existing risk row and retain unrelated metadata."""
    cursor = MagicMock()
    cursor.fetchall.return_value = []
    cursor.fetchone.side_effect = [{"id": 9}, None, {"primary_scope_id": None}]
    monkeypatch.setattr(risk_links, "member_role", lambda *a: "Consultant")
    monkeypatch.setattr(risk_links, "protect_text", lambda p, **k: p)

    def save(client, record, **kwargs):
        kwargs["authorize"](cursor, 42)
        kwargs["after_save"](cursor, 42, {1: 1})

    monkeypatch.setattr(risk_links, "save_risk_record", save)
    risk_links.save_assessment(
        "Client",
        {"risk_ref": 1, "primary_scope_id": 9},
        actor="actor",
        revision=0,
        group="default",
        metadata_revision=0,
        asset_ids=[],
    )
    assert any(
        "SET primary_scope_id" in c.args[0] and c.args[1] == (9, 42, 1)
        for c in cursor.execute.call_args_list
    )
    assert any("risk.scope_changed" in c.args[0] for c in cursor.execute.call_args_list)


@pytest.mark.parametrize("historical", [False, True])
def test_objective_past_date_requires_explicit_confirmation(monkeypatch, historical):
    """The server rejects a historical date unless the save explicitly acknowledges it."""
    from types import SimpleNamespace

    from streamlit.testing.v1 import AppTest

    from securescope.ui.grc_workspace import stitch_records

    monkeypatch.setattr(stitch_records, "current_actor", lambda: "admin")
    monkeypatch.setattr(stitch_records, "get_workspace_role", lambda *a: "Administrator")
    monkeypatch.setattr(stitch_records, "versions", lambda *a: [])
    saved = MagicMock()
    monkeypatch.setattr(stitch_records, "save_version", saved)
    event = {
        "action": "foundation_objective_save",
        "nonce": "one",
        "expected": 0,
        "payload": {
            "index": None,
            "record": {"title": "Historic target", "due_date": "2000-01-01"},
            "historical": historical,
        },
    }
    monkeypatch.setattr(
        stitch_records, "assurance_workbench", lambda *a, **k: SimpleNamespace(action=event)
    )
    app = AppTest.from_string(
        "from securescope.ui.grc_workspace.stitch_records import render_stitch_records\n"
        'render_stitch_records("Client", {"selected_engagement_id": 7, '
        '"selected_scope_id": 9}, "objectives", {})'
    ).run()
    assert not app.exception
    assert saved.called is historical
    response = app.session_state["stitch::Client::7::9::objectives:response"]
    if historical:
        assert "saved" in response["message"]
    else:
        assert "current overdue or historical" in response["error"]


@pytest.mark.parametrize("role,stale", [("Auditor", False), ("Administrator", True)])
def test_record_edit_rejects_readonly_and_stale_writes(monkeypatch, role, stale):
    """UI edit actions cannot bypass permissions or concurrency checks."""
    cursor = repository_cursor(monkeypatch, {"updated_at": "new" if stale else "old"}, role)
    with pytest.raises(repository.GrcWorkspaceRepositoryError):
        repository.update_foundation_record(
            "Client",
            7,
            9,
            4,
            section="context",
            values={
                "issue_type": "Internal",
                "category": "Technology",
                "title": "Legacy systems",
                "description": "Systems nearing end of support",
                "effect_on_isms": "Patching constraints",
                "relevance": "Relevant",
                "owner": "IT",
                "status": "Monitoring",
            },
            expected_updated_at="old",
            actor="admin",
            note="Reviewed with owner",
        )
    assert not any(
        "UPDATE" in str(call.args[0]) and "SET" in str(call.args[0])
        for call in cursor.execute.call_args_list
    )
