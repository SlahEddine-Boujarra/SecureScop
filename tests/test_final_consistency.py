"""Regression coverage for canonical context, scope decisions and SoA ownership."""

from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.grc.engagement_models import ScopeDraft
from securescope.grc.status_labels import status_label
from securescope.persistence import grc_repository as soa
from securescope.persistence import grc_workspace_repository as scope_repo
from securescope.ui import control_assessment_ui, risk_management
from securescope.ui.grc_workspace import formal, linked_modules, overview, record_tools


def test_all_overview_cards_share_component_and_scope_version(monkeypatch):
    """All eight domains use the same card and Scope is never an empty unit count."""
    cards = []
    monkeypatch.setattr(overview, "overview_card", lambda **values: cards.append(values))
    monkeypatch.setattr(
        formal.SERVICE,
        "load_section",
        lambda *a: {
            "context_issues": [],
            "interested_parties": [],
            "organizational_units": [],
            "role_assignments": [],
        },
    )
    monkeypatch.setattr(formal, "versions", lambda *a: [])
    monkeypatch.setattr(overview, "load_policies", lambda *a: ([], []))
    monkeypatch.setattr(
        overview,
        "list_risk_register",
        lambda *a: [
            {"risk_ref": 1, "primary_scope_id": 9, "control_references": ["A.5.2"]},
            {"risk_ref": 2, "primary_scope_id": 10},
        ],
    )
    monkeypatch.setattr(
        overview, "latest_statement_of_applicability", lambda *a, **k: {"status": "Draft"}
    )
    app = AppTest.from_string(
        "from securescope.ui.grc_workspace.overview import render_overview"
        '\nrender_overview("Client", {"selected_engagement_id":7,"selected_'
        'scope_id":9,"scopes":[{"id":9,"name":"Production","latest_status"'
        ':"Draft","latest_version_number":2,"organizational_units":["IT"]}'
        "]},lambda section:None)"
    ).run()
    assert not app.exception
    assert len(cards) == 8
    scope = next(c for c in cards if c["title"] == "ISMS Scope")
    assert dict(scope["metrics"])["Version"] == 2
    assert "Records" not in dict(scope["metrics"])
    risk = next(c for c in cards if c["title"] == "Risk Assessment")
    assert dict(risk["metrics"])["Recorded risks"] == 1
    treatment = cards[-1]
    assert dict(treatment["metrics"])["SoA status"] == "Draft"
    assert dict(treatment["metrics"])["Linked controls"] == 1
    assert treatment["actions"][0][0] == "Open Risk Management"


@pytest.mark.parametrize(
    "state,label,checkbox",
    [
        ("Draft", "Submit for Review", None),
        ("Under review", "Mark Reviewed", "I reviewed this scope version and its boundaries."),
        ("Reviewed", "Approve Scope", "I authorize approval of this reviewed scope version."),
        ("Approved", None, None),
    ],
)
def test_scope_decisions_have_distinct_controls(monkeypatch, state, label, checkbox):
    """Submission, review and approval never share a confirmation."""
    monkeypatch.setattr(
        record_tools,
        "list_scope_versions",
        lambda *a: [{"id": 4, "version_number": 2, "status": state}],
    )
    app = AppTest.from_string(
        "from securescope.ui.grc_workspace.record_tools import _scope_tool"
        's\n_scope_tools("Client",7,9,"admin","Administrator","review")'
    ).run()
    assert not app.exception
    buttons = [b.label for b in app.button]
    assert ("Approve Scope" in buttons) == (state == "Reviewed")
    assert ("Submit for Review" in buttons) == (state == "Draft")
    assert [c.label for c in app.checkbox] == ([checkbox] if checkbox else [])
    if label:
        assert label in buttons


def test_related_treatments_default_to_scope_and_navigation_resets_stale_filter(monkeypatch):
    """Scope-specific treatments navigate with a fresh current-scope filter."""
    monkeypatch.setattr(
        linked_modules,
        "list_risk_register",
        lambda *a: [
            {"risk_ref": 1, "primary_scope_id": 9, "treatment_option": "Modify"},
            {"risk_ref": 2, "primary_scope_id": 10, "treatment_option": "Modify"},
        ],
    )
    monkeypatch.setattr(linked_modules, "list_risk_treatment_plans", lambda *a: [])
    from securescope.ui.components_v2 import assurance_workbench as component

    received = []
    monkeypatch.setattr(
        component,
        "assurance_workbench",
        lambda data, **k: (received.append(data) or SimpleNamespace(action=None)),
    )
    nav = MagicMock()
    monkeypatch.setattr(risk_management, "navigate_to", nav)
    app = AppTest.from_string(
        "import streamlit as st\nfrom securescope.ui.grc_workspace.linked_m"
        'odules import render_treatment_links\nst.session_state["grc_select'
        'ed_engagement::Client"]=7\nst.session_state["grc_selected_scope::C'
        'lient"]=9\nst.session_state["risk_scope_filter::Client"]="All clie'
        'nt risks"\nrender_treatment_links("Client")'
    ).run()
    assert not app.exception
    assert [r["risk_ref"] for r in received[0]["rows"]] == [1]
    next(b for b in app.button if b.label == "Open treatment plan").click().run()
    assert not app.exception
    assert app.session_state["risk_scope_filter::Client::pending"] == "Current ISMS Scope"
    assert app.session_state["risk_management::Client::pending"] == "Treatment plan"
    assert app.session_state["grc_selected_engagement::Client"] == 7
    assert app.session_state["grc_selected_scope::Client"] == 9
    nav.assert_called_with("Risk")


def test_control_target_risk_selector_defaults_to_scope(monkeypatch):
    """Only canonical risks in the current scope appear until wider view is selected."""
    monkeypatch.setattr(
        control_assessment_ui,
        "list_risk_register",
        lambda *a: [
            {"risk_ref": 1, "primary_scope_id": 9, "threat": "Current"},
            {"risk_ref": 2, "primary_scope_id": 10, "threat": "Other"},
        ],
    )
    app = AppTest.from_string(
        "import streamlit as st\nfrom securescope.ui.control_assessment_ui "
        'import _target_editor\nst.session_state["grc_selected_scope::Clien'
        't"]=9\n_target_editor("Client",{"control_id":"A.5.2"},"target")'
    ).run()
    assert not app.exception
    assert next(m for m in app.multiselect if m.label == "Risks addressed").options == [
        "R-1 — Current"
    ]
    app.segmented_control[0].set_value("All client risks").run()
    assert len(next(m for m in app.multiselect if m.label == "Risks addressed").options) == 2


def cursor_for(monkeypatch, repo):
    """Bind a deterministic transaction cursor for repository boundary checks."""
    cursor = MagicMock()
    connection = MagicMock()
    connection.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(repo, "connect", lambda: connection)
    monkeypatch.setattr(repo, "run_pending_migrations", lambda: None)
    monkeypatch.setattr(repo, "_client_id", lambda *a: 42)
    return cursor


def test_soa_reads_scope_and_legacy_without_guessing(monkeypatch):
    """The existing association table is the only ownership source."""
    cursor = cursor_for(monkeypatch, soa)
    cursor.fetchone.return_value = None
    soa.latest_statement_of_applicability("Client", engagement_id=7, scope_id=9)
    query, parameters = cursor.execute.call_args.args
    assert parameters == (42, 9, 7, 9, 9, None, None)
    assert "link.link_origin <> 'Legacy backfill'" in query
    soa.list_statement_of_applicability_versions("Client")
    assert cursor.execute.call_args.args[1] == (42, None, None, None, None)


def test_legacy_soa_assignment_preserves_original_version_and_items(monkeypatch):
    """Explicit assignment creates a link and audit event, not another SoA."""
    cursor = cursor_for(monkeypatch, soa)
    cursor.fetchone.side_effect = [(1,), ("Administrator",), (17,), None]
    soa.assign_legacy_soa_scope(
        "Client",
        17,
        engagement_id=7,
        scope_id=9,
        actor="admin",
        rationale="Confirmed original scope",
    )
    queries = [c.args[0] for c in cursor.execute.call_args_list]
    assert any("INSERT INTO securescope_engagement_record_links" in q for q in queries)
    assert not any(
        "INSERT INTO securescope_soa" in q or "UPDATE securescope_soa" in q or "DELETE" in q
        for q in queries
    )


@pytest.mark.parametrize(
    "results",
    [
        [None],
        [(1,), ("Auditor",)],
        [(1,), ("Administrator",), None],
        [(1,), ("Administrator",), (17,), (33,)],
    ],
)
def test_soa_assignment_rejects_foreign_denied_missing_or_already_assigned(monkeypatch, results):
    """Ownership and permission failures never create associations."""
    cursor = cursor_for(monkeypatch, soa)
    cursor.fetchone.side_effect = results
    with pytest.raises(soa.GrcRepositoryError):
        soa.assign_legacy_soa_scope(
            "Client", 17, engagement_id=7, scope_id=9, actor="actor", rationale="Reviewed"
        )
    assert not any("INSERT" in c.args[0] for c in cursor.execute.call_args_list)


def test_new_scoped_soa_writes_same_version_with_association(monkeypatch):
    """Version and scope association are saved within the same transaction."""
    cursor = cursor_for(monkeypatch, soa)
    cursor.fetchone.side_effect = [(1,), ("Administrator",), (3,), (17,), None]
    result = soa.save_statement_of_applicability(
        "Client",
        [
            {
                "control_id": "A.5.2",
                "applicability": "Applicable",
                "inclusion_justification": "Required",
            }
        ],
        prepared_by="actor",
        engagement_id=7,
        scope_id=9,
        actor="actor",
    )
    assert result == 3
    inserts = [
        c
        for c in cursor.execute.call_args_list
        if "INSERT INTO securescope_soa_versions" in c.args[0]
    ]
    assert len(inserts) == 1
    assert any(
        "soa-scope:17" in c.args[1]
        for c in cursor.execute.call_args_list
        if "INSERT INTO securescope_engagement_record_links" in c.args[0]
    )


def test_unchanged_scope_does_not_create_identical_version(monkeypatch):
    """Saving unchanged editor content returns the existing canonical version."""
    draft = ScopeDraft(
        scope_code="PROD", name="Production", scope_statement="Current scope", boundaries="Services"
    )
    cursor = cursor_for(monkeypatch, scope_repo)
    monkeypatch.setattr(scope_repo, "_engagement", lambda *a, **k: {})
    monkeypatch.setattr(
        scope_repo, "_scope", lambda *a, **k: {"scope_code": "PROD", "name": "Production"}
    )
    cursor.fetchone.return_value = dict(asdict(draft), id=4, version_number=2, status="Draft")
    result = scope_repo.create_scope_version("Client", 7, draft, actor="actor", scope_id=9)
    assert result["unchanged"] and result["version_number"] == 2
    assert not any(
        "INSERT" in c.args[0] or "SET name" in c.args[0] for c in cursor.execute.call_args_list
    )


def test_status_labels_keep_domain_enums():
    """Display normalization does not require rewriting historical values."""
    assert status_label("Under review") == "Submitted for Review"
    assert status_label("Changes requested") == "Changes Requested"
    assert status_label("In progress") == "In Progress"
    assert status_label("Approved") == "Approved"
