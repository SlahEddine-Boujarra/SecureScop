"""Focused UI regressions for scoped evidence, stable criteria and risk defaults."""

from unittest.mock import Mock

from streamlit.testing.v1 import AppTest

from securescope.grc.assurance_requirements import evaluate_assurance
from securescope.ui import assurance_dashboard, assurance_workbench, evidence_hub_ui
from securescope.ui.control_assessment_ui import requirement_assessment_rows
from securescope.ui.grc_workspace import context


def test_assessment_preserves_stable_ids_and_saved_overrides():
    requirements = [dict(id="r1", title="Logging"), dict(id="r2", title="Policy")]
    results = [
        dict(id="r1", result="PASS", evidence_ids=[7]),
        dict(id="r2", result="PASS", policy_versions=[dict(id="p1", version=3)]),
    ]
    draft = {
        "criteria": [
            dict(criterion_identifier="r1", result="Partial", evidence_reference="Exception report")
        ]
    }
    rows = requirement_assessment_rows(requirements, results, draft)
    assert rows[0] == dict(
        criterion_identifier="r1",
        description="Logging",
        result="Partial",
        evidence_reference="Exception report",
    )
    assert rows[1]["evidence_reference"] == "Policy p1 v3"
    assert (
        requirement_assessment_rows(requirements, results, {})[0]["evidence_reference"]
        == "Evidence #7"
    )


def test_evidence_register_defaults_to_scope_and_wider_view_is_explicit(monkeypatch):
    load = Mock(return_value=[])
    monkeypatch.setattr(evidence_hub_ui, "list_evidence_records", load)
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 9))
    app = AppTest.from_string("""
from securescope.ui.evidence_hub_ui import _evidence_register
_evidence_register("Client", "Reviewer", None)
""").run()
    assert not app.exception
    assert load.call_args.kwargs == dict(scope_id=9, engagement_id=2)
    app.selectbox[0].set_value("All Client Evidence").run()
    assert not app.exception
    assert load.call_args.kwargs == dict(scope_id=None, engagement_id=2)


def test_new_risk_defaults_to_current_scope_without_touching_existing_rows(monkeypatch):
    state = {}
    monkeypatch.setattr(assurance_workbench.st, "session_state", state)
    existing = [dict(risk_ref=1, primary_scope_id=None)]
    assurance_workbench.dispatch_risk(
        "Client",
        "Owner",
        "risk::Client",
        dict(action="risk_new", payload={}, selected=None),
        existing,
        {},
        [],
        None,
        current_scope_id=9,
    )
    assert state["risk::Client:new"]["primary_scope_id"] == 9
    assert existing == [dict(risk_ref=1, primary_scope_id=None)]


def test_dashboard_unassessed_empty_state_has_no_false_conformity(monkeypatch):
    from securescope.persistence import grc_repository

    monkeypatch.setattr(
        grc_repository, "list_statement_of_applicability_versions", lambda *a, **k: []
    )
    from datetime import datetime, timezone

    result = evaluate_assurance(
        {"profile": {"assessment_scope": {}}}, now=datetime.now(timezone.utc)
    )
    entry = dict(control_id="A.8.16", title="Monitoring", owner="", result=result, open_work=0)
    monkeypatch.setattr(assurance_dashboard, "selected_context_ids", lambda client: (2, 9))
    monkeypatch.setattr(assurance_dashboard, "current_actor", lambda: "Auditor")
    monkeypatch.setattr(assurance_dashboard, "assurance_overview", lambda *args: [entry])
    from securescope.ui.components_v2 import assurance_pages

    captured = {}
    monkeypatch.setattr(
        assurance_pages, "assurance_page", lambda data, **kwargs: captured.update(data)
    )
    app = AppTest.from_string("""
from securescope.ui.assurance_dashboard import render_assurance_dashboard
render_assurance_dashboard("Client", [])
""").run()
    assert not app.exception
    metrics = {m["label"]: m["value"] for m in captured["coverage"]}
    assert metrics["Implementation Coverage"] == "Not Assessed"
    assert metrics["Open Requirement Gaps"] == "Not Determined"
    assert metrics["Assessment Coverage"] == "0.0%"
    assert "Requires Assessment" in assurance_dashboard.attention_categories(entry)


def test_audit_scope_copy_prefills_without_mutating_formal_scope(monkeypatch):
    from copy import deepcopy

    from securescope.persistence import grc_workspace_repository
    from securescope.ui import exposure_management_ui

    saved = dict(
        audit_no="AUD-001",
        audit_year=2026,
        status="Draft",
        scope_statement="Original audit boundary",
        exclusions="Keep exclusion",
    )
    formal = dict(
        scope_statement="Formal scope",
        locations=["Office"],
        organizational_units=["Operations"],
        technologies=["Cloud"],
    )
    before = deepcopy(formal)
    monkeypatch.setattr(exposure_management_ui, "load_audit_scope", lambda client: deepcopy(saved))
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 9))
    monkeypatch.setattr(grc_workspace_repository, "list_scope_versions", lambda *args: [formal])
    save = Mock()
    monkeypatch.setattr(exposure_management_ui, "save_audit_scope", save)
    app = AppTest.from_string("""
from securescope.ui.exposure_management_ui import _render_audit_scope_workspace
_render_audit_scope_workspace("Client", [])
""").run()
    assert not app.exception
    assert not app.text_area
    next(button for button in app.button if button.label == "Edit Audit Scope").click().run()
    assert not app.exception
    next(button for button in app.button if button.label == "Use Current ISMS Scope").click().run()
    assert not app.exception
    values = {field.label: field.value for field in app.text_area}
    assert values["Scope statement"] == "Formal scope"
    assert values["Sites / locations"] == "Office"
    assert values["Exclusions and justification"] == "Keep exclusion"
    assert formal == before
    save.assert_not_called()
