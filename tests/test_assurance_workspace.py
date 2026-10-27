"""Repository and runtime regressions for the existing scoped Control Profile model."""

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.persistence import assurance_workspace_repository as repository
from securescope.ui import control_workspace as ui


@pytest.fixture
def storage(monkeypatch):
    """Replace transport while retaining repository validation and profile versioning calls."""
    cursor = MagicMock()
    cursor.fetchone.return_value = {"id": 9}
    cursor.fetchall.return_value = []

    @contextmanager
    def transaction(client):
        """Yield a scoped transaction for testing authorization and written relationships."""
        yield cursor, 1

    profile = dict(
        control_id="A.8.15",
        profile_version=4,
        measurement_model="checklist",
        control_owner="Owner",
        assessment_owner="Reviewer",
        assessment_scope={"description": "Approved boundary"},
        assessment_methods=["Test"],
        evidence_requirements=["Reports"],
        supported_data_sources=[],
    )
    monkeypatch.setattr(repository, "workspace_cursor", transaction)
    monkeypatch.setattr(repository, "member_role", lambda *args: "Administrator")
    monkeypatch.setattr(repository, "_load_bundle", lambda *args: {"profile": deepcopy(profile)})
    monkeypatch.setattr(repository, "_documents", lambda *args: [])
    monkeypatch.setattr(repository, "_evidence", lambda *args: [])
    write = MagicMock(return_value=5)
    monkeypatch.setattr(repository, "create_profile_version", write)
    return cursor, profile, write


def criterion():
    """Return a valid organization-defined manual criterion."""
    return dict(
        id="r1",
        title="Review logs",
        expected_result="Review security events weekly.",
        type="Operational",
        mandatory=True,
        rule="Manual validation",
        asset_ids=[],
    )


def test_requirement_create_and_remove_reuse_immutable_profile_versions(storage):
    _, profile, write = storage
    original = deepcopy(profile)
    assert (
        repository.save_requirements(
            "Client", "A.8.15", "Admin", 2, 9, 4, [criterion()], auto=False, owner="Owner"
        )
        == 5
    )
    saved = write.call_args.kwargs
    assert saved["context_scope_id"] == 9
    assert saved["expected_profile_version"] == 4
    assert saved["assessment_scope"]["implementation_requirements"]["requirements"][0]["id"] == "r1"
    assert profile == original
    repository.save_requirements(
        "Client", "A.8.15", "Admin", 2, 9, 4, [], auto=False, owner="Owner"
    )
    assert (
        write.call_args.kwargs["assessment_scope"]["implementation_requirements"]["requirements"]
        == []
    )


def test_consultant_cannot_enable_automatic_assurance(storage, monkeypatch):
    monkeypatch.setattr(repository, "member_role", lambda *args: "Consultant")
    with pytest.raises(repository.FoundationError, match="Administrator"):
        repository.save_requirements(
            "Client", "A.8.15", "Consultant", 2, 9, 4, [criterion()], auto=True, owner="Owner"
        )
    storage[2].assert_not_called()


def test_foreign_policy_evidence_and_party_links_are_rejected(storage):
    for links in ({"policy_ids": ["foreign"]}, {"evidence_links": [{"evidence_id": 77}]}):
        with pytest.raises(repository.FoundationError):
            repository.save_requirements(
                "Client",
                "A.8.15",
                "Admin",
                2,
                9,
                4,
                [dict(criterion(), **links)],
                auto=False,
                owner="Owner",
            )
    storage[2].assert_not_called()


def test_foreign_scope_is_rejected_before_profile_write(storage):
    storage[0].fetchone.return_value = None
    with pytest.raises(repository.FoundationError, match="Scope"):
        repository.save_requirements(
            "Client", "A.8.15", "Admin", 2, 9, 4, [criterion()], auto=False, owner="Owner"
        )
    storage[2].assert_not_called()


def test_evidence_mapping_does_not_overwrite_historical_source(storage, monkeypatch):
    audit = MagicMock()
    monkeypatch.setattr(repository, "_append_audit_event", audit)
    repository.link_evidence_scope(
        "Client", "A.8.15", "Admin", 2, 9, 8, "Scoped evidence inspected."
    )
    sql = "\n".join(c.args[0] for c in storage[0].execute.call_args_list)
    assert "INSERT INTO securescope_engagement_record_links" in sql
    assert "INSERT INTO securescope_evidence_control_mappings" in sql
    assert "UPDATE securescope_evidence_records" not in sql
    assert "DELETE" not in sql
    assert audit.call_args.kwargs["payload"]["scope_id"] == 9


def test_control_navigation_keeps_client_engagement_and_scope(monkeypatch):
    from securescope.ui import risk_management
    from securescope.ui.grc_workspace.context import workspace_state_keys

    route = MagicMock()
    monkeypatch.setattr(risk_management, "navigate_to", route)
    engagement_key, scope_key = workspace_state_keys("Client")
    app = AppTest.from_string(f"""
import streamlit as st
from securescope.ui.control_workspace import _navigate
st.session_state[{engagement_key!r}]=2
st.session_state[{scope_key!r}]=9
st.session_state['risk_scope_filter::Client']='All Client Risks'
_navigate('Client','A.8.15','risk',14)
""").run()
    assert not app.exception
    assert app.session_state[scope_key] == 9
    assert app.session_state[engagement_key] == 2
    assert app.session_state["risk_scope_filter::Client::pending"] == "Current ISMS Scope"


def test_workspace_requirement_form_has_explicit_save_and_stable_identity(monkeypatch):
    profile = dict(
        control_id="A.8.15",
        control_name="Logging",
        control_owner="Security",
        profile_version=4,
        assessment_scope={
            "implementation_requirements": {
                "requirements": [criterion()],
                "baseline_template_version": 2,
            }
        },
    )
    result = dict(
        requirements=[
            dict(criterion(), result="NO EVIDENCE", reason="Missing evidence", freshness="Missing")
        ],
        implementation="Insufficient Evidence",
        assurance="Not Assessed",
        mandatory_count=1,
        satisfied=0,
    )
    view = dict(
        role="Administrator",
        history=[],
        result=result,
        bundle=dict(
            profile=profile,
            engagement_id=2,
            scope_id=9,
            documents=[],
            requirement_evidence=[],
            party_requirements=[],
            assets=[],
            risks=[],
            actions=[],
        ),
    )
    monkeypatch.setattr(ui, "load_workspace", lambda *args: view)
    monkeypatch.setattr(ui, "selected_context_ids", lambda *args: (2, 9))
    monkeypatch.setattr(ui, "current_actor", lambda: "Admin")
    monkeypatch.setattr(ui, "evidence_choices", lambda *args: [])
    monkeypatch.setattr(
        ui,
        "assurance_workbench",
        lambda *args, **kwargs: SimpleNamespace(
            action={"nonce": "open-r1", "action": "requirement_edit", "payload": {"id": "r1"}}
        ),
    )
    save = MagicMock(return_value=5)
    monkeypatch.setattr(ui, "save_requirements", save)
    app = AppTest.from_string(
        (
            "from securescope.ui.control_workspace import "
            "render_control_workspace\nrender_control_workspace('Client','A.8."
            "15','Administrator')"
        )
    ).run()
    assert not app.exception
    next(b for b in app.button if b.label == "Save requirement").click().run()
    assert not app.exception
    assert save.call_args.args[6][0]["id"] == "r1"
    assert any("requirement updated" in s.value for s in app.success)


def test_profile_edit_preserves_scoped_requirements_and_version_guard(monkeypatch, storage):
    from securescope.ui import control_profiles_workbench as profiles

    _, profile, _ = storage
    config = dict(scope_id=9, engagement_id=2, requirements=[criterion()])
    profile["assessment_scope"]["implementation_requirements"] = config
    profile["automation_level"] = "Manual"
    write = MagicMock(return_value=5)
    monkeypatch.setattr(profiles, "create_profile_version", write)
    profiles.save_profile_edit(
        "Client",
        profile,
        dict(fields={"organization_name": "Local logging"}, expected_version=4),
        "admin@example.test",
    )
    assert write.call_args.kwargs["context_scope_id"] == 9
    assert write.call_args.kwargs["expected_profile_version"] == 4
    assert write.call_args.kwargs["assessment_scope"]["implementation_requirements"] == config


def test_worker_rechecks_enabling_administrator(monkeypatch):
    from securescope.evidence import continuous_assurance as worker

    config = dict(engagement_id=2, scope_id=9, auto_enabled_by="former@example.test")
    monkeypatch.setattr(
        worker,
        "automated_candidates",
        lambda: [
            dict(
                client_name="Client",
                control_id="A.8.15",
                assessment_scope={"implementation_requirements": config},
            )
        ],
    )
    monkeypatch.setattr(worker, "load_workspace", lambda *args: {"role": "Auditor"})
    record = MagicMock()
    monkeypatch.setattr(worker, "record_evaluation", record)
    assert worker.refresh_continuous_assurance() == 0
    record.assert_not_called()


def test_legacy_assessment_does_not_certify_selected_scope(storage, monkeypatch):
    _, profile, _ = storage
    legacy = dict(
        profile=deepcopy(profile),
        assessment=dict(
            id=8,
            validation_status="Validated",
            assessment_status="Implemented and effective",
            created_at="2026-09-21T12:00:00+00:00",
        ),
        validator_authorized=True,
    )
    monkeypatch.setattr(repository, "_load_bundle", lambda *args: legacy)
    view = repository.load_workspace("Client", "A.8.15", "Admin", 2, 9)
    assert view["bundle"]["assessment"] == {}
    assert not view["bundle"]["validator_authorized"]
    assert view["result"]["assurance"] == "Not Assessed"
    assert view["result"]["baseline_preview"]


def test_seed_writes_pending_review_marker_without_overwriting_existing_version(storage):
    _, profile, write = storage
    repository.save_requirements(
        "Client",
        "A.8.15",
        "Admin",
        2,
        9,
        4,
        [criterion()],
        auto=False,
        owner="Owner",
        seed_baseline=True,
    )
    config = write.call_args.kwargs["assessment_scope"]["implementation_requirements"]
    assert config["baseline_template_version"] == 2
    assert config["baseline_review_pending"]
    assert not config["reviewed"]
    assert profile["profile_version"] == 4


def test_identical_requirement_save_reuses_version_and_stale_save_is_rejected(storage):
    _, profile, write = storage
    repository.save_requirements(
        "Client", "A.8.15", "Admin", 2, 9, 4, [criterion()], auto=False, owner="Owner"
    )
    profile["assessment_scope"] = deepcopy(write.call_args.kwargs["assessment_scope"])
    write.reset_mock()
    saved = profile["assessment_scope"]["implementation_requirements"]["requirements"]
    assert (
        repository.save_requirements(
            "Client", "A.8.15", "Admin", 2, 9, 4, saved, auto=False, owner="Owner"
        )
        == 4
    )
    write.assert_not_called()
    with pytest.raises(repository.GrcRepositoryError, match="Reload"):
        repository.save_requirements(
            "Client", "A.8.15", "Admin", 2, 9, 3, saved, auto=False, owner="Owner"
        )
    write.assert_not_called()


@pytest.mark.parametrize(
    "evidence_change",
    [
        {"validation_status": "Pending"},
        {"collected_at": "2000-01-01"},
        {"validator": None},
        {"mapping_approved": False},
    ],
)
def test_requirement_closure_rejects_unreviewed_stale_or_unmapped_proof(
    storage, monkeypatch, evidence_change
):
    from datetime import datetime, timezone

    cursor, profile, _ = storage
    cursor.fetchone.return_value = dict(
        id=9,
        control_id="A.8.15",
        status="Ready for verification",
        dependencies="Control requirement r1",
    )
    requirement = dict(
        criterion(),
        evidence_links=[
            dict(evidence_id=7, conclusion="PASS", rationale="Reviewed actual reports")
        ],
    )
    profile["assessment_scope"] = {
        "implementation_requirements": dict(scope_id=9, requirements=[requirement])
    }
    proof = dict(
        id=7,
        tool_id="manual",
        scope_id=9,
        engagement_id=2,
        mapping_approved=True,
        validation_status="Validated",
        validator="Reviewer",
        validated_at=datetime.now(timezone.utc).isoformat(),
        collected_at=datetime.now(timezone.utc).isoformat(),
        **{},
    )
    proof.update(evidence_change)
    monkeypatch.setattr(repository, "_evidence", lambda *args: [proof])
    with pytest.raises(repository.FoundationError, match="fresh, validated"):
        repository.update_requirement_action(
            "Client", "Admin", 2, 9, 9, "Completed", "Verified reports", evidence_id=7
        )
    assert not any(
        "UPDATE securescope_improvement_actions" in c.args[0] for c in cursor.execute.call_args_list
    )


def test_requirement_closure_reassesses_only_the_related_requirement(storage, monkeypatch):
    from datetime import datetime, timezone

    cursor, profile, _ = storage
    cursor.fetchone.return_value = dict(
        id=9,
        control_id="A.8.15",
        status="Ready for verification",
        dependencies="Control requirement r1",
    )
    requirement = dict(
        criterion(),
        evidence_links=[
            dict(evidence_id=7, conclusion="PASS", rationale="Reviewed actual reports")
        ],
    )
    profile["assessment_scope"] = {
        "implementation_requirements": dict(
            scope_id=9, requirements=[requirement, dict(criterion(), id="unresolved")]
        )
    }
    proof = dict(
        id=7,
        tool_id="manual",
        scope_id=9,
        engagement_id=2,
        mapping_approved=True,
        validation_status="Validated",
        validator="Reviewer",
        validated_at=datetime.now(timezone.utc).isoformat(),
        collected_at=datetime.now(timezone.utc).isoformat(),
    )
    monkeypatch.setattr(repository, "_evidence", lambda *args: [proof])
    audit = MagicMock()
    monkeypatch.setattr(repository, "_append_audit_event", audit)
    repository.update_requirement_action(
        "Client", "Admin", 2, 9, 9, "Completed", "Verified reports", evidence_id=7
    )
    assert audit.call_args.kwargs["payload"]["verification"]["result"] == "PASS"
    assert audit.call_args.kwargs["payload"]["evidence_id"] == 7
    assert len(profile["assessment_scope"]["implementation_requirements"]["requirements"]) == 2


@pytest.mark.parametrize("view", ["Current ISMS Scope", "All client risks", "Unassigned scope"])
def test_treatment_navigation_preserves_explicit_risk_view(monkeypatch, view):
    from securescope.ui import risk_management

    monkeypatch.setattr(risk_management, "navigate_to", MagicMock())
    app = AppTest.from_string(f"""
import streamlit as st
from securescope.ui.risk_management import open_risk_management
st.session_state['engagement'] = 2
st.session_state['scope'] = 9
open_risk_management('Client', stage='Treatment plan', risk_view={view!r})
""").run()
    assert not app.exception
    assert app.session_state["risk_scope_filter::Client::pending"] == view
    assert app.session_state["scope"] == 9


def test_workspace_remediation_state_and_form_keys_do_not_collide(monkeypatch):
    profile = dict(
        control_id="A.8.15",
        control_name="Logging",
        control_owner="Security",
        profile_version=4,
        assessment_scope={
            "implementation_requirements": {
                "requirements": [criterion()],
                "baseline_template_version": 2,
            }
        },
    )
    result = dict(
        requirements=[
            dict(criterion(), result="NO EVIDENCE", reason="Missing evidence", freshness="Missing")
        ],
        implementation="Insufficient Evidence",
        assurance="Not Assessed",
        mandatory_count=1,
        satisfied=0,
    )
    view = dict(
        role="Administrator",
        history=[],
        result=result,
        bundle=dict(
            profile=profile,
            engagement_id=2,
            scope_id=9,
            documents=[],
            requirement_evidence=[],
            party_requirements=[],
            assets=[],
            risks=[],
            actions=[],
        ),
    )
    monkeypatch.setattr(ui, "load_workspace", lambda *args: view)
    monkeypatch.setattr(ui, "selected_context_ids", lambda *args: (2, 9))
    monkeypatch.setattr(ui, "current_actor", lambda: "Admin")
    monkeypatch.setattr(ui, "evidence_choices", lambda *args: [])
    monkeypatch.setattr(
        ui,
        "assurance_workbench",
        lambda *args, **kwargs: SimpleNamespace(
            action={
                "nonce": "open-r1",
                "action": "requirement_remediation",
                "payload": {"id": "r1"},
            }
        ),
    )
    save = MagicMock(return_value=5)
    monkeypatch.setattr(ui, "create_requirement_action", save)
    app = AppTest.from_string(
        (
            "from securescope.ui.control_workspace import "
            "render_control_workspace\nrender_control_workspace('Client','A.8."
            "15','Administrator')"
        )
    ).run()
    assert not app.exception
    next(b for b in app.button if b.label == "Create Remediation").click().run()
    assert not app.exception
    assert save.call_args.args[5] == "r1"
    assert any("Remediation #5" in s.value for s in app.success)
