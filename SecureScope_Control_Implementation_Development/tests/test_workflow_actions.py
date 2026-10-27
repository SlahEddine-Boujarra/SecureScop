"""User-facing action regressions without a live database."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from streamlit.testing.v1 import AppTest

from securescope.evidence.models import WorkspaceRole
from securescope.ui import control_assessment_ui as assessment
from securescope.ui import control_profiles_workbench as profiles
from securescope.ui import workspace_inputs


def test_draft_save_from_review_and_conclusion(monkeypatch):
    """The single conclusion save persists edits and shows local feedback."""
    monkeypatch.setattr(workspace_inputs, "current_actor", lambda: "admin@example.test")
    monkeypatch.setattr(assessment, "load_register", lambda *a: {"rows": [], "revision": 0})
    monkeypatch.setattr(assessment, "list_evidence_records", lambda *a, **k: [])
    monkeypatch.setattr(assessment, "control_detail_history", lambda *a: {})
    monkeypatch.setattr(
        assessment, "_identity", lambda *a: ("admin@example.test", WorkspaceRole.ADMINISTRATOR)
    )
    saved = MagicMock(side_effect=[1, 2])
    monkeypatch.setattr(assessment, "save_register", saved)
    app = AppTest.from_string("""
from securescope.ui.control_assessment_ui import render_assessment
render_assessment('Client', [dict(control_id='A.8.16', profile_id=7,
 control_name='Monitoring', profile_version=1, assessment_scope={})])
""").run()
    assert not app.exception
    assert sum(button.label == "Save Draft" for button in app.button) == 1
    assert not any(button.key == "assessment::Client::7::save_top" for button in app.button)
    app.text_area(key="assessment::Client::7::current").set_value("Review logs daily").run()
    app.button(key="assessment::Client::7::save_draft").click().run()
    assert not app.exception
    assert saved.call_args.args[2][0]["current_state"] == "Review logs daily"
    assert saved.call_args.kwargs["actor"] == "admin@example.test"
    assert app.success
    app.text_area(key="assessment::Client::7::current").set_value(
        "Review and investigate alerts"
    ).run()
    app.button(key="assessment::Client::7::save_draft").click().run()
    assert not app.exception
    assert saved.call_args.kwargs["expected_revision"] == 1
    assert saved.call_args.args[2][0]["current_state"] == "Review and investigate alerts"
    assert app.success


def test_implementation_action_survives_component_trigger_rerun(monkeypatch):
    """A real component event opens the selected panel on the next render."""
    monkeypatch.setattr(
        profiles, "_identity", lambda *a: ("admin@example.test", WorkspaceRole.ADMINISTRATOR)
    )
    monkeypatch.setattr(
        profiles,
        "assurance_workbench",
        lambda *a, **k: SimpleNamespace(
            action={
                "action": "profile_implementation",
                "nonce": "open-one",
                "payload": {"control_id": "A.8.16"},
            }
        ),
    )
    from securescope.ui import control_workspace

    def panel(*args):
        import streamlit as st

        st.success("Evidence opened: " + args[1])

    monkeypatch.setattr(control_workspace, "render_control_workspace", panel)
    app = AppTest.from_string("""
from securescope.ui.control_profiles_workbench import render_control_profiles
render_control_profiles('Client', [dict(control_id='A.8.16')], [dict(Title='Monitoring')])
""").run()
    assert not app.exception
    assert app.success[0].value == "Evidence opened: A.8.16"


def test_conclusion_save_uses_existing_assessment_service(monkeypatch):
    """The conclusion action saves through the same finalization service as review."""
    monkeypatch.setattr(workspace_inputs, "current_actor", lambda: "admin@example.test")
    monkeypatch.setattr(assessment, "load_register", lambda *a: {"rows": [], "revision": 0})
    monkeypatch.setattr(assessment, "list_evidence_records", lambda *a, **k: [])
    monkeypatch.setattr(assessment, "control_detail_history", lambda *a: {})
    monkeypatch.setattr(
        assessment, "_identity", lambda *a: ("admin@example.test", WorkspaceRole.ADMINISTRATOR)
    )
    saved = MagicMock()
    monkeypatch.setattr(assessment, "save_manual_control_assessment", saved)
    app = AppTest.from_string("""
from securescope.ui.control_assessment_ui import render_assessment
render_assessment('Client', [dict(control_id='A.8.16', profile_id=7,
 control_name='Monitoring', profile_version=1, assessment_scope={},
 target_id=3, target_version=1, target_description='Review alerts')])
""").run()
    app.text_area(key="assessment::Client::7::current").set_value("Daily review").run()
    app.radio(key="assessment::Client::7::dimension::Operating effectiveness").set_value(
        "Partially implemented"
    ).run()
    assert (
        app.radio(key="assessment::Client::7::dimension::Operating effectiveness").value
        == "Partially implemented"
    )
    app.selectbox(key="assessment::Client::7::confidence").set_value("High").run()
    app.button(key="assessment::Client::7::finalize").click().run()
    assert not app.exception
    assert saved.call_args.args == ("Client", 7)
    assert saved.call_args.kwargs["current_state"] == "Daily review"
    assert saved.call_args.kwargs["confidence"] == "High"
    assert saved.call_args.kwargs["validator"] == ""
    assert app.success
