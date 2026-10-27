"""Regression coverage for record-preserving assurance presentation changes."""

from streamlit.testing.v1 import AppTest


def test_summary_escapes_record_text(monkeypatch):
    """User-controlled summary text must never become HTML."""
    from securescope.ui.components import stitch

    rendered = []
    monkeypatch.setattr(stitch, "render_html", rendered.append)
    stitch.render_assurance_summary([("<label>", "<script>alert(1)</script>", "<detail>")])
    assert "<script>" not in rendered[0]
    assert "&lt;script&gt;" in rendered[0]


def test_plan_view_does_not_change_canonical_editor_rows():
    """The custom presentation and existing batch editor receive all 30 tasks."""
    app = AppTest.from_string("""
import streamlit as st
from unittest.mock import patch
from securescope.ui import gap_dashboard_ui as plan
from securescope.ui.components_v2 import assurance_plan
with (
    patch.object(plan, "load_project_plan", return_value={"tasks": [], "events": []}),
    patch.object(assurance_plan, "render_plan_view", side_effect=
        lambda client, rows, metrics, callback: st.write(f"View receives {len(rows)} tasks")),
    patch.object(plan, "render_batch_planner", side_effect=
        lambda client, rows: st.write(f"Editor receives {len(rows)} tasks")),
):
    plan.render_project_plan("Test")
""").run(timeout=30)
    assert not app.exception
    assert any("View receives 30 tasks" in item.value for item in app.markdown)
    app.session_state["plan_mode::Test"] = "Plan in one pass"
    app.run()
    assert not app.exception
    assert any("Editor receives 30 tasks" in item.value for item in app.markdown)
    assert not any("View receives" in item.value for item in app.markdown)
    app.button(key="plan_back::Test").click().run()
    assert not app.exception
    assert any("View receives 30 tasks" in item.value for item in app.markdown)
    assert not any("Editor receives" in item.value for item in app.markdown)


def test_soa_editor_preserves_all_rows_and_scope_key():
    """The design must retain every canonical row and scope-specific edit key."""
    app = AppTest.from_string("""
import streamlit as st
from securescope.ui.soa_ownership import render_soa_working_editor
rows=[
    dict(control_id="A.5.1",control_name="Policy",applicability="Applicable",
         inclusion_justification="Needed",exclusion_justification=""),
    dict(control_id="A.7.4",control_name="Physical monitoring",applicability="Not applicable",
         inclusion_justification="",exclusion_justification="Remote scope")
]
result=render_soa_working_editor("Test",2,9,rows)
st.session_state["result_ids"]=result["control_id"].tolist()
""").run(timeout=30)
    assert not app.exception
    assert app.session_state["result_ids"] == ["A.5.1", "A.7.4"]
    assert "soa_working_editor::Test::2::9" in app.session_state
