"""Validate dashboard semantics and real Streamlit navigation with synthetic data."""

from datetime import date

import altair as alt
import pytest
from streamlit.testing.v1 import AppTest

from securescope.grc.gap_dashboard import (
    area_summaries,
    assessment_result,
    dashboard_entries,
    summarize_entries,
)
from securescope.grc.isms_project_plan import (
    ProjectTaskUpdate,
    project_task_rows,
    project_totals,
    workday_end,
)
from securescope.ui.gap_charts import (
    conformity_chart,
    counts_chart,
    project_timeline,
    radar_chart,
)
from securescope.ui.gap_dashboard_ui import csv_export


def effective_record(**changes):
    """Build a synthetic validated assessment; keyword fields override its inputs."""

    return {
        "control_id": "A.8.8",
        "assessment_status": "Implemented and effective",
        "validation_status": "Validated",
        "evidence_freshness": "Current",
        "assessment_current_evidence_count": 1,
        "profile_version": 1,
        **changes,
    }


def test_fresh_workspace_counts_every_catalog_entry_as_unassessed():
    """Never populate a new workspace with the example spreadsheet's 100% values."""

    entries = dashboard_entries([])
    total = summarize_entries(entries)
    areas = area_summaries(entries)
    assert total["entries"] == total["in_scope"] == total["not_assessed"] == 123
    assert total["met"] == total["assessment_coverage"] == 0
    assert total["conformity"] is None
    assert [a["entries"] for a in areas] == [4, 3, 5, 7, 3, 6, 2, 37, 8, 14, 34]


@pytest.mark.parametrize(
    "status",
    [
        "Target achieved",
        "Accepted residual risk",
        "Implemented but not verified",
        "Insufficient evidence",
        "Likely implemented",
    ],
)
def test_advisory_or_incomplete_results_never_count_as_met(status):
    """Preserve the assessment engine's distinction between completion and assurance."""

    assert assessment_result(effective_record(assessment_status=status)) == "Review required"


@pytest.mark.parametrize(
    "changes",
    [
        {"validation_status": "Pending"},
        {"evidence_freshness": "Expired"},
        {"evidence_freshness": "Unknown"},
        {"assessment_current_evidence_count": 0},
    ],
)
def test_missing_validation_or_current_evidence_blocks_a_met_result(changes):
    """A recorded effective conclusion cannot hide expired or absent evidence."""

    assert assessment_result(effective_record(**changes)) == "Review required"


def test_manual_and_hub_evidence_are_both_supported():
    """Count valid direct assessment evidence as well as approved Evidence Hub mappings."""

    assert assessment_result(effective_record()) == "Met"
    assert (
        assessment_result(
            effective_record(assessment_current_evidence_count=0, current_evidence_count=1)
        )
        == "Met"
    )


def test_only_justified_approved_annex_exclusions_reduce_the_denominator():
    """Mandatory clauses and draft exclusions remain visible and in scope."""

    exclusion = {
        "soa_applicability": "Not applicable",
        "soa_approved": True,
        "soa_exclusion_justification": "No physical media in approved scope",
    }
    rows = [
        effective_record(**exclusion),
        effective_record(control_id="4.1", **exclusion),
        effective_record(control_id="A.7.1", **{**exclusion, "soa_approved": False}),
    ]
    total = summarize_entries(dashboard_entries(rows))
    assert total["excluded"] == 1
    assert total["in_scope"] == 122
    assert total["review_required"] == 2
    assert (
        assessment_result(effective_record(**{**exclusion, "soa_exclusion_justification": ""}))
        != "Excluded"
    )


def test_deduplicated_latest_profile_and_weighted_total():
    """An old positive version cannot inflate or outweigh a newer unfinished version."""

    entries = dashboard_entries(
        [
            effective_record(),
            effective_record(profile_version=2, assessment_status="Not assessed"),
            effective_record(control_id="4.1"),
            effective_record(control_id="A.6.1"),
        ]
    )
    total = summarize_entries(entries)
    assert total["entries"] == 123
    assert total["met"] == 2
    assert total["conformity"] == pytest.approx(200 / 123)


def test_all_excluded_area_stays_undefined_and_is_not_plotted_as_zero():
    """An undefined denominator must not become a numeric point on the radar."""

    entries = dashboard_entries(
        [
            {
                "control_id": f"A.6.{index}",
                "soa_applicability": "Not applicable",
                "soa_approved": True,
                "soa_exclusion_justification": "Approved test exclusion",
            }
            for index in range(1, 9)
        ]
    )
    areas = area_summaries(entries)
    assert areas[8]["conformity"] is None
    radar = radar_chart(areas)
    points = next(
        layer["data"]["values"] for layer in radar["layer"] if layer["mark"]["type"] == "point"
    )
    assert points == []  # Remaining areas are unassessed, not zero-percent measured results.
    assert not any(p["area"].startswith("A.6 ") for p in points)


@pytest.mark.parametrize(
    "start, days, expected",
    [
        (date(2026, 9, 7), 1, date(2026, 9, 7)),
        (date(2026, 9, 11), 2, date(2026, 9, 14)),
        (date(2026, 9, 7), 5, date(2026, 9, 11)),
        (date(2026, 9, 7), 6, date(2026, 9, 14)),
        (date(2026, 9, 11), 6, date(2026, 9, 18)),
        (None, 5, None),
        (date(2026, 9, 7), 0, None),
    ],
)
def test_weekday_schedule_includes_start_and_skips_weekends(start, days, expected):
    """Keep one-day and weekend-spanning tasks on the intended work calendar."""

    assert workday_end(start, days) == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"resource": ""},
        {"work_days": -1},
        {"work_days": 1.5},
        {"completed_days": 6},
        {"completed_days": -1},
        {"start_date": date(2026, 9, 12)},
        {"start_date": None, "completed_days": 1},
    ],
)
def test_invalid_task_update_is_rejected_before_saving(changes):
    """Reject misleading percentages and inconsistent schedules at the domain boundary."""

    values = {
        "resource": "Reviewer",
        "start_date": date(2026, 9, 7),
        "work_days": 5,
        "completed_days": 0,
        **changes,
    }
    with pytest.raises(ValueError):
        ProjectTaskUpdate(**values).validate()


def test_summary_task_does_not_double_count_project_effort():
    """The control implementation parent rolls up its children without inflating totals."""

    rows = project_task_rows(
        [
            {"task_ref": 16, "start_date": date(2026, 9, 7), "work_days": 10, "completed_days": 5},
            {"task_ref": 17, "start_date": date(2026, 9, 21), "work_days": 5, "completed_days": 0},
        ]
    )
    assert rows[14]["work_days"] == 15
    assert rows[14]["end_date"] == date(2026, 9, 25)
    total = project_totals(rows, date(2026, 9, 20))
    assert total["work_days"] == 15
    assert total["completed_days"] == 5
    assert total["progress"] == pytest.approx(100 / 3)
    assert total["overdue"] == 1
    assert project_totals(project_task_rows([]), date.today())["progress"] is None


def test_chart_specs_validate_in_the_installed_streamlit_chart_stack():
    """Validate actual dashboard specifications against the Vega-Lite schema."""

    areas = area_summaries(dashboard_entries([effective_record()]))
    tasks = project_task_rows([{"task_ref": 1, "start_date": date(2026, 9, 7), "work_days": 1}])
    for spec in [
        radar_chart(areas),
        counts_chart(areas),
        conformity_chart(areas),
        project_timeline(tasks),
    ]:
        assert alt.Chart.from_dict(spec).to_dict(validate=True)


def test_csv_exports_protect_formula_cells_and_preserve_quotes_dates_and_unicode():
    """Keep downloaded task notes safe to open in spreadsheet software."""

    import csv
    import io

    records = [
        {
            "Name": ' =HYPERLINK("x")',
            "Notes": 'évidence, "review"\nnext line',
            "Date": date(2026, 9, 8),
            "Missing": None,
            "Count": 0,
        }
    ]
    restored = list(csv.DictReader(io.StringIO(csv_export(records).decode("utf-8-sig"))))
    assert restored[0]["Name"].startswith("' =")
    assert restored[0]["Notes"] == records[0]["Notes"]
    assert restored[0]["Date"] == "2026-09-08"
    assert restored[0]["Count"] == "0"


def gap_fixture_app():
    """Run the production assurance page with test-only in-memory project persistence."""

    import streamlit as st

    from securescope.ui import exposure_management_ui as page
    from securescope.ui import gap_dashboard_ui as dashboard
    from tests.test_iso_gap_dashboard import effective_record

    st.selectbox("Workspace", ["Alpha", "Beta"], key="test_workspace")
    workspace = st.session_state.test_workspace
    st.session_state.setdefault("test_plans", {})
    st.session_state.setdefault("test_plan_loads", 0)

    def load_plan(client):
        """Return the fixture's workspace-owned saved tasks."""
        st.session_state.test_plan_loads += 1
        return {"tasks": list(st.session_state.test_plans.get(client, {}).values()), "events": []}

    def save_task(client, ref, update, *, actor, expected_revision):
        """Exercise domain validation and revision checking in the UI fixture."""
        from dataclasses import asdict

        from securescope.persistence.isms_project_repository import ProjectPlanError

        update.validate()
        if not actor.strip():
            raise ValueError("Updated by is required.")
        current = st.session_state.test_plans.setdefault(client, {})
        if expected_revision != current.get(ref, {}).get("revision", 0):
            raise ProjectPlanError("This task changed since the form was opened.")
        current[ref] = {**asdict(update), "task_ref": ref, "revision": expected_revision + 1}
        return expected_revision + 1

    dashboard.load_project_plan = load_plan
    dashboard.save_project_task = save_task
    page.list_control_overview = lambda name, **kwargs: [
        effective_record(
            control_name=f"{name} vulnerability management",
            profile_id=1,
            target_id=1,
            target_version=1,
            measurement_model="evidence_documentation",
            automation_level="Manual",
        )
    ]
    page.control_detail_history = lambda *args: {}
    from securescope.ui import control_assessment_ui as editor

    editor.load_register = lambda *args: {"rows": [], "revision": 0}
    editor.list_evidence_records = lambda *args, **kwargs: []
    editor.control_detail_history = lambda *args: {}
    editor.working_actor = lambda *args: "consultant@example.test"
    editor._identity = lambda *args: ("consultant@example.test", "Consultant")
    page.render_gap_assessment_page(workspace, [])


@pytest.fixture
def gap_app(monkeypatch):
    """Restore fixture replacements after each actual Streamlit workflow test."""

    from securescope.ui.components_v2 import assurance_plan

    monkeypatch.setattr(assurance_plan, "_COMPONENT", None)
    from securescope.ui import control_assessment_ui as editor
    from securescope.ui import exposure_management_ui as page
    from securescope.ui import gap_dashboard_ui as dashboard

    for module, names in [
        (
            editor,
            (
                "load_register",
                "list_evidence_records",
                "control_detail_history",
                "working_actor",
                "_identity",
            ),
        ),
        (page, ("list_control_overview", "control_detail_history")),
        (dashboard, ("load_project_plan", "save_project_task")),
    ]:
        for name in names:
            monkeypatch.setattr(module, name, getattr(module, name))
    return AppTest.from_function(gap_fixture_app, default_timeout=15)


def test_dashboard_is_default_and_does_not_load_the_project_plan(gap_app):
    """Load the dashboard and its charts without running hidden persistence workflows."""

    app = gap_app.run()
    assert not app.exception
    assert app.subheader[0].value == "ISO/IEC 27001 Gap Assessment"
    assert app.session_state.test_plan_loads == 0
    assert len(app.get("vega_lite_chart")) == 3
    assert app.dataframe[0].value.iloc[-1]["Met"] == 1


def test_filter_then_assess_opens_the_real_editor(gap_app):
    """Filter an area and follow the action to its matching control editor."""

    app = gap_app.run()
    app.selectbox(key="gap_area::Alpha").select("A.8 Technological controls").run()
    assert not app.exception
    assert app.selectbox(key="gap_area::Alpha").value == "A.8 Technological controls"
    app.button(key="gap_assess::Alpha").click().run()
    assert not app.exception
    assert app.selectbox(key="guided_control::Alpha").value.startswith("A.8.8")


def open_test_plan(app):
    """Select the project plan through its actual session-controlled tab label."""

    from securescope.ui.gap_dashboard_ui import PROJECT_PLAN_TAB

    app.session_state["assurance_active_tab::Alpha"] = PROJECT_PLAN_TAB
    app.run()
    app.session_state["plan_mode::Alpha"] = "Edit a task"
    return app.run()


def test_project_save_recalculates_and_survives_rerun(gap_app):
    """Save a Friday task and see its weekday finish and progress in the main table."""

    app = open_test_plan(gap_app)
    assert not app.exception
    app.date_input[0].set_value(date(2026, 9, 11))
    app.number_input[0].set_value(2)
    app.number_input[1].set_value(1)
    next(w for w in app.text_input if w.label == "Updated by").set_value("Test reviewer")
    next(w for w in app.button if w.label == "Save Changes").click().run()
    assert not app.exception
    assert app.success
    row = app.session_state.test_plans["Alpha"][1]
    from securescope.ui.gap_dashboard_ui import project_task_rows

    calculated = project_task_rows([row])[0]
    assert calculated["progress"] == 50
    assert str(calculated["end_date"])[:10] == "2026-09-14"
    app.session_state["plan_mode::Alpha"] = "Edit a task"
    app.run()
    assert app.number_input[0].value == 2
    assert app.number_input[1].value == 1


def test_project_drafts_and_dashboard_filters_do_not_cross_workspaces(gap_app):
    """A newly selected workspace starts with its own dashboard and task fields."""

    app = open_test_plan(gap_app)
    app.text_area[0].set_value("Alpha private draft")
    app.selectbox(key="test_workspace").select("Beta").run()
    assert not app.exception
    assert app.subheader[0].value == "ISO/IEC 27001 Gap Assessment"
    assert app.selectbox(key="gap_area::Beta").value == "All areas"
    from securescope.ui.gap_dashboard_ui import PROJECT_PLAN_TAB

    app.session_state["assurance_active_tab::Beta"] = PROJECT_PLAN_TAB
    app.run()
    assert not app.exception
    app.session_state["plan_mode::Beta"] = "Edit a task"
    app.session_state["assurance_pending_tab::Beta"] = PROJECT_PLAN_TAB
    app.run()
    assert app.text_area[0].value == ""


def test_stale_task_form_cannot_overwrite_newer_saved_data(gap_app):
    """A second writer's change rejects the old form until the saved task is reloaded."""

    app = open_test_plan(gap_app)
    app.session_state.test_plans = {
        "Alpha": {
            1: {
                "task_ref": 1,
                "resource": "Another reviewer",
                "revision": 1,
                "start_date": date(2026, 9, 7),
                "work_days": 10,
                "completed_days": 3,
            }
        }
    }
    next(w for w in app.text_input if w.label == "Updated by").set_value("Old reviewer")
    next(w for w in app.button if w.label == "Save Changes").click().run()
    assert not app.exception
    assert any("changed" in error.value for error in app.error)
    assert app.session_state.test_plans["Alpha"][1]["completed_days"] == 3
    app.button(key="plan_reload::Alpha::1").click().run()
    assert not app.exception
    assert app.number_input[0].value == 10
