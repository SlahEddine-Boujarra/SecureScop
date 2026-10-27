"""Exercise assurance decisions and actual Streamlit interaction boundaries."""

from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from securescope.ui.control_presenter import (
    evidence_coverage_counts,
    human_assessment_label,
    status_tone,
)
from securescope.ui.exposure_management_ui import (
    _securescope_recommendation,
    _technical_coverage_label,
)


@pytest.mark.parametrize(
    "stored, expected",
    [
        ("Accepted residual risk", "Accepted Risk"),
        ("Implemented but not verified", "Verification Pending"),
        ("Target achieved", "Target Achieved"),
        ("Insufficient evidence", "Insufficient Evidence"),
        ("Implemented and effective", "Implemented"),
        (None, "Not Reviewed"),
    ],
)
def test_human_conclusion_is_not_silently_promoted(stored, expected):
    """Check that unfinished verification and exceptions remain distinguishable."""

    assert human_assessment_label(stored) == expected
    if expected != "Implemented":
        assert status_tone(expected) != "success"


@pytest.mark.parametrize("score", [95, float("nan"), float("inf"), -1, 101])
def test_scores_without_current_evidence_do_not_imply_implementation(score):
    """Reject misleading numeric recommendations when approved evidence has aged out."""

    assert (
        _securescope_recommendation(
            {"assurance_score": score, "approved_evidence_count": 4, "current_evidence_count": 0}
        )
        == "Evidence review required"
    )


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 101])
def test_invalid_scores_with_current_evidence_require_review(score):
    """Keep invalid score data out of the advisory recommendation buckets."""

    assert (
        _securescope_recommendation(
            {"assurance_score": score, "approved_evidence_count": 1, "current_evidence_count": 1}
        )
        == "Manual review"
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -5, 120, "bad"])
def test_invalid_coverage_is_missing_instead_of_a_fabricated_percentage(value):
    """Display unavailable measurements without turning NaN into full coverage."""

    assert _technical_coverage_label({"target_unit": "%", "current_value": value}) == "—"


def test_evidence_coverage_uses_the_same_applicable_population():
    """Exclude duplicate profiles, expired evidence and non-applicable controls."""

    rows = [
        {"control_id": "A.8.8", "current_evidence_count": 2},
        {"control_id": "A.8.8", "current_evidence_count": 2},
        {"control_id": "A.8.9", "approved_evidence_count": 5, "current_evidence_count": 0},
        {"control_id": "A.8.10", "applicability": "Not applicable", "current_evidence_count": 9},
    ]
    assert evidence_coverage_counts(rows) == (1, 2)
    assert evidence_coverage_counts([]) == (0, 0)


def test_browser_sessions_do_not_share_route_objects(monkeypatch):
    """Ensure another session cannot replace the page used by a callback."""

    from securescope.ui import navigation_runtime as routing

    session_a, session_b = {}, {}
    page_a, page_b = object(), object()
    switched = []
    runtime = SimpleNamespace(session_state=session_a, switch_page=switched.append)
    monkeypatch.setattr(routing, "st", runtime)
    routing.configure_page_registry({"Overview": page_a})
    runtime.session_state = session_b
    assert not routing.page_registry_configured()
    routing.configure_page_registry({"Overview": page_b})
    runtime.session_state = session_a
    routing.navigate_to("Overview")
    assert switched == [page_a]
    assert "app_navigation" not in session_b
    with pytest.raises(ValueError, match="Unknown"):
        routing.navigate_to("wrong route")
    assert session_a["app_navigation"] == "Overview"


def assurance_fixture_app():
    """Run the real assurance page with synthetic records and blocked persistence.

    Returns:
        None. Builds a Streamlit test surface without external services.

    Raises:
        AssertionError: If the UI unexpectedly accesses a hidden section or writes.
    """

    from types import SimpleNamespace

    import streamlit as st

    from securescope.ui import control_assessment_ui as editor
    from securescope.ui import control_profiles_workbench as profiles
    from securescope.ui import exposure_management_ui as page

    editor.load_register = lambda *args: {"rows": [], "revision": 0}
    editor.list_evidence_records = lambda *args, **kwargs: []
    editor.control_detail_history = lambda *args: {}
    editor.working_actor = lambda *args: "consultant@example.test"
    editor._identity = lambda *args: ("consultant@example.test", "Consultant")
    profiles._identity = editor._identity
    profiles.assurance_workbench = lambda *args, **kwargs: SimpleNamespace(
        action=st.session_state.pop("fixture_profile_action", None)
    )

    st.selectbox("Workspace", ["Demo A", "Demo B"], key="fixture_workspace")
    workspace = st.session_state.fixture_workspace
    rows = [
        {
            "control_id": control_id,
            "control_name": f"{workspace} control {index}",
            "profile_id": index,
            "profile_version": 1,
            "measurement_model": "evidence_documentation",
            "automation_level": "Manual",
            "assessment_status": "Implemented but not verified",
            "target_id": 1,
            "target_version": 1,
        }
        for index, control_id in enumerate(["A.8.8", "A.8.9"], 1)
    ]

    def fail(*args, **kwargs):
        """Reject any unexpected persistence or hidden-tab execution."""

        raise AssertionError("Unexpected service call in the fixture")

    page.list_control_overview = lambda name, **kwargs: rows
    page.list_control_gaps_and_actions = lambda name: []
    page.control_detail_history = lambda *args: {}
    page.components_v2_available = lambda: True
    page.render_iso_evidence_hub = fail
    page._render_gap_action_workflow = fail
    page.latest_statement_of_applicability = fail
    page.list_statement_of_applicability_versions = fail
    page.save_manual_control_assessment = fail
    page.create_profile_version = fail
    page.create_control_target = fail
    if f"assurance_active_tab::{workspace}" not in st.session_state:
        st.session_state[f"assurance_active_tab::{workspace}"] = (
            ":material/table_view: Control profiles"
        )
    if st.session_state.get("fixture_direct_assessment"):
        editor.render_assessment(workspace, rows)
    else:
        page.render_gap_assessment_page(workspace, [])


@pytest.fixture
def assurance_app(monkeypatch):
    """Restore fixture service replacements after every real Streamlit test."""

    from securescope.ui import exposure_management_ui as page

    for name in (
        "list_control_overview",
        "list_control_gaps_and_actions",
        "control_detail_history",
        "components_v2_available",
        "render_iso_evidence_hub",
        "_render_gap_action_workflow",
        "latest_statement_of_applicability",
        "list_statement_of_applicability_versions",
        "save_manual_control_assessment",
        "create_profile_version",
        "create_control_target",
    ):
        monkeypatch.setattr(page, name, getattr(page, name))
    from securescope.ui import control_assessment_ui as editor
    from securescope.ui import control_profiles_workbench as profiles

    for module, names in (
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
        (profiles, ("_identity", "assurance_workbench")),
    ):
        for name in names:
            monkeypatch.setattr(module, name, getattr(module, name))
    return AppTest.from_function(assurance_fixture_app, default_timeout=10)


def test_default_assurance_page_does_not_execute_hidden_workflows(assurance_app):
    """Load the register with no assessment forms or offscreen service calls."""

    app = assurance_app.run()
    assert not app.exception
    assert len(app.tabs) == 7
    assert not app.text_area
    assert all(button.key != "new_assessment::Demo A" for button in app.button)


def test_row_selection_opens_the_matching_assessment(assurance_app):
    """Follow a v2 row event through its preview into the actual control editor."""

    app = assurance_app
    app.session_state["fixture_profile_action"] = {
        "action": "profile_assess",
        "payload": {"control_id": "A.8.9"},
        "nonce": "test-open",
    }
    app.run()
    assert not app.exception
    assert app.subheader[0].value == "A.8.9 — Demo A control 2"
    assert app.selectbox(key="guided_control::Demo A").value.startswith("A.8.9")
    assert app.text_area
    app.selectbox(key="guided_control::Demo A").select("A.8.8").run()
    assert not app.exception
    assert app.selectbox(key="guided_control::Demo A").value == "A.8.8"


def test_selection_cannot_cross_workspace_boundaries(assurance_app):
    """Switch workspaces after a selection without carrying its detail panel over."""

    app = assurance_app
    app.session_state["fixture_profile_action"] = {
        "action": "profile_assess",
        "payload": {"control_id": "A.8.9"},
        "nonce": "test-open",
    }
    app.run()
    app.selectbox(key="fixture_workspace").select("Demo B").run()
    assert not app.exception
    assert not app.subheader
    assert len(app.text_area) == 0


def test_invalid_component_row_id_is_ignored(assurance_app):
    """Resolve row identities against current workspace records before showing detail."""

    app = assurance_app
    app.session_state["fixture_profile_action"] = {
        "action": "profile_assess",
        "payload": {"control_id": "another-workspace-id"},
        "nonce": "test-foreign",
    }
    app.run()
    assert not app.exception
    assert not app.subheader


def test_assessment_draft_does_not_transfer_to_a_different_control(assurance_app):
    """Start a draft and verify a different control opens with its own empty form."""

    app = assurance_app
    app.session_state["fixture_direct_assessment"] = True
    app.run()
    assert not app.exception
    scope = next(item for item in app.text_area if item.label == "Operational Narrative")
    scope.set_value("Only control A.8.8 is in this draft").run()
    selector = app.selectbox(key="guided_control::Demo A")
    selector.select("A.8.9").run()
    assert not app.exception
    scope = next(item for item in app.text_area if item.label == "Operational Narrative")
    assert scope.value == ""


def test_assessment_returns_to_its_unsaved_control_draft(assurance_app):
    """Control switching restores session draft contents without writing a decision."""
    app = assurance_app
    app.session_state["fixture_direct_assessment"] = True
    app.run()
    app.text_area(key="assessment::Demo A::1::current").set_value("Reviewed production").run()
    app.selectbox(key="guided_control::Demo A").select("A.8.9").run()
    app.selectbox(key="guided_control::Demo A").select("A.8.8").run()
    assert not app.exception
    assert app.text_area(key="assessment::Demo A::1::current").value == "Reviewed production"


def test_conclusion_save_persists_current_draft_with_visible_feedback(assurance_app, monkeypatch):
    from unittest.mock import MagicMock

    from securescope.ui import control_assessment_ui as editor

    saved = MagicMock(return_value=1)
    monkeypatch.setattr(editor, "save_register", saved)
    app = assurance_app
    app.session_state["fixture_direct_assessment"] = True
    app.run()
    app.text_area(key="assessment::Demo A::1::current").set_value("Reviewed production")
    app.button(key="assessment::Demo A::1::save_draft").click().run()
    assert not app.exception
    assert saved.call_args.args[2][0]["current_state"] == "Reviewed production"
    assert any("Draft saved" in message.value for message in app.success)
