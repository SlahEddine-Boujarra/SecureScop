"""Regression contracts for the v5.3.8.12 assurance workspace merge."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
EXPOSURE = (ROOT / "ui" / "exposure_management_ui.py").read_text(encoding="utf-8")
EVIDENCE = (ROOT / "ui" / "evidence_hub_ui.py").read_text(encoding="utf-8")


def test_control_assurance_keeps_original_control_workflows() -> None:
    """The merge may add Evidence but must not remove mature control workflows."""

    page = EXPOSURE[EXPOSURE.index("def render_gap_assessment_page(") :]
    for label in (
        "Control profiles",
        "Assess control",
        "Evidence",
        "Gap actions",
        "Statement of Applicability",
    ):
        assert label in page
    assert "render_assessment(client_name, [dict(row) for row in rows])" in page
    assert "_render_gap_action_workflow(client_name)" in page
    assert "soa_working_editor" in page
    assert "render_treatment_links(client_name)" not in page
    assert "risk_treatment_plan_form" not in page


def test_gap_register_is_still_rendered_before_action_creation() -> None:
    """Users must retain the persistent gap table as well as the action form."""

    start = EXPOSURE.index("def _render_gap_action_workflow(")
    end = EXPOSURE.index("def render_gap_assessment_page(", start)
    workflow = EXPOSURE[start:end]
    assert "list_control_gaps_and_actions(client_name)" in workflow
    assert "st.dataframe(pd.DataFrame(gaps)" in workflow
    assert 'with st.form("improvement_action_form")' in workflow
    assert '"Create action, POA&M item and milestone"' in workflow


def test_embedded_evidence_keeps_all_original_evidence_functions() -> None:
    """Evidence Hub is relocated, not functionally reduced."""

    render = EVIDENCE[EVIDENCE.index("def render_iso_evidence_hub(") :]
    for label in (
        "Evidence Settings",
        "Collect Evidence",
        "Import Reports",
        "Manual Evidence",
        "Consultant Review",
        "Evidence Requests",
        "Auditor Package",
    ):
        assert label in render
    assert "_overview(client_name)" in render
    assert "_auditor_tab(client_name, actor, role)" in render
