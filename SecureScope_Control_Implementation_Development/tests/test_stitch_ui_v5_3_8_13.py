"""Regression contracts for the v5.3.8.13 Stitch UI foundation."""

from pathlib import Path

from tests.ui_style_sources import read_theme_source

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def test_stitch_design_components_are_local_and_reusable() -> None:
    """Keep Stitch as a local design system rather than production CDN HTML."""

    source = (SOURCE_ROOT / "ui/components/stitch.py").read_text(encoding="utf-8")
    assert "render_stitch_metrics" in source
    assert "render_certification_journey" in source
    assert "render_attention_panel" in source
    assert "render_coverage_gaps" in source
    assert "cdn.tailwindcss.com" not in source
    assert "fonts.googleapis.com" not in source


def test_sidebar_matches_final_information_architecture() -> None:
    """Expose the approved small set of primary workspaces."""

    source = (SOURCE_ROOT / "ui/securescope_sidebar.py").read_text(encoding="utf-8")
    for label in (
        "Command Center",
        "Exposure Overview",
        "Programme Foundation",
        "Control Assurance",
        "Asset Management",
        "Scan Center",
        "Vulnerabilities",
        "SIEM",
        "Remediation",
        "Reports & Audit",
        "Client Workspace",
    ):
        assert label in source
    assert '"1 · Asset Discovery": "Asset Discovery"' in source
    assert '"6 · ISO 27001 Assessment": "ISO 27001 Mapping"' in source
    assert '"ISO Evidence Hub": "ISO Evidence Hub"' in source


def test_command_center_uses_real_assurance_and_coverage_signals() -> None:
    """Keep programme, human assurance and technical coverage distinct."""

    source = (SOURCE_ROOT / "ui/pages/command_center.py").read_text(encoding="utf-8")
    assert "Controls Assessed" in source
    assert "Human-reviewed applicable controls" in source
    assert "render_assurance_distribution" in source
    assert "render_technical_coverage" in source
    assert "No current engine-specific coverage data" in source
    assert "No current Wazuh snapshot" in source


def test_control_assurance_separates_recommendation_from_human_assessment() -> None:
    """Prevent evidence-derived signals from becoming silent compliance decisions."""

    source = (SOURCE_ROOT / "ui/exposure_management_ui.py").read_text(encoding="utf-8")
    assert '"SecureScope recommendation"' in source
    assert '"Human assessment"' in source
    assert 'return "Likely implemented"' in source
    assert 'return "Partial support"' in source
    assert 'return "Gap signal"' in source
    assert (
        'row.get("assessment_status")'
        not in source[
            source.index("def _securescope_recommendation") : source.index(
                "def _evidence_strength_label"
            )
        ]
    )


def test_control_assurance_preserves_professional_workflows() -> None:
    """UI consolidation must not remove Evidence, gaps, SoA or RTP."""

    source = (SOURCE_ROOT / "ui/exposure_management_ui.py").read_text(encoding="utf-8")
    start = source.index("def render_gap_assessment_page")
    page = source[start:]
    for label in (
        "Control profiles",
        "Assess control",
        "Evidence",
        "Gap actions",
        "Statement of Applicability",
    ):
        assert label in page
    assert "render_iso_evidence_hub(client_name, embedded=True)" in page
    assert "_render_gap_action_workflow(client_name)" in page
    assert "render_soa_working_editor(" in page
    soa_source = (SOURCE_ROOT / "ui/soa_ownership.py").read_text(encoding="utf-8")
    assert "assurance_page(" in soa_source
    assert "_edit_soa_row(" in soa_source


def test_exposure_uses_asset_tag_and_correct_coverage_semantics() -> None:
    """Keep hostname out of the decision table and coverage separate from scope."""

    source = (SOURCE_ROOT / "app.py").read_text(encoding="utf-8")
    start = source.index("def _overview_affected_asset_rows")
    end = source.index("def _asset_table_rows", start)
    overview = source[start:end]
    assert '"Asset Tag"' in overview
    assert '"Hostname"' not in overview
    assert "render_coverage_gaps" in overview
    assert "in-scope assets missing scan or monitoring evidence" in overview


def test_programme_foundation_has_state_aware_primary_action() -> None:
    """Do not hard-code Continue Discovery when another decision is next."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    start = source.index("def legacy_render_setup_overview")
    end = source.index("def render_engagement_section", start)
    overview = source[start:end]
    assert "Continue Discovery" in overview
    assert "Review ISMS Scope" in overview
    assert "Review Responsibilities" in overview
    assert "Continue to Control Assurance" in overview
    assert "render_programme_workflow" in overview


def test_final_design_tokens_are_applied() -> None:
    """Keep the approved Stitch visual language in the local theme."""

    source = read_theme_source()
    assert "#f6f8fa" in source
    assert "#00685f" in source
    assert "#0f172a" in source
    assert "#dce3eb" in source
    assert '"Segoe UI Variable Text"' in source
