"""Regression contracts for v5.3.8.11 assurance/remediation UX consolidation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
APP = (ROOT / "app.py").read_text(encoding="utf-8")
EXPOSURE = (ROOT / "ui" / "exposure_management_ui.py").read_text(encoding="utf-8")
EVIDENCE = (ROOT / "ui" / "evidence_hub_ui.py").read_text(encoding="utf-8")
SIDEBAR = (ROOT / "ui" / "securescope_sidebar.py").read_text(encoding="utf-8")
DUAL = (ROOT / "ui" / "dual_engine_ui.py").read_text(encoding="utf-8")


def _function_source(source: str, function_name: str, next_function: str) -> str:
    """Return one top-level source slice."""

    start = source.index(f"def {function_name}(")
    end = source.index(f"def {next_function}(", start + 1)
    return source[start:end]


def test_sidebar_uses_one_control_assurance_workspace() -> None:
    """Do not expose parallel Control/Technical/Evidence workspaces."""

    visible = SIDEBAR.split("HIDDEN_NAVIGATION_PAGES", 1)[0]
    assert '"Control Assurance"' in visible
    assert '"Technical Assurance"' not in visible
    assert '"Evidence Hub"' not in visible
    assert '"ISO 27001 Mapping"' in SIDEBAR


def test_control_assurance_embeds_compact_evidence_workflow() -> None:
    """Evidence collection/review belongs inside Control Assurance."""

    start = EXPOSURE.index("def render_gap_assessment_page(")
    page = EXPOSURE[start:]
    assert 'st.title("Control Assurance")' in page
    assert ":material/folder_open: Evidence" in page
    assert "render_iso_evidence_hub(client_name, embedded=True)" in page
    assert '"Open A.8 technical assurance"' in page


def test_embedded_evidence_hub_preserves_complete_workflow() -> None:
    """Merging Evidence Hub must not remove its original tables or actions."""

    render = EVIDENCE[EVIDENCE.index("def render_iso_evidence_hub(") :]
    assert "embedded: bool = False" in render
    for label in (
        '"Overview"',
        '"Evidence Settings"',
        '"Collect Evidence"',
        '"Import Reports"',
        '"Manual Evidence"',
        '"Consultant Review"',
        '"Evidence Requests"',
        '"Auditor Package"',
    ):
        assert label in render
    for renderer in (
        "_overview(client_name)",
        "_tool_catalog()",
        "_collect_tab(client_name, actor, role)",
        "_import_tab(client_name, actor, role)",
        "_manual_tab(client_name, actor, role)",
        "_review_tab(client_name, actor, role)",
        "_requests_tab(client_name, actor, role)",
        "_auditor_tab(client_name, actor, role)",
    ):
        assert renderer in render


def test_remediation_follows_triage_plan_fix_verify_close_flow() -> None:
    """Remediation should be a workflow, not a collection of unrelated registers."""

    page = _function_source(EXPOSURE, "render_remediation_page", "_parse_criterion_lines")
    for label in (
        '"Priority queue"',
        '"Active plans"',
        '"Verify & close"',
        '"Finding Exceptions"',
        '"Triage"',
        '"Planned"',
        '"In progress"',
        '"Verify"',
        '"Closed"',
    ):
        assert label in page
    assert "group_remediation_candidates" in page
    assert "ready_items" in page


def test_vulnerabilities_is_dashboard_first_and_filters_are_secondary() -> None:
    """Keep posture/risk signals visible before detailed filters and lifecycle forms."""

    page = _function_source(EXPOSURE, "render_vulnerabilities_page", "_render_plan_creation")
    assert '"ACTIVE FINDINGS"' in page
    assert '"PRIORITY EXPOSURE"' in page
    assert '"EXPLOIT SIGNALS"' in page
    assert '"READY TO VERIFY"' in page
    assert 'st.markdown("### Exposure distribution")' in page
    assert 'with st.expander("Filters", expanded=False)' in page
    assert 'st.markdown("### Priority findings")' in page


def test_asset_register_tables_do_not_expose_hostname_column() -> None:
    """Asset tag remains the stable identity while hostname stays internal."""

    table = _function_source(APP, "_asset_table_rows", "_select_asset_from_list")
    assert '"Asset tag"' in table
    assert '"IP address"' in table
    assert '"Hostname"' not in table


def test_large_page_hero_is_replaced_by_compact_title() -> None:
    """Legacy descriptive hero copy should no longer consume page space."""

    page_hero = _function_source(APP, "page_hero", "section_heading")
    assert "del eyebrow, subtitle" in page_hero
    assert "ss-simple-page-header" in page_hero
    assert '<div class="page-hero">' not in page_hero
    assert "Nuclei Scan Center</h1>" not in DUAL
