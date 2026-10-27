"""Regression contracts for the v5.3.8.10 functional-consolidation pass."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (PROJECT_ROOT / "src" / "securescope" / "app.py").read_text(encoding="utf-8")
EXPOSURE_SOURCE = (
    PROJECT_ROOT / "src" / "securescope" / "ui" / "exposure_management_ui.py"
).read_text(encoding="utf-8")
SIDEBAR_SOURCE = (PROJECT_ROOT / "src" / "securescope" / "ui" / "securescope_sidebar.py").read_text(
    encoding="utf-8"
)
NAVIGATION_SOURCE = (PROJECT_ROOT / "src" / "securescope" / "ui" / "navigation.py").read_text(
    encoding="utf-8"
)


def test_findings_route_uses_canonical_vulnerability_workspace() -> None:
    """Route detailed findings through the modern Vulnerabilities page."""
    assert "render_vulnerabilities_page(" in APP_SOURCE
    assert 'PageSpec("4 · Reports & Findings", "Vulnerabilities"' in NAVIGATION_SOURCE
    renderers = APP_SOURCE.split("def _page_renderers()", 1)[1]
    assert '"4 · Reports & Findings": lambda: render_vulnerabilities_page(' in renderers
    assert "render_findings_dashboard()" not in renderers


def test_sidebar_calls_detailed_workspace_vulnerabilities() -> None:
    """Expose the user-facing role rather than the old report-centric label."""
    assert '"Vulnerabilities"' in SIDEBAR_SOURCE
    assert '"Reports & Findings",\n                "bug_report"' not in SIDEBAR_SOURCE


def test_technical_assurance_does_not_duplicate_remediation_and_cve_workspaces() -> None:
    """Keep A.8 reasoning focused on evidence-to-control assurance."""
    assert ":material/task_alt: Corrective actions" not in APP_SOURCE
    assert ":material/bug_report: Vulnerability intelligence" not in APP_SOURCE
    assert '"Open technical remediation"' in APP_SOURCE
    assert '"Review control gaps & SoA"' in APP_SOURCE


def test_evidence_hub_owns_full_auditor_package_ui() -> None:
    """Technical Assurance keeps only the A.8-specific PDF export."""
    assurance_tail = APP_SOURCE.split('"A.8 assurance export"', 1)[1]
    assurance_tail = assurance_tail.split("def inject_full_app_styles", 1)[0]
    assert "Download A.8 assurance PDF" in assurance_tail
    assert "Download audit evidence package" not in assurance_tail
    assert "Open Evidence Hub" in assurance_tail


def test_client_history_owns_exposure_audit_trail() -> None:
    """Keep historical reports and lifecycle audit events in one records page."""
    history = APP_SOURCE.split("def render_client_history_page", 1)[1]
    history = history.split("def _wazuh_env_summary", 1)[0]
    assert '"Audit trail"' in history
    assert "list_audit_events(client)" in history
    assert "CISO synced" not in history


def test_dead_reports_audit_page_is_removed() -> None:
    """Remove the unrouted reports/audit presentation duplicate."""
    assert "def render_reports_audit_page(" not in EXPOSURE_SOURCE
