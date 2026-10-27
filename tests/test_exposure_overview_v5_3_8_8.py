"""Regression contract for the v5.3.8.8 Exposure Overview rebuild."""

from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "securescope" / "app.py"


def _overview_source() -> str:
    """Return only the Exposure Overview function source text.

    Returns:
        Source slice containing ``render_overview_page``.

    Raises:
        AssertionError: If the expected function boundaries are absent.
    """

    source = APP_PATH.read_text(encoding="utf-8")
    start = source.index("def render_overview_page() -> None:")
    end = source.index("def _asset_table_rows(", start)
    return source[start:end]


def test_overview_uses_canonical_exposure_model() -> None:
    """Ensure Overview consumes canonical findings across scanner engines."""

    source = _overview_source()
    assert "synchronize_findings_from_history" in source
    assert "list_findings(" in source
    assert "workspace_dashboard_metrics" in source
    assert "workspace_finding_analysis" in source


def test_overview_removes_non_decision_noise() -> None:
    """Keep provider administration and legacy integrations off Overview."""

    source = _overview_source()
    assert "render_scanner_fabric_overview(" not in source
    assert '"CISO coverage"' not in source
    assert '"Clock synchronization"' not in source
    assert '"Quick actions"' not in source


def test_overview_has_decision_sections() -> None:
    """Ensure the page answers exposure, coverage and action questions."""

    source = _overview_source()
    for label in (
        "Exposure Overview",
        "Active Vulnerabilities",
        "Priority Findings",
        "Scan Coverage",
        "Monitoring Coverage",
        "Exposure by Severity",
        "Actionable Risk Triggers",
        "Coverage Gaps",
        "Most Affected Assets",
        "Vulnerability age",
        "Recommended next step",
    ):
        assert label in source


def test_priority_table_is_action_oriented() -> None:
    """Keep the Overview table compact and prioritization-focused."""

    source = APP_PATH.read_text(encoding="utf-8")
    helper_start = source.index("def _canonical_priority_rows(")
    helper_end = source.index("def _exposure_source_row(", helper_start)
    helper = source[helper_start:helper_end]
    for column in (
        "Severity",
        "Finding",
        "Asset",
        "CVSS",
        "Exploit signal",
        "Source",
        "Last seen",
    ):
        assert f'"{column}"' in helper
