"""Professional Streamlit pages for SecureScope exposure and GRC workflows."""

from __future__ import annotations

import math
from datetime import date, datetime, time, timedelta, timezone
from html import escape
from typing import Any, Mapping, Sequence

import pandas as pd
import streamlit as st

from securescope.compliance.quick_remediation_service import (
    QuickRemediationError,
    candidate_payload_checksum,
    group_remediation_candidates,
    proposal_from_candidates,
)
from securescope.compliance.remediation_recipe_service import (
    RemediationRecipeError,
    RemediationRecipeRegistry,
)
from securescope.core.finding_domain import (
    ACTIVE_FINDING_STATUSES,
    FINDING_STATUSES,
    FindingDomainError,
    finding_dashboard_summary,
)
from securescope.core.gap_assessment_domain import (
    ASSESSMENT_MODELS,
    ASSESSMENT_STATUSES,
    ASSURANCE_DIMENSIONS,
    CRITERION_RESULTS,
    TEST_RESULTS,
    GapAssessmentError,
    RiskAcceptance,
    a81_wazuh_endpoint_coverage,
)
from securescope.core.presentation import safe_text
from securescope.core.remediation_domain import (
    PLAN_PRIORITIES,
    RemediationPlanInput,
    RemediationValidationError,
)
from securescope.grc.risk_register import (
    ASSET_GROUPS,
    ASSET_TAXONOMY,
    RISK_TYPES,
    TREATMENT_OPTIONS,
    TREATMENT_STATUSES,
    risk_level,
    risk_score,
)
from securescope.integrations.vulnerability_intelligence_service import extract_cves
from securescope.integrations.wazuh_remediation_adapter import WazuhRemediationAdapter
from securescope.persistence.audit_scope_repository import (
    MONTH_KEYS,
    default_schedule_rows,
    load_audit_scope,
    save_audit_scope,
)
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.db_wazuh_service import WazuhDatabaseError, load_latest_wazuh_status
from securescope.persistence.exposure_repository import (
    ExposureRepositoryError,
    create_remediation_plan,
    create_risk_acceptance,
    list_findings,
    list_remediation_plans,
    list_remediation_work_items,
    mark_expired_risk_acceptances,
    synchronize_findings_from_history,
    transition_finding,
    transition_remediation_work_item,
    workspace_dashboard_metrics,
    workspace_finding_analysis,
)
from securescope.persistence.grc_repository import (
    GrcRepositoryError,
    control_detail_history,
    create_control_target,
    create_improvement_action,
    create_profile_version,
    latest_statement_of_applicability,
    list_control_gaps_and_actions,
    list_control_overview,
    list_statement_of_applicability_versions,
    save_manual_control_assessment,
    save_statement_of_applicability,
)
from securescope.persistence.remediation_execution_repository import (
    create_approved_execution,
    list_remediation_executions,
)
from securescope.persistence.risk_register_repository import (
    list_risk_register,
    save_risk_record,
    seed_starter_risks,
)
from securescope.reporting.iso_assurance_export import build_iso_assurance_workbook
from securescope.reporting.template_toolkit import import_soa_template
from securescope.ui.assurance_interactions import (
    open_control_assessment,
)
from securescope.ui.components.navigation import module_tabs
from securescope.ui.components.primitives import metric_card
from securescope.ui.components_v2 import (
    components_v2_available,
)
from securescope.ui.control_assessment_ui import render_assessment
from securescope.ui.control_presenter import (
    ASSESSMENT_LABELS,
    human_assessment_label,
)
from securescope.ui.control_profiles_workbench import render_control_profiles
from securescope.ui.document_registers_ui import (
    render_populated_toolkit_download,
)
from securescope.ui.evidence_hub_ui import render_iso_evidence_hub
from securescope.ui.gap_dashboard_ui import (
    DASHBOARD_TAB,
    PROJECT_PLAN_TAB,
    render_gap_dashboard,
    render_project_plan,
)
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.intelligence_ui import enrich_priority_rows
from securescope.ui.navigation_runtime import navigate_to
from securescope.ui.workflow_sections import workflow_section

PRODUCT_ASSURANCE_WORDING = (
    "SecureScope provides evidence-assisted ISO/IEC 27001:2022 clauses 4–10 "
    "and Annex A assessment and improvement tracking. Automated technical "
    "evidence does not certify ISO/IEC 27001 compliance."
)

FORM_TEXT_AREA_HEIGHT = 88
FORM_LONG_TEXT_AREA_HEIGHT = 112


def _soft_metric_card(label: str, value: Any, meta: str, tone: str = "neutral") -> None:
    """Render a metric through the common escaped component.

    Args:
        label: Metric title.
        value: Display value.
        meta: Supporting text.
        tone: Semantic tone or legacy alias.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    metric_card(label, value, meta, tone)


def _workflow_step(label: str, value: Any, description: str) -> None:
    """Render one remediation workflow stage.

    Args:
        label: Workflow stage name.
        value: Current stage count.
        description: Short stage meaning.

    Returns:
        None.
    """

    st.markdown(
        f"""
        <div class="ss-workflow-step">
            <strong>{safe_text(label)}</strong>
            <b>{safe_text(value)}</b>
            <span>{safe_text(description)}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _compact_table_height(row_count: int, maximum: int = 440) -> int:
    """Return a readable dataframe height without leaving an empty panel.

    Args:
        row_count: Number of rows rendered in the dataframe.
        maximum: Maximum permitted table height in pixels.

    Returns:
        Dataframe height sized for the header and visible rows.

    Raises:
        ValueError: Never raised; negative inputs are normalized to zero.
    """

    return min(maximum, 76 + max(0, int(row_count)) * 35)


def _remediation_plan_rows(
    plans: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build a consultant-facing remediation plan register.

    Args:
        plans: Workspace-scoped plan rows loaded from PostgreSQL.

    Returns:
        Display rows that retain stable identifiers without exposing raw UUIDs.

    Raises:
        ValueError: Never raised for mapping-like repository rows.
    """

    return [
        {
            "Plan": f"#{row.get('id')}",
            "Title": row.get("title"),
            "Priority": row.get("priority"),
            "Owner": row.get("remediation_owner") or "Unassigned",
            "Due date": row.get("due_date"),
            "Status": row.get("status"),
            "Findings": row.get("finding_count", 0),
            "Tasks": (f"{row.get('completed_task_count', 0)}/" f"{row.get('task_count', 0)}"),
            "Milestones": row.get("milestone_count", 0),
            "Overdue": "Yes" if row.get("overdue") else "No",
        }
        for row in plans
    ]


def _remediation_work_item_rows(
    work_items: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build a readable task and milestone register.

    Args:
        work_items: Workspace-scoped task and milestone repository rows.

    Returns:
        Display rows using business labels and stable numeric references.

    Raises:
        ValueError: Never raised for mapping-like repository rows.
    """

    rows: list[dict[str, Any]] = []
    for item in work_items:
        item_type = str(item.get("entity_type") or "item").title()
        rows.append(
            {
                "Work item": f"{item_type} #{item.get('id')}",
                "Plan": f"#{item.get('plan_id')} · {item.get('plan_title')}",
                "Title": item.get("title"),
                "Owner": item.get("owner") or "Unassigned",
                "Priority": item.get("priority"),
                "Due date": item.get("due_date"),
                "Status": item.get("status"),
                "SLA days": item.get("sla_days"),
                "Evidence": item.get("evidence_reference") or "—",
            }
        )
    return rows


def _risk_treatment_plan_rows(
    plans: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build a consultant-facing Risk Treatment Plan register.

    Args:
        plans: Workspace-scoped treatment plan rows loaded from PostgreSQL.

    Returns:
        Display rows without internal tenant identifiers or UUID columns.

    Raises:
        ValueError: Never raised for mapping-like repository rows.
    """

    rows: list[dict[str, Any]] = []
    for plan in plans:
        linked_controls = plan.get("linked_controls") or []
        if isinstance(linked_controls, Sequence) and not isinstance(
            linked_controls,
            (str, bytes),
        ):
            control_display = ", ".join(str(value) for value in linked_controls)
        else:
            control_display = str(linked_controls)
        rows.append(
            {
                "Plan": f"#{plan.get('id')}",
                "Title": plan.get("title"),
                "Risk": plan.get("risk_reference"),
                "Treatment": plan.get("treatment_option"),
                "Linked controls": control_display or "—",
                "Owner": plan.get("owner") or "Unassigned",
                "Due date": plan.get("due_date"),
                "Status": plan.get("status"),
                "Milestones": (
                    f"{plan.get('completed_milestones', 0)}/" f"{plan.get('milestone_count', 0)}"
                ),
                "Approver": plan.get("approver") or "—",
            }
        )
    return rows


def _control_sort_key(control_id: Any) -> tuple[int, tuple[int, ...], str]:
    """Return a natural order for clauses followed by Annex A controls.

    Args:
        control_id: Clause or Annex A identifier such as ``10.1`` or ``A.5.1``.

    Returns:
        Sort key that places clauses 4–10 before Annex A and compares numbers.

    Raises:
        ValueError: Never raised; non-numeric fragments sort after numeric ones.
    """

    text = str(control_id or "")
    annex = text.upper().startswith("A.")
    normalized = text[2:] if annex else text
    parts: list[int] = []
    for value in normalized.split("."):
        try:
            parts.append(int(value))
        except ValueError:
            parts.append(9999)
    return (1 if annex else 0, tuple(parts), text)


def _metric_value(value: Any, unavailable: str = "Unavailable") -> Any:
    """Format an optional metric without converting missing data to zero.

    Args:
        value: Metric value or None.
        unavailable: Label used for unavailable data.

    Returns:
        Original value or unavailable label.

    Raises:
        ValueError: Never raised for displayable values.
    """

    return unavailable if value is None else value


def _render_optional_metric(label: str, value: Any, suffix: str = "") -> None:
    """Render an optional metric without presenting missing evidence as zero.

    Args:
        label: Human-readable metric name.
        value: Metric value or ``None`` when not assessed.
        suffix: Optional display suffix.

    Returns:
        None.

    Raises:
        ValueError: Never raised for displayable values.
    """

    if value is None:
        st.metric(label, "—")
        st.caption("Not assessed")
    else:
        st.metric(label, f"{value}{suffix}")


def _safe_sync_findings(
    client_name: str,
    scan_history: Sequence[Mapping[str, Any]],
) -> dict[str, int] | None:
    """Synchronize findings and present safe repository failures.

    Args:
        client_name: Exact active workspace name.
        scan_history: Workspace-filtered scan history.

    Returns:
        Synchronization counts, or None when persistence is unavailable.

    Raises:
        ValueError: Never raised; known domain/repository errors are displayed.
    """

    try:
        return synchronize_findings_from_history(client_name, scan_history)
    except (ExposureRepositoryError, FindingDomainError) as exc:
        st.warning(f"Canonical finding synchronization is unavailable: {exc}")
        return None


def render_workspace_exposure_metrics(
    client_name: str,
    scan_history: Sequence[Mapping[str, Any]],
    assets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Render aggregated exposure/GRC metrics for the active workspace.

    Args:
        client_name: Exact active workspace name.
        scan_history: Workspace-filtered scanner history.
        assets: Workspace-filtered asset inventory.

    Returns:
        Loaded dashboard metrics, or an empty mapping when unavailable.

    Raises:
        ValueError: Never raised; repository failures become safe UI states.
    """

    _safe_sync_findings(client_name, scan_history)
    try:
        metrics = workspace_dashboard_metrics(client_name)
    except ExposureRepositoryError as exc:
        st.info(f"Exposure metrics are not available yet: {exc}")
        return {}

    first_row = st.columns(6, gap="small")
    labels = (
        ("Active vulnerabilities", metrics.get("unique_active_findings")),
        ("Critical", metrics.get("critical")),
        ("High", metrics.get("high")),
        ("Medium", metrics.get("medium")),
        ("Low", metrics.get("low")),
        ("Informational", metrics.get("informational")),
    )
    for column, (label, value) in zip(first_row, labels):
        with column:
            st.metric(label, _metric_value(value, "Unknown"))

    asset_ips = {
        str(asset.get("ip") or asset.get("asset_ip") or "").strip().lower()
        for asset in assets
        if str(asset.get("ip") or asset.get("asset_ip") or "").strip()
    }
    scanned_ips: set[str] = set()
    for record in scan_history:
        record_asset = record.get("asset")
        nested_ip = str(record_asset.get("ip") or "") if isinstance(record_asset, Mapping) else ""
        scanned_ip = str(record.get("asset_ip") or nested_ip).strip().lower()
        if scanned_ip:
            scanned_ips.add(scanned_ip)
    scan_coverage = (
        round(len(asset_ips & scanned_ips) / len(asset_ips) * 100, 1) if asset_ips else None
    )
    try:
        wazuh_rows = load_latest_wazuh_status(client_name)
    except WazuhDatabaseError:
        wazuh_coverage = None
    else:
        wazuh_result = a81_wazuh_endpoint_coverage(assets, wazuh_rows, 100)
        wazuh_coverage = wazuh_result.current_coverage

    st.markdown("### Exposure and coverage")
    exposure_columns = st.columns(5, gap="small")
    exposure_values = (
        ("Assets", len(assets), ""),
        ("Scan coverage", scan_coverage, "%"),
        ("Wazuh endpoint coverage", wazuh_coverage, "%"),
        ("KEV exposure", metrics.get("kev"), ""),
        ("High-EPSS exposure", metrics.get("high_epss"), ""),
    )
    for column, (label, value, suffix) in zip(
        exposure_columns,
        exposure_values,
    ):
        with column:
            _render_optional_metric(label, value, suffix)

    st.markdown("### Remediation")
    remediation_values = (
        ("Open plans", metrics.get("open_remediation_plans"), ""),
        ("Overdue actions", metrics.get("overdue_remediation", 0), ""),
        (
            "Ready for verification",
            metrics.get("ready_for_verification"),
            "",
        ),
        (
            "Remediation completion",
            metrics.get("remediation_completion_rate"),
            "%",
        ),
        (
            "Mean time to remediate",
            metrics.get("mean_time_to_remediate_days"),
            " days",
        ),
        ("Mean vulnerability age", metrics.get("mean_age_days"), " days"),
        ("SLA compliance", metrics.get("sla_compliance"), "%"),
    )
    for offset in range(0, len(remediation_values), 4):
        chunk = remediation_values[offset : offset + 4]
        outcome_columns = st.columns(len(chunk), gap="small")
        for column, (label, value, suffix) in zip(outcome_columns, chunk):
            with column:
                _render_optional_metric(label, value, suffix)

    st.markdown("### Governance")
    governance = st.columns(5, gap="small")
    governance_values = (
        ("Open control gaps", metrics.get("open_gaps", 0)),
        (
            "Controls needing assessment",
            metrics.get("controls_requiring_assessment", 0),
        ),
        ("Evidence due", metrics.get("evidence_due", 0)),
        ("Risk reviews due", metrics.get("risk_reviews_due", 0)),
        ("Risks expiring ≤30d", metrics.get("accepted_risks_expiring", 0)),
    )
    for column, (label, value) in zip(governance, governance_values):
        with column:
            _render_optional_metric(label, value)
    return metrics


def render_workspace_finding_analysis(client_name: str) -> None:
    """Render workspace trends and actionable vulnerability analysis.

    Args:
        client_name: Exact active workspace name.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository failures become safe UI states.
    """

    range_label = st.selectbox(
        "Finding analysis period",
        ["7 days", "30 days", "90 days"],
        index=1,
        key="overview_finding_period",
    )
    days = int(range_label.split()[0])
    try:
        analysis = workspace_finding_analysis(client_name, days=days)
    except ExposureRepositoryError as exc:
        st.info(f"Finding analysis is not available yet: {exc}")
        return
    trend_rows = analysis.get("status_trends", [])
    if trend_rows:
        trend_frame = pd.DataFrame(trend_rows)
        trend_chart = trend_frame.pivot_table(
            index="event_date",
            columns="status",
            values="event_count",
            aggfunc="sum",
            fill_value=0,
        )
        st.bar_chart(trend_chart, width="stretch")
    else:
        st.info(f"No finding lifecycle events were recorded in the last {days} days.")
    columns = st.columns(4, gap="small")
    panels = (
        ("Vulnerability age", analysis.get("age_buckets", [])),
        ("Findings by scanner", analysis.get("scanners", [])),
        ("Most affected assets", analysis.get("affected_assets", [])),
        ("Remediation SLA by severity", analysis.get("sla_by_severity", [])),
    )
    for column, (title, panel_rows) in zip(columns, panels):
        with column:
            st.markdown(f"#### {title}")
            if panel_rows:
                st.dataframe(
                    pd.DataFrame(panel_rows),
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.caption("No assessed data.")


@st.fragment
def render_vulnerabilities_page(
    client_name: str,
    scan_history: Sequence[Mapping[str, Any]],
) -> None:
    """Render the canonical vulnerability investigation workspace.

    Args:
        client_name: Exact active workspace name.
        scan_history: Workspace-filtered scanner history.

    Returns:
        None.

    Raises:
        ValueError: Never raised; known repository failures are displayed safely.
    """

    st.title("Vulnerabilities")
    _safe_sync_findings(client_name, scan_history)

    try:
        rows = list_findings(client_name)
    except ExposureRepositoryError as exc:
        st.error(f"Vulnerability inventory is unavailable: {exc}")
        return

    if not rows:
        st.info(
            "No vulnerability findings are available yet. Run an authorized "
            "OpenVAS or Nuclei assessment to populate this workspace."
        )
        return

    rows = enrich_priority_rows(client_name, rows)
    summary = finding_dashboard_summary(rows)
    active_rows = [row for row in rows if str(row.get("status") or "") in ACTIVE_FINDING_STATUSES]
    severity_counts = {
        severity: sum(1 for row in active_rows if str(row.get("severity") or "") == severity)
        for severity in ("Critical", "High", "Medium", "Low", "Info")
    }
    kev_count = sum(row.get("kev_known_exploited") is True for row in active_rows)
    high_epss_count = sum(
        isinstance(row.get("epss_score"), (int, float))
        and float(row.get("epss_score") or 0.0) >= 0.5
        for row in active_rows
    )
    ready_to_verify = int(summary.get("lifecycle", {}).get("Ready for verification", 0))

    try:
        analysis = workspace_finding_analysis(client_name, days=30)
    except ExposureRepositoryError:
        analysis = {}
    age_rows = analysis.get("age_buckets", [])
    age_90 = next(
        (
            int(row.get("finding_count") or 0)
            for row in age_rows
            if str(row.get("age_bucket")) == "90+ days"
        ),
        0,
    )

    kpi_columns = st.columns(4, gap="medium")
    with kpi_columns[0]:
        _soft_metric_card(
            "ACTIVE FINDINGS",
            summary["unique_active_findings"],
            "Canonical findings across OpenVAS and Nuclei",
            "blue",
        )
    with kpi_columns[1]:
        _soft_metric_card(
            "PRIORITY EXPOSURE",
            severity_counts["Critical"] + severity_counts["High"],
            f"{severity_counts['Critical']} Critical · {severity_counts['High']} High",
            "lilac",
        )
    with kpi_columns[2]:
        _soft_metric_card(
            "EXPLOIT SIGNALS",
            kev_count + high_epss_count,
            f"{kev_count} KEV · {high_epss_count} high EPSS",
            "peach",
        )
    with kpi_columns[3]:
        _soft_metric_card(
            "READY TO VERIFY",
            ready_to_verify,
            "Findings waiting for fresh verification evidence",
            "mint",
        )

    distribution_column, signal_column = st.columns([1.8, 1], gap="large")
    with distribution_column:
        st.markdown("### Exposure distribution")
        severity_frame = pd.DataFrame(
            {
                "Severity": ["Critical", "High", "Medium", "Low", "Info"],
                "Active findings": [
                    severity_counts["Critical"],
                    severity_counts["High"],
                    severity_counts["Medium"],
                    severity_counts["Low"],
                    severity_counts["Info"],
                ],
            }
        ).set_index("Severity")
        st.bar_chart(severity_frame, width="stretch", height=300)

    with signal_column:
        st.markdown("### Risk signals")
        with st.container(border=True):
            st.metric("Known exploited", kev_count)
            st.metric("High EPSS", high_epss_count)
            st.metric("Older than 90 days", age_90)
            st.caption(
                "Exploitability and age help prioritize remediation; CVSS alone "
                "does not determine business priority."
            )

    trend_rows = analysis.get("status_trends", [])
    if trend_rows:
        st.markdown("### 30-day finding activity")
        trend_frame = pd.DataFrame(trend_rows)
        trend_chart = trend_frame.pivot_table(
            index="event_date",
            columns="status",
            values="event_count",
            aggfunc="sum",
            fill_value=0,
        )
        st.line_chart(trend_chart, width="stretch", height=270)

    severity_filter: list[str] = []
    status_filter: list[str] = []
    scanner_filter: list[str] = []
    asset_filter: list[str] = []
    treatment_filter: list[str] = []
    kev_filter = "All"
    search = ""
    with st.expander("Filters", expanded=False):
        filter_columns = st.columns(4)
        with filter_columns[0]:
            severity_filter = st.multiselect(
                "Severity",
                ["Critical", "High", "Medium", "Low", "Info", "Unknown"],
                default=[],
                key="vulnerability_severity_filter",
            )
        with filter_columns[1]:
            status_filter = st.multiselect(
                "Lifecycle",
                list(FINDING_STATUSES),
                default=[],
                key="vulnerability_status_filter",
            )
        with filter_columns[2]:
            scanner_options = sorted(
                {
                    str(scanner)
                    for row in rows
                    for scanner in (row.get("scanners") or [])
                    if str(scanner).strip()
                }
            )
            scanner_filter = st.multiselect(
                "Scanner",
                scanner_options,
                default=[],
                key="vulnerability_scanner_filter",
            )
        with filter_columns[3]:
            kev_filter = st.selectbox(
                "KEV",
                ["All", "Known exploited", "Not known", "Not enriched"],
                key="vulnerability_kev_filter",
            )
        secondary_filters = st.columns(3)
        with secondary_filters[0]:
            asset_options = sorted({str(row["asset_identity"]) for row in rows})
            asset_filter = st.multiselect(
                "Asset",
                asset_options,
                default=[],
                key="vulnerability_asset_filter",
            )
        with secondary_filters[1]:
            treatment_filter = st.multiselect(
                "Remediation state",
                sorted({str(row.get("treatment_decision") or "Not planned") for row in rows}),
                default=[],
                key="vulnerability_treatment_filter",
            )
        with secondary_filters[2]:
            search = (
                st.text_input(
                    "Search",
                    placeholder="CVE, finding, component or asset",
                    key="vulnerability_search",
                )
                .strip()
                .lower()
            )

    filtered: list[Mapping[str, Any]] = []
    for row in rows:
        if severity_filter and row.get("severity") not in severity_filter:
            continue
        if status_filter and row.get("status") not in status_filter:
            continue
        if scanner_filter and not set(scanner_filter).intersection(
            {str(value) for value in (row.get("scanners") or [])}
        ):
            continue
        if asset_filter and str(row.get("asset_identity")) not in asset_filter:
            continue
        treatment = str(row.get("treatment_decision") or "Not planned")
        if treatment_filter and treatment not in treatment_filter:
            continue
        kev_value = row.get("kev_known_exploited")
        if kev_filter == "Known exploited" and kev_value is not True:
            continue
        if kev_filter == "Not known" and kev_value is not False:
            continue
        if kev_filter == "Not enriched" and kev_value is not None:
            continue
        searchable = " ".join(
            str(row.get(key) or "")
            for key in (
                "vulnerability_identity",
                "title",
                "component",
                "asset_identity",
            )
        ).lower()
        if search and search not in searchable:
            continue
        filtered.append(row)

    severity_marks = {
        "Critical": "🔴 Critical",
        "High": "🟠 High",
        "Medium": "🟡 Medium",
        "Low": "🔵 Low",
        "Info": "⚪ Info",
    }
    display_rows: list[dict[str, Any]] = []
    for row in filtered:
        scanners = [str(value) for value in (row.get("scanners") or [])]
        evidence = row.get("most_recent_evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        if not scanners or scanners == ["unknown-scanner"]:
            scanners = [
                str(
                    evidence.get("scanner")
                    or evidence.get("engine")
                    or evidence.get("source")
                    or "Unknown"
                )
            ]
        epss = row.get("epss_score")
        if row.get("kev_known_exploited") is True:
            exploit_signal = "CISA KEV"
        elif isinstance(epss, (int, float)):
            exploit_signal = f"EPSS {float(epss):.0%}"
        elif row.get("enrichment_status"):
            exploit_signal = str(row["enrichment_status"])
        else:
            exploit_signal = "Unavailable · refresh feed"
        cvss = row.get("cvss")
        display_rows.append(
            {
                "Severity": severity_marks.get(
                    str(row.get("severity") or "Unknown"),
                    str(row.get("severity") or "Unknown"),
                ),
                "Finding": row.get("title") or row.get("vulnerability_identity"),
                "Asset": row.get("asset_identity"),
                "CVSS": "—" if cvss in (None, "") else cvss,
                "Exploit signal": exploit_signal,
                "Lifecycle": row.get("status"),
                "Source": ", ".join(scanners),
                "Last seen": row.get("last_seen"),
                "Remediation": row.get("treatment_decision") or "Not planned",
            }
        )

    st.markdown("### Priority findings")
    st.caption(f"{len(display_rows)} finding(s) match the current view.")
    visible_columns = list(display_rows[0]) if display_rows else []
    with st.popover("Finding table options"):
        chosen_columns = st.multiselect(
            "Visible columns",
            visible_columns,
            default=visible_columns,
            key=f"finding_columns::{client_name}",
        )
    pages = max(1, (len(display_rows) + 19) // 20)
    page = st.number_input(
        "Findings page",
        min_value=1,
        max_value=pages,
        value=1,
        key=f"finding_page::{client_name}::{pages}",
    )
    offset = (int(page) - 1) * 20
    page_rows = display_rows[offset : offset + 20]
    page_findings = filtered[offset : offset + 20]
    selection = st.dataframe(
        pd.DataFrame(page_rows).reindex(columns=chosen_columns or visible_columns),
        hide_index=True,
        width="stretch",
        height=_compact_table_height(len(page_rows), maximum=620),
        on_select="rerun",
        selection_mode="single-row",
        key=f"finding_details::{client_name}::{[row['id'] for row in page_findings]}",
        column_config={
            "Finding": st.column_config.TextColumn("Finding", width="large"),
            "Asset": st.column_config.TextColumn("Asset", width="medium"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "CVSS": st.column_config.TextColumn("CVSS", width="small"),
            "Exploit signal": st.column_config.TextColumn(
                "Exploit signal",
                width="small",
            ),
            "Lifecycle": st.column_config.TextColumn("Lifecycle", width="medium"),
            "Remediation": st.column_config.TextColumn("Remediation", width="medium"),
        },
    )

    if selection.selection.rows:
        finding = page_findings[selection.selection.rows[0]]
        with st.container(border=True):
            st.subheader(str(finding.get("title") or "Finding details"))
            st.caption(
                f"{finding.get('severity', 'Unknown')}"
                f" · {finding.get('asset_identity', 'Unknown asset')}"
                f" · {finding.get('status', 'Unknown state')}"
            )
            overview, evidence_tab, treatment_tab = module_tabs(
                ["Technical details", "Detection evidence", "Treatment"]
            )
            with overview:
                for field in (
                    "vulnerability_identity",
                    "description",
                    "component",
                    "cvss",
                    "first_seen",
                    "last_seen",
                ):
                    if finding.get(field) is not None:
                        st.write(f"{field.replace('_', ' ').capitalize()}: {finding[field]}")
            with evidence_tab:
                evidence = finding.get("most_recent_evidence")
                if evidence:
                    import json

                    from securescope.core.output_sanitizer import display_tool_output

                    st.code(
                        display_tool_output(
                            json.dumps(evidence, ensure_ascii=False, default=str), limit=12000
                        ),
                        language="json",
                    )
                else:
                    st.info("No detailed detection evidence is attached to this finding.")
            with treatment_tab:
                st.write(
                    str(finding.get("treatment_decision") or "No treatment decision recorded.")
                )
                st.caption(
                    "Use the existing lifecycle action below to record a reviewed transition."
                )

    analysis_columns = st.columns(2, gap="large")
    with analysis_columns[0]:
        st.markdown("### Most affected assets")
        affected_assets = analysis.get("affected_assets", [])
        if affected_assets:
            st.dataframe(
                pd.DataFrame(affected_assets),
                hide_index=True,
                width="stretch",
                height=_compact_table_height(len(affected_assets), maximum=360),
            )
        else:
            st.caption("No active asset concentration data.")
    with analysis_columns[1]:
        st.markdown("### Vulnerability age")
        if age_rows:
            st.dataframe(
                pd.DataFrame(age_rows),
                hide_index=True,
                width="stretch",
                height=_compact_table_height(len(age_rows), maximum=360),
            )
        else:
            st.caption("No active vulnerability age data.")

    with workflow_section(
        "Update finding lifecycle", "Update the status and accountable owner of this finding."
    ):
        labels = {f"#{row['id']} · {row['severity']} · {row['title']}": row for row in rows}
        selected_label = st.selectbox(
            "Finding",
            list(labels),
            key="finding_lifecycle_selection",
        )
        selected = labels[selected_label]
        with st.form("finding_lifecycle_form"):
            target_status = st.selectbox(
                "New status",
                list(FINDING_STATUSES),
                index=list(FINDING_STATUSES).index(selected["status"]),
            )
            reason = st.text_area("Reason and analyst notes")
            evidence_reference = st.text_input(
                "Verification evidence reference",
                placeholder="Re-scan report, ticket, approval or evidence ID",
            )
            actor = st.text_input("Changed by", value=current_actor(), disabled=True)
            analyst_authorized = st.checkbox("Authorized analyst decision")
            false_positive_approved = st.checkbox("False-positive decision approved")
            submitted = st.form_submit_button(
                "Apply validated transition",
                type="primary",
                width="stretch",
            )
        if submitted:
            try:
                transition_finding(
                    client_name,
                    int(selected["id"]),
                    target_status,
                    actor=actor,
                    reason=reason,
                    evidence_reference=evidence_reference,
                    analyst_authorized=analyst_authorized,
                    false_positive_approved=false_positive_approved,
                    risk_acceptance_approved=False,
                )
            except (ExposureRepositoryError, FindingDomainError) as exc:
                st.error(str(exc))
            else:
                st.success("Finding lifecycle and audit history updated.")
                st.rerun()


def _render_plan_creation(client_name: str, findings: Sequence[Mapping[str, Any]]) -> None:
    """Render and persist a complete remediation-plan creation form.

    Args:
        client_name: Exact active workspace name.
        findings: Canonical workspace finding rows.

    Returns:
        None.

    Raises:
        ValueError: Never raised; validation failures are displayed safely.
    """

    if not findings:
        st.info("No canonical findings are available for a remediation plan.")
        return
    labels = {
        f"#{row['id']} · {row['severity']} · {row['title']}": int(row["id"]) for row in findings
    }
    with st.form("create_remediation_plan_form"):
        selected_labels = st.multiselect(
            "Affected findings",
            list(labels),
        )
        title = st.text_input("Plan title")
        description = st.text_area("Description")
        form_columns = st.columns(2)
        with form_columns[0]:
            priority = st.selectbox("Priority", list(PLAN_PRIORITIES))
            treatment = st.selectbox(
                "Treatment decision",
                ["Remediate", "Mitigate", "Avoid"],
            )
            remediation_owner = st.text_input("Remediation owner")
            technical_owner = st.text_input("Technical owner")
            start_date = st.date_input("Start date", value=date.today())
            due_date = st.date_input(
                "Due date",
                value=date.today() + timedelta(days=30),
            )
            sla_days = st.number_input("SLA (days)", min_value=1, value=30)
        with st.expander("Advanced Details"):
            business_owner = st.text_input("Business owner")
            risk_owner = st.text_input("Risk owner")
            required_resources = st.text_area("Required resources")
            dependencies = st.text_area("Dependencies")
            compensating_controls = st.text_area("Compensating controls")
            expected_risk_reduction = st.text_area("Expected risk reduction")
        implementation_steps = st.text_area("Implementation steps")
        success_criteria = st.text_area("Success criteria")
        validation_method = st.text_area("Validation method")
        st.markdown("Initial task and milestone")
        task_columns = st.columns(2)
        with task_columns[0]:
            task_title = st.text_input("Initial task title")
            task_description = st.text_area("Initial task description")
            task_owner = st.text_input("Initial task owner")
            task_priority = st.selectbox(
                "Initial task priority",
                list(PLAN_PRIORITIES),
            )
            task_due_date = st.date_input("Initial task due date", value=due_date)
            task_sla_days = st.number_input(
                "Initial task SLA (days)",
                min_value=1,
                value=int(sla_days),
            )
            task_success_criteria = st.text_area("Initial task success criteria")
            task_verification = st.text_area("Initial task verification method")
        with task_columns[1]:
            milestone_title = st.text_input("Initial milestone title")
            milestone_owner = st.text_input("Initial milestone owner")
            milestone_due_date = st.date_input(
                "Initial milestone due date",
                value=min(task_due_date, date.today() + timedelta(days=14)),
            )
            milestone_success = st.text_area("Initial milestone success criteria")
        actor = st.text_input("Created by", value=current_actor(), disabled=True)
        submitted = st.form_submit_button(
            "Create plan, task and milestone",
            type="primary",
            width="stretch",
        )
    if submitted:
        try:
            plan = RemediationPlanInput(
                title=title,
                description=description,
                priority=priority,
                treatment_decision=treatment,
                remediation_owner=remediation_owner,
                technical_owner=technical_owner,
                business_owner=business_owner,
                risk_owner=risk_owner,
                start_date=start_date,
                due_date=due_date,
                sla_days=int(sla_days),
                required_resources=required_resources,
                dependencies=dependencies,
                implementation_steps=implementation_steps,
                compensating_controls=compensating_controls,
                expected_risk_reduction=expected_risk_reduction,
                success_criteria=success_criteria,
                validation_method=validation_method,
            )
            plan_id = create_remediation_plan(
                client_name,
                plan,
                [labels[label] for label in selected_labels],
                actor=actor,
                initial_task={
                    "title": task_title,
                    "description": task_description,
                    "owner": task_owner,
                    "priority": task_priority,
                    "start_date": start_date,
                    "due_date": task_due_date,
                    "sla_days": int(task_sla_days),
                    "success_criteria": task_success_criteria,
                    "verification_method": task_verification,
                    "milestone_title": milestone_title,
                    "milestone_owner": milestone_owner,
                    "milestone_due_date": milestone_due_date,
                    "milestone_success_criteria": milestone_success,
                },
            )
        except (RemediationValidationError, ExposureRepositoryError) as exc:
            st.error(str(exc))
        else:
            st.success(
                f"Remediation plan #{plan_id} is ready. "
                "An existing active plan is reused for the same findings."
            )
            st.rerun()


def _render_quick_plan_creation(
    client_name: str,
    findings: Sequence[Mapping[str, Any]],
) -> None:
    """Prepare a compact, deterministic remediation plan.

    Args:
        client_name: Exact active workspace name.
        findings: Workspace-scoped active canonical findings.

    Returns:
        None.

    Raises:
        ValueError: Never raised; validation failures are rendered safely.
    """

    if not findings:
        st.info("No active non-informational finding is available for remediation.")
        return
    try:
        registry = RemediationRecipeRegistry.load()
        candidates = group_remediation_candidates(
            findings,
            recipe_matcher=registry.match,
        )
    except (QuickRemediationError, RemediationRecipeError) as exc:
        st.error(f"Quick Remediation cannot prepare safe candidates: {exc}")
        return
    if not candidates:
        st.info("Only informational findings are active; no remediation is proposed.")
        return

    candidate_labels: dict[str, Any] = {}
    table_rows: list[dict[str, Any]] = []
    for candidate in candidates:
        has_cve = bool(extract_cves(candidate.vulnerability_identity))
        no_cve_label = "Not applicable · no CVE"
        unavailable_label = "Unavailable · refresh feed"
        label = (
            f"{candidate.priority.label} · {candidate.vulnerability_identity} · "
            f"{len(candidate.assets)} asset(s)"
        )
        candidate_labels[label] = candidate
        table_rows.append(
            {
                "Finding / group": candidate.title,
                "Affected assets": len(candidate.assets),
                "Risk priority": candidate.priority.label,
                "KEV": (
                    "Known exploited"
                    if candidate.kev is True
                    else (
                        "Not listed in checked feed"
                        if candidate.kev is False
                        else unavailable_label if has_cve else no_cve_label
                    )
                ),
                "EPSS": (
                    f"{candidate.epss:.1%}"
                    if candidate.epss is not None
                    else unavailable_label if has_cve else no_cve_label
                ),
                "Recommended fix": "Available",
                "Execution capability": candidate.execution_level,
                "Owner": "Unassigned",
                "Due date": candidate.due_date,
                "Status": "Ready to prepare",
            }
        )
    st.dataframe(
        pd.DataFrame(table_rows),
        hide_index=True,
        width="stretch",
        height=min(480, 90 + len(table_rows) * 35),
    )
    selected_labels = st.multiselect(
        "Findings",
        list(candidate_labels),
        help=(
            "Matching findings share one plan while every asset and finding "
            "link remains traceable."
        ),
        key="quick_remediation_candidate_selection",
    )
    selected = [candidate_labels[label] for label in selected_labels]
    if not selected:
        st.caption("Select one or more candidates to prepare a deterministic plan.")
        return
    proposal = proposal_from_candidates(selected)
    default_priority = str(proposal["priority"])

    with st.form("create_quick_remediation_plan_form"):
        st.markdown("#### Prepared remediation")
        title = st.text_input("Plan title", value=str(proposal["title"]))
        recommended_action = st.text_area(
            "Recommended action",
            value=str(proposal["recommended_action"]),
            help="Advisory text only. SecureScope never executes scanner text.",
        )
        primary_columns = st.columns(3)
        with primary_columns[0]:
            priority = st.selectbox(
                "Priority",
                list(PLAN_PRIORITIES),
                index=list(PLAN_PRIORITIES).index(default_priority),
            )
        with primary_columns[1]:
            remediation_owner = st.text_input("Owner")
        with primary_columns[2]:
            due_date = st.date_input("Due date", value=proposal["due_date"])
        validation_method = st.text_area(
            "Validation method",
            value=str(proposal["validation_method"]),
        )
        with st.expander("Advanced details", expanded=False):
            advanced_columns = st.columns(2)
            with advanced_columns[0]:
                technical_owner = st.text_input("Technical owner")
                business_owner = st.text_input("Business owner")
                risk_owner = st.text_input("Risk owner")
                required_resources = st.text_area("Required resources")
                dependencies = st.text_area("Dependencies")
            with advanced_columns[1]:
                treatment = st.selectbox(
                    "Treatment decision",
                    ["Remediate", "Mitigate", "Avoid"],
                )
                success_criteria = st.text_area(
                    "Success criteria",
                    value="; ".join(proposal["expected_evidence"]),
                )
                compensating_controls = st.text_area("Compensating controls")
                expected_risk_reduction = st.text_area(
                    "Expected risk reduction",
                    value=("Fresh scan no longer detects the selected canonical " "findings."),
                )
                actor = st.text_input("Created by", value=current_actor(), disabled=True)
        submitted = st.form_submit_button(
            "Create plan",
            type="primary",
            width="stretch",
        )
    if not submitted:
        return
    try:
        effective_actor = actor.strip() or remediation_owner.strip()
        effective_technical = technical_owner.strip() or remediation_owner.strip()
        effective_business = business_owner.strip() or remediation_owner.strip()
        effective_risk = risk_owner.strip() or remediation_owner.strip()
        sla_days = max(1, (due_date - date.today()).days)
        effective_success = (
            success_criteria.strip()
            or "Approved change record and fresh targeted scan confirm absence."
        )
        plan = RemediationPlanInput(
            title=title,
            description=recommended_action,
            priority=priority,
            treatment_decision=treatment,
            remediation_owner=remediation_owner,
            technical_owner=effective_technical,
            business_owner=effective_business,
            risk_owner=effective_risk,
            start_date=date.today(),
            due_date=due_date,
            sla_days=sla_days,
            required_resources=required_resources,
            dependencies=dependencies,
            implementation_steps=recommended_action,
            compensating_controls=compensating_controls,
            expected_risk_reduction=expected_risk_reduction,
            success_criteria=effective_success,
            validation_method=validation_method,
        )
        plan_id = create_remediation_plan(
            client_name,
            plan,
            proposal["finding_ids"],
            actor=effective_actor,
            initial_task={
                "title": proposal["initial_task"],
                "description": recommended_action,
                "owner": remediation_owner,
                "priority": priority,
                "start_date": date.today(),
                "due_date": due_date,
                "sla_days": sla_days,
                "success_criteria": effective_success,
                "verification_method": validation_method,
                "milestone_title": "Change implemented and ready for verification",
                "milestone_owner": remediation_owner,
                "milestone_due_date": due_date,
                "milestone_success_criteria": effective_success,
            },
        )
    except (
        QuickRemediationError,
        RemediationValidationError,
        ExposureRepositoryError,
    ) as exc:
        st.error(str(exc))
    else:
        st.success(
            f"Remediation plan #{plan_id} created with its first task and "
            "verification milestone."
        )
        st.rerun()


def _render_approved_execution_request(
    client_name: str,
    findings: Sequence[Mapping[str, Any]],
    plans: Sequence[Mapping[str, Any]],
) -> None:
    """Render an advanced request for one exact allow-listed execution.

    Args:
        client_name: Exact active workspace name.
        findings: Active workspace canonical findings.
        plans: Workspace remediation plans with linked finding IDs.

    Returns:
        None.

    Raises:
        ValueError: Never raised; validation failures are rendered safely.
    """

    try:
        registry = RemediationRecipeRegistry.load()
        candidates = group_remediation_candidates(
            findings,
            recipe_matcher=registry.match,
        )
        wazuh_rows = load_latest_wazuh_status(client_name)
    except (
        QuickRemediationError,
        RemediationRecipeError,
        WazuhDatabaseError,
    ) as exc:
        st.warning(f"Approved execution prerequisites are unavailable: {exc}")
        return
    executable = [candidate for candidate in candidates if candidate.recipe_id]
    if not executable:
        st.info(
            "No finding matches an integrity-checked execution recipe. Guided "
            "manual remediation remains available in Quick fix."
        )
        return
    eligible: dict[str, tuple[Mapping[str, Any], Any]] = {}
    for plan in plans:
        plan_finding_ids = {int(value) for value in (plan.get("finding_ids") or [])}
        for candidate in executable:
            if plan_finding_ids.intersection(candidate.finding_ids):
                label = (
                    f"Plan #{plan['id']} · {candidate.vulnerability_identity} · "
                    f"{candidate.recipe_id}"
                )
                eligible[label] = (plan, candidate)
    if not eligible:
        st.info("Create a plan for an executable candidate before requesting execution.")
        return

    selection = st.selectbox(
        "Approved execution candidate",
        list(eligible),
        key="approved_execution_candidate",
    )
    plan, candidate = eligible[selection]
    asset_identity = st.selectbox(
        "Exact target asset",
        list(candidate.assets),
        key="approved_execution_asset",
    )
    finding = next(
        (
            row
            for row in findings
            if int(row["id"]) in candidate.finding_ids
            and str(row["asset_identity"]) == asset_identity
        ),
        None,
    )
    recipe = registry.get(str(candidate.recipe_id))
    normalized_identity = asset_identity.split(":", 1)[-1].casefold()
    wazuh_row = next(
        (
            row
            for row in wazuh_rows
            if normalized_identity
            in {
                str(row.get("asset_ip") or "").casefold(),
                str(row.get("asset_tag") or "").casefold(),
            }
        ),
        None,
    )
    st.caption(
        f"Recipe {recipe.recipe_id} v{recipe.version} · "
        f"Privilege: {recipe.required_privilege} · "
        f"Expected duration: {recipe.expected_duration}"
    )
    st.warning(f"Restart/service impact: {recipe.restart_requirement}")
    st.caption(f"Rollback: {recipe.rollback_action}")
    if finding is None or wazuh_row is None:
        st.error(
            "The exact finding/asset has no synchronized Wazuh agent. Remote "
            "execution is unavailable; use Guided manual."
        )
        return
    agent_status = str(wazuh_row.get("wazuh_status") or "")
    if agent_status.casefold() not in recipe.compatible_wazuh_states:
        st.error("The matched Wazuh agent is not active and compatible.")
        return
    asset_ip = str(wazuh_row.get("asset_ip") or "").strip()
    asset_tag = str(wazuh_row.get("asset_tag") or "").strip()
    with st.form("approved_execution_request_form"):
        requester = st.text_input("Requested by")
        approver = st.text_input("Approver")
        confirmed_workspace = st.text_input(
            "Confirm workspace",
            placeholder=client_name,
        )
        confirmed_asset = st.text_input(
            "Confirm exact asset",
            placeholder=asset_identity,
        )
        approval_recorded = st.checkbox(
            "I approve this reviewed recipe for this exact workspace and asset"
        )
        submitted = st.form_submit_button(
            "Queue approved execution",
            type="primary",
            width="stretch",
        )
    if not submitted:
        if not WazuhRemediationAdapter.execution_enabled():
            st.caption(
                "Execution kill switch is disabled. An approved request will "
                "remain queued until an administrator enables it."
            )
        return
    if confirmed_workspace.strip() != client_name:
        st.error("Workspace confirmation does not match.")
        return
    if confirmed_asset.strip() != asset_identity:
        st.error("Asset confirmation does not match.")
        return
    try:
        execution_id = create_approved_execution(
            client_name,
            plan_id=int(plan["id"]),
            finding_id=int(finding["id"]),
            recipe=recipe,
            candidate_checksum=candidate_payload_checksum(candidate),
            asset_identity=asset_identity,
            asset_ip=asset_ip,
            asset_tag=asset_tag,
            wazuh_agent_id=str(wazuh_row.get("wazuh_agent_id") or ""),
            wazuh_agent_status=agent_status,
            requested_by=requester,
            approved_by=approver,
            approval_recorded=approval_recorded,
        )
    except ExposureRepositoryError as exc:
        st.error(str(exc))
    else:
        st.success(f"Approved execution #{execution_id} queued for the worker.")
        st.rerun()


def _render_risk_acceptance(
    client_name: str,
    findings: Sequence[Mapping[str, Any]],
) -> None:
    """Render a complete approved residual-risk acceptance form.

    Args:
        client_name: Exact active workspace name.
        findings: Canonical workspace findings.

    Returns:
        None.

    Raises:
        ValueError: Never raised; validation failures are displayed safely.
    """

    if not findings:
        st.info("No finding is available for risk acceptance.")
        return
    labels = {
        f"#{row['id']} · {row['severity']} · {row['title']}": int(row["id"]) for row in findings
    }
    with st.form("risk_acceptance_form"):
        selected_label = st.selectbox("Linked finding", list(labels))
        st.markdown("#### Decision basis")
        narrative_columns = st.columns(2)
        with narrative_columns[0]:
            business_justification = st.text_area(
                "Business justification",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with narrative_columns[1]:
            acceptance_scope = st.text_area(
                "Acceptance scope",
                height=FORM_TEXT_AREA_HEIGHT,
            )

        st.markdown("#### Ownership and approval")
        owner_columns = st.columns(3)
        with owner_columns[0]:
            risk_owner = st.text_input("Risk owner")
        with owner_columns[1]:
            approver = st.text_input("Approver")
        with owner_columns[2]:
            actor = st.text_input("Recorded by")

        date_columns = st.columns(4)
        with date_columns[0]:
            approval_date = st.date_input("Approval date", value=date.today())
        with date_columns[1]:
            effective_date = st.date_input("Effective date", value=date.today())
        with date_columns[2]:
            expiration_date = st.date_input(
                "Expiration / review date",
                value=date.today() + timedelta(days=90),
            )
        with date_columns[3]:
            review_frequency = st.text_input("Review frequency", value="Quarterly")

        st.markdown("#### Residual-risk evaluation")
        inherent_columns = st.columns(2)
        with inherent_columns[0]:
            inherent_likelihood = st.text_input("Inherent likelihood")
        with inherent_columns[1]:
            inherent_impact = st.text_input("Inherent impact")
        residual_columns = st.columns(3)
        with residual_columns[0]:
            residual_likelihood = st.text_input("Residual likelihood")
        with residual_columns[1]:
            residual_impact = st.text_input("Residual impact")
        with residual_columns[2]:
            residual_risk_level = st.text_input("Residual risk level")

        control_columns = st.columns(2)
        with control_columns[0]:
            current_controls = st.text_area(
                "Current controls",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with control_columns[1]:
            compensating_controls = st.text_area(
                "Compensating controls",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        evidence_reference = st.text_input("Approval/evidence reference")
        submitted = st.form_submit_button(
            "Approve risk acceptance",
            type="primary",
            width="stretch",
        )
    if submitted:
        try:
            acceptance = RiskAcceptance(
                linked_reference=str(labels[selected_label]),
                business_justification=business_justification,
                risk_owner=risk_owner,
                approver=approver,
                approval_date=approval_date,
                residual_likelihood=residual_likelihood,
                residual_impact=residual_impact,
                residual_risk_level=residual_risk_level,
                compensating_controls=compensating_controls,
                evidence_reference=evidence_reference,
                effective_date=effective_date,
                expiration_date=expiration_date,
                acceptance_scope=acceptance_scope,
            )
            acceptance_id = create_risk_acceptance(
                client_name,
                acceptance,
                inherent_likelihood=inherent_likelihood,
                inherent_impact=inherent_impact,
                current_controls=current_controls,
                review_frequency=review_frequency,
                actor=actor,
                finding_id=labels[selected_label],
            )
        except (GapAssessmentError, ExposureRepositoryError) as exc:
            st.error(str(exc))
        else:
            st.success(f"Risk acceptance #{acceptance_id} approved and scheduled for review.")
            st.rerun()


@st.fragment
def render_remediation_page(
    client_name: str,
    scan_history: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Render the vulnerability-remediation decision workspace.

    Args:
        client_name: Exact active workspace name.
        scan_history: Optional workspace scan history used to refresh canonical
            findings before prioritization.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository failures are displayed safely.
    """

    st.title("Remediation")
    from securescope.ui.assurance_queue import render_requirement_queue

    render_requirement_queue(client_name)
    if scan_history is not None:
        _safe_sync_findings(client_name, scan_history)

    try:
        due_count = mark_expired_risk_acceptances(client_name)
        findings = list_findings(
            client_name,
            statuses=sorted(ACTIVE_FINDING_STATUSES),
        )
        plans = list_remediation_plans(client_name)
        work_items = list_remediation_work_items(client_name)
        executions = list_remediation_executions(client_name)
    except ExposureRepositoryError as exc:
        st.error(f"Remediation data is unavailable: {exc}")
        return

    findings = enrich_priority_rows(client_name, findings)
    source_groups = {}
    for plan in plans:
        if plan.get("status") not in {"Completed", "Cancelled"} and plan.get("finding_ids"):
            source_groups.setdefault(tuple(sorted(plan["finding_ids"])), []).append(plan)
    duplicates = [group for group in source_groups.values() if len(group) > 1]
    if duplicates:
        st.warning(
            (
                "Some historical active plans share the same findings. Review"
                " ownership and history before cancelling redundant work."
            )
        )
        with st.expander("Review historical duplicate plans"):
            for group in duplicates:
                st.write("Plans " + ", ".join(f"#{p['id']} · {p['title']}" for p in group))
                st.caption("Records remain unchanged. No plan or audit history has been deleted.")

    if due_count:
        st.warning(f"{due_count} accepted risk decision(s) are due for review.")

    try:
        registry = RemediationRecipeRegistry.load()
        candidates = group_remediation_candidates(
            findings,
            recipe_matcher=registry.match,
        )
    except (QuickRemediationError, RemediationRecipeError):
        candidates = []

    priority_candidates = [
        candidate for candidate in candidates if candidate.priority.label in {"Critical", "High"}
    ]
    overdue_plans = sum(bool(plan.get("overdue")) for plan in plans)
    ready_plans = sum(str(plan.get("status")) == "Ready for verification" for plan in plans)
    ready_items = [
        item for item in work_items if str(item.get("status")) == "Ready for verification"
    ]

    kpi_columns = st.columns(4, gap="medium")
    with kpi_columns[0]:
        metric_card(
            "REMEDIATION QUEUE",
            len(candidates),
            "Grouped active findings ready for treatment planning",
            "info" if candidates else "neutral",
            compact=True,
        )
    with kpi_columns[1]:
        metric_card(
            "HIGH PRIORITY",
            len(priority_candidates),
            "Critical/High remediation groups after context scoring",
            "warning" if priority_candidates else "neutral",
            compact=True,
        )
    with kpi_columns[2]:
        metric_card(
            "OVERDUE",
            overdue_plans,
            "Plans past their approved due date",
            "warning" if overdue_plans else "neutral",
            compact=True,
        )
    with kpi_columns[3]:
        metric_card(
            "READY TO VERIFY",
            ready_plans + len(ready_items),
            "Plans or tasks waiting for verification evidence",
            "info" if ready_plans or ready_items else "neutral",
            compact=True,
        )

    st.markdown("### Remediation workflow")
    pipeline_columns = st.columns(5, gap="small")
    pipeline = (
        ("Triage", len(candidates), "Prioritize true exposure"),
        (
            "Planned",
            sum(str(plan.get("status")) in {"Draft", "Approved"} for plan in plans),
            "Owner and due date agreed",
        ),
        (
            "In progress",
            sum(str(plan.get("status")) == "In progress" for plan in plans),
            "Change is being implemented",
        ),
        (
            "Verify",
            ready_plans + len(ready_items),
            "Fresh evidence required",
        ),
        (
            "Closed",
            sum(str(plan.get("status")) == "Completed" for plan in plans),
            "Validated remediation",
        ),
    )
    for column, (label, value, description) in zip(pipeline_columns, pipeline):
        with column:
            _workflow_step(label, value, description)

    queue_tab, plans_tab, verify_tab, risk_tab = module_tabs(
        ["Priority queue", "Active plans", "Verify & close", "Finding Exceptions"]
    )

    with queue_tab:
        st.markdown("### What should be fixed first")
        st.caption(
            "Priority combines severity with KEV/EPSS, asset context, external "
            "exposure and vulnerability age. Scanner text is advisory only."
        )
        _render_quick_plan_creation(client_name, findings)

    with plans_tab:
        st.markdown("### Remediation plans")
        if not plans:
            st.info("No remediation plan has been created yet.")
        else:
            plan_rows = _remediation_plan_rows(plans)
            st.dataframe(
                pd.DataFrame(plan_rows),
                hide_index=True,
                width="stretch",
                height=_compact_table_height(len(plan_rows), maximum=520),
                column_config={
                    "Plan": st.column_config.TextColumn("Plan", width="small"),
                    "Title": st.column_config.TextColumn("Title", width="large"),
                    "Priority": st.column_config.TextColumn("Priority", width="small"),
                    "Owner": st.column_config.TextColumn("Owner", width="medium"),
                    "Due date": st.column_config.DateColumn("Due date", width="medium"),
                    "Status": st.column_config.TextColumn("Status", width="medium"),
                },
            )

        with st.expander("Approved endpoint execution", expanded=False):
            st.caption(
                "Execution remains allow-listed and approval-gated. Guided manual "
                "remediation is the default path."
            )
            if executions:
                execution_columns = (
                    "id",
                    "recipe_id",
                    "asset_tag",
                    "asset_ip",
                    "status",
                    "approved_by",
                    "verification_reference",
                    "failure_reason",
                    "updated_at",
                )
                st.dataframe(
                    pd.DataFrame(executions)[
                        [name for name in execution_columns if name in executions[0]]
                    ],
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.caption("No approved endpoint execution has been requested.")
            _render_approved_execution_request(client_name, findings, plans)

    with verify_tab:
        st.markdown("### Verification queue")
        st.caption(
            "A remediation is not complete until fresh evidence demonstrates the "
            "original weakness is no longer present or the approved acceptance is valid."
        )
        if ready_items:
            ready_rows = _remediation_work_item_rows(ready_items)
            st.dataframe(
                pd.DataFrame(ready_rows),
                hide_index=True,
                width="stretch",
                height=_compact_table_height(len(ready_rows), maximum=420),
            )
        else:
            st.info("No task is currently waiting for verification.")

        open_items = [
            item for item in work_items if str(item.get("status")) not in {"Completed", "Cancelled"}
        ]
        if open_items:
            with workflow_section(
                "Update remediation work item",
                "Track remediation progress and save the next action.",
            ):
                item_labels = {
                    f"{row['entity_type']} #{row['id']} · {row['title']}": row for row in open_items
                }
                selected_label = st.selectbox(
                    "Work item",
                    list(item_labels),
                    key="remediation_work_item_selection",
                )
                selected_item = item_labels[selected_label]
                allowed_statuses = (
                    [
                        "Open",
                        "In progress",
                        "Blocked",
                        "Ready for verification",
                        "Completed",
                        "Cancelled",
                    ]
                    if selected_item["entity_type"] == "task"
                    else [
                        "Open",
                        "In progress",
                        "Blocked",
                        "Completed",
                        "Cancelled",
                    ]
                )
                with st.form("remediation_work_item_transition"):
                    transition_columns = st.columns(2)
                    with transition_columns[0]:
                        target_status = st.selectbox(
                            "New status",
                            allowed_statuses,
                            index=allowed_statuses.index(selected_item["status"]),
                        )
                    with transition_columns[1]:
                        actor = st.text_input("Changed by", value=current_actor(), disabled=True)
                    reason = st.text_area(
                        "Status rationale",
                        height=FORM_TEXT_AREA_HEIGHT,
                    )
                    evidence_reference = st.text_input(
                        "Verification evidence reference",
                        help=(
                            "Use the canonical EV-<id> from Evidence. Completion requires"
                            " fresh accepted evidence and reviewer authorization; a "
                            "control reference is not evidence."
                        ),
                    )
                    transition_clicked = st.form_submit_button(
                        "Apply transition",
                        type="primary",
                        width="stretch",
                    )
                if transition_clicked:
                    try:
                        transition_remediation_work_item(
                            client_name,
                            str(selected_item["entity_type"]),
                            int(selected_item["id"]),
                            target_status,
                            actor=actor,
                            reason=reason,
                            evidence_reference=evidence_reference,
                        )
                    except ExposureRepositoryError as exc:
                        st.error(str(exc))
                    else:
                        st.success("Remediation work item and history updated.")
                        st.rerun()

        with st.expander("All tasks and milestones", expanded=False):
            if work_items:
                all_rows = _remediation_work_item_rows(work_items)
                st.dataframe(
                    pd.DataFrame(all_rows),
                    hide_index=True,
                    width="stretch",
                    height=_compact_table_height(len(all_rows), maximum=520),
                )
            else:
                st.caption("No remediation tasks or milestones exist yet.")

    with risk_tab:
        st.markdown("### Exceptions and accepted risk")
        st.caption(
            "Use risk acceptance only for an explicit, authorized residual-risk "
            "decision with an expiry and review date."
        )
        _render_risk_acceptance(client_name, findings)


def _parse_criterion_lines(value: str) -> list[dict[str, Any]]:
    """Parse criterion rows without assigning artificial weights or scores.

    Args:
        value: Newline-delimited ``description | result | evidence`` text.

    Returns:
        Explicit criterion records suitable for persistence.

    Raises:
        GapAssessmentError: If a row is malformed or uses an unknown result.
    """

    criteria: list[dict[str, Any]] = []
    for index, line in enumerate(value.splitlines(), start=1):
        if not line.strip():
            continue
        parts = [part.strip() for part in line.split("|", maxsplit=2)]
        if len(parts) < 2 or not parts[0]:
            raise GapAssessmentError(
                f"Criterion line {index} must contain description | result | evidence."
            )
        result = parts[1]
        if result not in CRITERION_RESULTS:
            raise GapAssessmentError(f"Criterion line {index} uses unsupported result: {result}")
        criteria.append(
            {
                "criterion_identifier": f"criterion-{index}",
                "description": parts[0],
                "required": True,
                "assessment_method": "Examine",
                "expected_evidence": parts[2] if len(parts) == 3 else "",
                "result": result,
                "evidence_reference": parts[2] if len(parts) == 3 else "",
            }
        )
    return criteria


def _render_manual_control_assessment(
    client_name: str,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    """Render a model-neutral manual control assessment and target workflow.

    Args:
        client_name: Exact active workspace name.
        rows: Latest workspace control-profile rows.

    Returns:
        None.

    Raises:
        ValueError: Never raised; domain and repository errors are displayed.
    """

    if not rows:
        st.info("No control assessment profile is available.")
        return
    labels = {
        f"{row['control_id']} · {row['control_name']} · {row['measurement_model']}": row
        for row in rows
    }
    selection_key = f"manual_control_profile::{client_name}"
    pending = st.session_state.pop(f"manual_control_pending::{client_name}", "")
    for label, profile in labels.items():
        if str(profile["control_id"]) == pending:
            st.session_state[selection_key] = label
            break
    if st.session_state.get(selection_key) not in labels:
        st.session_state.pop(selection_key, None)
    selected_label = st.selectbox(
        "Control assessment profile",
        list(labels),
        key=selection_key,
        on_change=open_control_assessment,
        args=(client_name,),
    )
    selected = labels[selected_label]
    from securescope.ui.policy_workspace import render_related_policies

    render_related_policies(client_name, str(selected["control_id"]))
    form_context = f"{client_name}::{selected['profile_id']}"
    st.caption(
        f"Model: {selected['measurement_model']} · Automation: "
        f"{selected['automation_level']}. This workflow records analyst evidence; "
        "it does not infer compliance from scanner data."
    )
    with st.expander("Control detail, evidence and version history"):
        st.write(str(selected.get("control_objective") or "Objective unavailable"))
        st.caption(
            str(
                selected.get("expected_security_outcome")
                or "Expected security outcome requires profile review."
            )
        )
        try:
            detail = control_detail_history(
                client_name,
                str(selected["control_id"]),
            )
        except GrcRepositoryError as exc:
            st.warning(f"Control detail history is unavailable: {exc}")
        else:
            detail_tabs = module_tabs(
                [
                    "Profiles",
                    "Targets",
                    "Assessments",
                    "Dimensions",
                    "Assessment evidence",
                    "Evidence Hub",
                    "Gaps",
                ]
            )
            for detail_tab, detail_name in zip(
                detail_tabs,
                [
                    "profiles",
                    "targets",
                    "assessments",
                    "dimensions",
                    "evidence",
                    "evidence_hub",
                    "gaps",
                ],
            ):
                with detail_tab:
                    detail_rows = detail.get(detail_name, [])
                    if detail_rows:
                        st.dataframe(
                            pd.DataFrame(detail_rows),
                            hide_index=True,
                            width="stretch",
                        )
                    else:
                        st.caption("No history recorded.")
    target_is_approved = selected.get("target_id") is not None
    if not target_is_approved:
        st.warning(
            "Approve a versioned target in the section below before saving an "
            "assessment. Current State cannot be evaluated without Target State."
        )
    with st.expander("Create a new assessment-profile version"):
        with st.form(f"control_profile_version_form::{form_context}"):
            st.markdown("#### Profile definition")
            model_columns = st.columns(2)
            with model_columns[0]:
                profile_model = st.selectbox(
                    "Measurement model",
                    list(ASSESSMENT_MODELS),
                    index=list(ASSESSMENT_MODELS).index(selected["measurement_model"]),
                )
            with model_columns[1]:
                automation_level = st.selectbox(
                    "Automation level",
                    ["Manual", "Partial", "Automated recommendation"],
                )
            profile_scope = st.text_area(
                "Approved assessment scope",
                height=FORM_TEXT_AREA_HEIGHT,
            )
            owner_columns = st.columns(3)
            with owner_columns[0]:
                control_owner = st.text_input("Profile control owner")
            with owner_columns[1]:
                assessment_owner = st.text_input("Profile assessment owner")
            with owner_columns[2]:
                profile_actor = st.text_input("Profile version created by")
            assessment_methods = st.multiselect(
                "Assessment methods",
                ["Examine", "Interview", "Test", "Observe", "Measure"],
                default=["Examine"],
            )
            requirement_columns = st.columns(2)
            with requirement_columns[0]:
                supported_sources = st.text_area(
                    "Supported data sources (one per line)",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            with requirement_columns[1]:
                evidence_requirements = st.text_area(
                    "Evidence requirements (one per line)",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            profile_submitted = st.form_submit_button(
                "Create profile version",
                type="primary",
                width="stretch",
            )
        if profile_submitted:
            try:
                new_version = create_profile_version(
                    client_name,
                    str(selected["control_id"]),
                    measurement_model=profile_model,
                    control_owner=control_owner,
                    assessment_owner=assessment_owner,
                    assessment_scope={"description": profile_scope.strip()},
                    assessment_methods=assessment_methods,
                    evidence_requirements=[
                        line.strip() for line in evidence_requirements.splitlines() if line.strip()
                    ],
                    automation_level=automation_level,
                    supported_data_sources=[
                        line.strip() for line in supported_sources.splitlines() if line.strip()
                    ],
                    actor=profile_actor,
                )
            except GrcRepositoryError as exc:
                st.error(str(exc))
            else:
                st.success(
                    f"Profile {selected['control_id']} version {new_version} created. "
                    "Approve a new target for this version before assessment."
                )
                st.rerun()
    with st.form(f"manual_control_assessment_form::{form_context}"):
        st.markdown("#### 1. Scope and assessment conclusion")
        scope_definition = st.text_area(
            "Assessment scope",
            height=FORM_TEXT_AREA_HEIGHT,
        )
        state_columns = st.columns(2)
        with state_columns[0]:
            current_state = st.text_area(
                "Current state",
                height=FORM_LONG_TEXT_AREA_HEIGHT,
            )
        with state_columns[1]:
            target_state = st.text_area(
                "Target state",
                height=FORM_LONG_TEXT_AREA_HEIGHT,
            )
        decision_columns = st.columns(2)
        with decision_columns[0]:
            assessment_status = st.selectbox(
                "Conservative assessment status",
                [
                    status
                    for status in ASSESSMENT_STATUSES
                    if status not in {"Not applicable", "Accepted residual risk"}
                ],
                index=1,
            )
        with decision_columns[1]:
            priority = st.selectbox(
                "Gap priority",
                ["Critical", "High", "Medium", "Low"],
                index=2,
            )

        st.markdown("#### 2. Gap and treatment")
        gap_columns = st.columns(2)
        with gap_columns[0]:
            gap_statement = st.text_area(
                "Gap statement",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with gap_columns[1]:
            related_risk = st.text_area(
                "Related risk",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        treatment_columns = st.columns(2)
        with treatment_columns[0]:
            remaining_effort = st.text_area(
                "Remaining effort",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with treatment_columns[1]:
            recommended_treatment = st.text_area(
                "Recommended treatment",
                height=FORM_TEXT_AREA_HEIGHT,
            )
        required_verification = st.text_area(
            "Required verification",
            height=FORM_TEXT_AREA_HEIGHT,
        )

        st.markdown("#### 3. Six independent assurance dimensions")
        dimension_results: dict[str, str] = {}
        dimension_columns = st.columns(3)
        for index, dimension in enumerate(ASSURANCE_DIMENSIONS):
            with dimension_columns[index % 3]:
                dimension_results[dimension] = st.selectbox(
                    dimension,
                    [
                        status
                        for status in ASSESSMENT_STATUSES
                        if status
                        not in {
                            "Not applicable",
                            "Accepted residual risk",
                        }
                    ],
                    index=2,
                    key=f"manual_dimension_{dimension}::{form_context}",
                )
        criterion_lines = st.text_area(
            "Criterion results",
            height=FORM_LONG_TEXT_AREA_HEIGHT,
            help=(
                "One per line: description | Pass/Partial/Fail/Not assessed/"
                "Not applicable | evidence reference. No percentage is calculated."
            ),
        )

        st.markdown("#### 4. Evidence and validation")
        evidence_reference_columns = st.columns(2)
        with evidence_reference_columns[0]:
            evidence_source = st.text_input("Evidence source")
        with evidence_reference_columns[1]:
            evidence_reference = st.text_input("Raw evidence reference")
        evidence_summary = st.text_area(
            "Evidence summary",
            height=FORM_LONG_TEXT_AREA_HEIGHT,
        )
        evidence_quality_columns = st.columns(2)
        with evidence_quality_columns[0]:
            evidence_freshness = st.selectbox(
                "Evidence freshness",
                ["Current", "Approaching expiration", "Expired", "Unknown"],
            )
        with evidence_quality_columns[1]:
            confidence = st.selectbox("Confidence", ["Low", "Medium", "High"])
        evidence_owner_columns = st.columns(3)
        with evidence_owner_columns[0]:
            accountable_owner = st.text_input("Accountable control owner")
        with evidence_owner_columns[1]:
            actor = st.text_input("Assessor")
        with evidence_owner_columns[2]:
            validator = st.text_input("Authorized validator (optional)")
        expiration_columns = st.columns([1, 2], vertical_alignment="bottom")
        with expiration_columns[0]:
            evidence_has_expiration = st.checkbox("Evidence has expiration date")
        with expiration_columns[1]:
            evidence_expiration_date = st.date_input(
                "Evidence expiration date",
                value=date.today() + timedelta(days=365),
                help="Used only when the expiration checkbox is selected.",
            )

        include_test = st.checkbox("Record an effectiveness test")
        test_data: dict[str, Any] | None = None
        if include_test:
            st.markdown("#### 5. Effectiveness test")
            test_definition_columns = st.columns(2)
            with test_definition_columns[0]:
                test_scenario = st.text_area(
                    "Test scenario",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
                expected_outcome = st.text_area(
                    "Expected outcome",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            with test_definition_columns[1]:
                test_objective = st.text_area(
                    "Test objective",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
                observed_outcome = st.text_area(
                    "Observed outcome",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            test_reference_columns = st.columns(3)
            with test_reference_columns[0]:
                tested_sample = st.text_input("Tested sample")
            with test_reference_columns[1]:
                test_evidence = st.text_input("Test evidence reference")
            with test_reference_columns[2]:
                tester = st.text_input("Tester")
            test_result_columns = st.columns(3, vertical_alignment="bottom")
            with test_result_columns[0]:
                test_result = st.selectbox("Test result", list(TEST_RESULTS))
            with test_result_columns[1]:
                retest_required = st.checkbox("Re-test required")
            with test_result_columns[2]:
                retest_due_date = st.date_input(
                    "Re-test due date",
                    value=date.today() + timedelta(days=30),
                    help="Used only when re-testing is required.",
                )
            corrective_action = st.text_area(
                "Corrective action",
                height=FORM_TEXT_AREA_HEIGHT,
            )
            test_data = {
                "test_scenario": test_scenario,
                "test_objective": test_objective,
                "expected_outcome": expected_outcome,
                "observed_outcome": observed_outcome,
                "test_date": date.today(),
                "tested_sample": tested_sample,
                "evidence_reference": test_evidence,
                "tester": tester,
                "result": test_result,
                "corrective_action": corrective_action,
                "retest_required": retest_required,
                "retest_due_date": retest_due_date if retest_required else None,
            }
        submitted = st.form_submit_button(
            "Save assessment and create gap when required",
            type="primary",
            width="stretch",
            disabled=not target_is_approved,
        )
    if submitted:
        try:
            criteria = _parse_criterion_lines(criterion_lines)
            expiration = (
                datetime.combine(
                    evidence_expiration_date,
                    time.min,
                    tzinfo=timezone.utc,
                )
                if evidence_has_expiration
                else None
            )
            assessment_id, gap_id = save_manual_control_assessment(
                client_name,
                int(selected["profile_id"]),
                assessment_status=assessment_status,
                current_state=current_state,
                target_state=target_state,
                gap_statement=gap_statement,
                scope_definition=scope_definition,
                accountable_owner=accountable_owner,
                evidence_source=evidence_source,
                evidence_reference=evidence_reference,
                evidence_summary=evidence_summary,
                evidence_freshness=evidence_freshness,
                evidence_expiration=expiration,
                confidence=confidence,
                dimension_results=dimension_results,
                criteria=criteria,
                effectiveness_test=test_data,
                related_risk=related_risk,
                remaining_effort=remaining_effort,
                priority=priority,
                recommended_treatment=recommended_treatment,
                required_verification=required_verification,
                actor=actor,
                validator=validator,
            )
        except (GrcRepositoryError, GapAssessmentError) as exc:
            st.error(str(exc))
        else:
            message = f"Assessment #{assessment_id} saved."
            if gap_id is not None:
                message += f" Gap #{gap_id} opened for treatment."
            st.success(message)
            st.rerun()

    with workflow_section(
        "Approve a versioned target for this control", "Record the approved expected outcome."
    ):
        with st.form(f"generic_control_target_form::{form_context}"):
            st.markdown("#### Approved control target")
            target_description = st.text_area(
                "Approved target description",
                height=FORM_LONG_TEXT_AREA_HEIGHT,
            )
            quantitative_target = st.checkbox("This target has a numeric value")
            target_columns = st.columns(3)
            with target_columns[0]:
                target_value = st.number_input(
                    "Target value",
                    min_value=0.0,
                    value=100.0,
                    help="Persisted only when the numeric-target checkbox is selected.",
                )
            with target_columns[1]:
                target_unit = st.text_input(
                    "Unit",
                    value="%",
                    help="Persisted only when the numeric-target checkbox is selected.",
                )
            with target_columns[2]:
                target_date = st.date_input(
                    "Target date",
                    value=date.today() + timedelta(days=90),
                    key=f"generic_target_date::{form_context}",
                )
            rationale_columns = st.columns(2)
            with rationale_columns[0]:
                rationale = st.text_area(
                    "Target rationale",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            with rationale_columns[1]:
                risk_basis = st.text_area(
                    "Target risk basis",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            remaining_scope = st.text_area(
                "Remaining-scope treatment when target is below full coverage",
                height=FORM_TEXT_AREA_HEIGHT,
            )
            requirement_columns = st.columns(2)
            with requirement_columns[0]:
                required_evidence = st.text_area(
                    "Required evidence",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            with requirement_columns[1]:
                required_test = st.text_area(
                    "Required effectiveness test",
                    height=FORM_TEXT_AREA_HEIGHT,
                )
            approval_columns = st.columns(2)
            with approval_columns[0]:
                approver = st.text_input("Target approver")
            with approval_columns[1]:
                approval_date = st.date_input(
                    "Target approval date",
                    value=date.today(),
                    key=f"generic_target_approval_date::{form_context}",
                )
            target_submitted = st.form_submit_button(
                "Approve target version",
                type="primary",
                width="stretch",
            )
        if target_submitted:
            try:
                version = create_control_target(
                    client_name,
                    int(selected["profile_id"]),
                    target_description=target_description,
                    target_value=float(target_value) if quantitative_target else None,
                    unit=target_unit if quantitative_target else "",
                    target_date=target_date,
                    rationale=rationale,
                    risk_basis=risk_basis,
                    remaining_scope_justification=remaining_scope,
                    required_evidence=[
                        line.strip() for line in required_evidence.splitlines() if line.strip()
                    ],
                    required_effectiveness_test=required_test,
                    approver=approver,
                    approval_date=approval_date,
                )
            except GrcRepositoryError as exc:
                st.error(str(exc))
            else:
                st.success(f"Target version {version} approved.")
                st.rerun()


def _render_gap_action_workflow(client_name: str) -> None:
    """Render persistent gap treatment actions and initial milestones.

    Args:
        client_name: Exact active workspace name.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository failures are displayed safely.
    """

    from securescope.ui.assurance_queue import render_requirement_queue

    render_requirement_queue(client_name)
    try:
        gaps = list_control_gaps_and_actions(client_name)
    except (GrcRepositoryError, DatabaseConfigurationError) as exc:
        st.error(f"Gap actions are unavailable: {exc}")
        return
    if not gaps:
        st.info("No persistent control gap is available for an improvement action.")
        return
    st.dataframe(pd.DataFrame(gaps), hide_index=True, width="stretch")
    labels = {
        f"#{row['id']} · {row['control_id']} · {row['priority']} · "
        f"{row['gap_statement']}": int(row["id"])
        for row in gaps
        if row["status"] not in {"Closed", "Accepted risk"}
    }
    if not labels:
        st.info("All recorded gaps are closed or covered by accepted risk.")
        return
    with st.form("improvement_action_form"):
        selected_gap = st.selectbox("Linked open gap", list(labels))
        recommended_action = st.text_area("Recommended action")
        action_columns = st.columns(2)
        with action_columns[0]:
            action_owner = st.text_input("Action owner")
            risk_owner = st.text_input("Action risk owner")
            priority = st.selectbox(
                "Action priority",
                ["Critical", "High", "Medium", "Low"],
                index=2,
            )
            start_date = st.date_input("Action start date", value=date.today())
            due_date = st.date_input(
                "Action due date",
                value=date.today() + timedelta(days=90),
            )
            sla_days = st.number_input("Action SLA (days)", min_value=1, value=90)
        with action_columns[1]:
            required_resources = st.text_area("Required resources")
            dependencies = st.text_area("Dependencies")
            success_criteria = st.text_area("Success criteria")
            verification_method = st.text_area("Verification method")
            expected_evidence = st.text_area("Expected evidence")
            actor = st.text_input("Action recorded by")
        milestone_title = st.text_input("First milestone")
        milestone_owner = st.text_input("Milestone owner")
        milestone_due_date = st.date_input(
            "Milestone due date",
            value=date.today() + timedelta(days=30),
        )
        milestone_success = st.text_area("Milestone success criteria")
        submitted = st.form_submit_button(
            "Create action, POA&M item and milestone",
            type="primary",
            width="stretch",
        )
    if submitted:
        try:
            action_id = create_improvement_action(
                client_name,
                labels[selected_gap],
                recommended_action=recommended_action,
                action_owner=action_owner,
                risk_owner=risk_owner,
                priority=priority,
                required_resources=required_resources,
                dependencies=dependencies,
                start_date=start_date,
                due_date=due_date,
                sla_days=int(sla_days),
                success_criteria=success_criteria,
                verification_method=verification_method,
                expected_evidence=expected_evidence,
                milestone_title=milestone_title,
                milestone_owner=milestone_owner,
                milestone_due_date=milestone_due_date,
                milestone_success_criteria=milestone_success,
                actor=actor,
            )
        except (GrcRepositoryError, DatabaseConfigurationError) as exc:
            st.error(str(exc))
        else:
            st.success(f"Improvement action #{action_id} created.")
            st.rerun()


def _human_assessment_label(value: Any) -> str:
    """Return the standardized human-facing assessment state.

    Args:
        value: Stored assessment status.

    Returns:
        One of the product-level human assessment labels.

    Raises:
        No exceptions are raised.
    """

    return human_assessment_label(value)


def _securescope_recommendation(row: Mapping[str, Any]) -> str:
    """Return an advisory SecureScope signal without copying the human decision.

    The recommendation is deliberately derived from assurance/evidence fields,
    not from the stored human assessment status. This preserves the product
    boundary: evidence can support a recommendation but never silently certify
    an ISO control.

    Args:
        row: Latest control-overview row.

    Returns:
        Conservative advisory recommendation label.

    Raises:
        No exceptions are raised.
    """

    evidence_count = int(row.get("approved_evidence_count") or 0)
    automation = str(row.get("automation_level") or "").casefold()
    score = row.get("assurance_score")
    try:
        assurance_score = float(score) if score is not None else None
    except (TypeError, ValueError):
        assurance_score = None
    current_count = int(row.get("current_evidence_count") or 0)
    if evidence_count > 0 and current_count <= 0:
        return "Evidence review required"
    if current_count <= 0:
        return "Manual review" if "manual" in automation else "Insufficient evidence"
    if assurance_score is not None and (
        not math.isfinite(assurance_score) or not 0 <= assurance_score <= 100
    ):
        return "Manual review"
    if assurance_score is None:
        if evidence_count <= 0:
            return "Manual review" if "manual" in automation else "Insufficient evidence"
        return "Manual review"
    if assurance_score >= 85:
        return "Likely implemented"
    if assurance_score >= 60:
        return "Partial support"
    return "Gap signal"


def _evidence_strength_label(row: Mapping[str, Any]) -> str:
    """Summarize validated evidence strength for one control.

    Args:
        row: Latest control-overview row.

    Returns:
        Compact evidence-strength label.

    Raises:
        No exceptions are raised.
    """

    count = int(row.get("approved_evidence_count") or 0)
    if count <= 0:
        return "—"
    current_count = int(row.get("current_evidence_count") or 0)
    if current_count <= 0:
        return f"{count} validated · freshness review required"
    if current_count < count:
        return f"{current_count} current · {count - current_count} need review"
    return f"{count} current · validated"


def _technical_coverage_label(row: Mapping[str, Any]) -> str:
    """Return real quantitative technical coverage when the model exposes it.

    Args:
        row: Latest control-overview row.

    Returns:
        Percentage text, or an em dash when no comparable coverage exists.

    Raises:
        No exceptions are raised.
    """

    unit = str(row.get("target_unit") or "").strip()
    value = row.get("current_value")
    if unit != "%" or value is None:
        return "—"
    try:
        numeric = float(value)
        if not math.isfinite(numeric) or not 0 <= numeric <= 100:
            return "—"
    except (TypeError, ValueError):
        return "—"
    rounded = round(numeric, 1)
    return f"{rounded:g}%"


def _review_date_label(value: Any) -> str:
    """Format a control review timestamp consistently for register display.

    Args:
        value: Timestamp/date value from PostgreSQL.

    Returns:
        ISO date text or an em dash.

    Raises:
        No exceptions are raised.
    """

    if isinstance(value, (datetime, date)):
        return value.isoformat()[:10]
    text = str(value or "").strip()
    return text[:10] if text else "—"


def _soa_rows_for_export(
    rows: Sequence[Mapping[str, Any]],
    latest_soa: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Normalize the current SoA register for both UI and Excel export."""

    source_rows = list(latest_soa.get("items", [])) if latest_soa else list(rows)
    return [
        {
            "control_id": row.get("control_id"),
            "control_name": row.get("control_name"),
            "necessary_control": row.get("necessary_control", True),
            "applicability": (
                "Not applicable"
                if str(row.get("applicability")).lower() == "not applicable"
                else "Applicable"
            ),
            "inclusion_justification": row.get("inclusion_justification") or "",
            "exclusion_justification": row.get("exclusion_justification") or "",
            "implementation_status": row.get("implementation_status")
            or row.get("assessment_status"),
            "control_owner": row.get("control_owner") or "Unassigned",
            "related_risks": ", ".join(str(value) for value in row.get("related_risks") or []),
            "related_treatment_plans": ", ".join(
                str(value) for value in row.get("related_treatment_plans") or []
            ),
            "evidence": ", ".join(str(value) for value in row.get("evidence") or []),
            "effectiveness_review": row.get("effectiveness_review") or "",
            "approved": bool(row.get("approved")),
        }
        for row in source_rows
        if str(row.get("control_id") or "").startswith("A.")
    ]


def _soa_editor_rows(editor: pd.DataFrame) -> list[dict[str, Any]]:
    """Convert the editable SoA grid into the export/import row contract.

    Args:
        editor: DataFrame returned by the current SoA data editor.
    Returns:
        Rows with list-valued evidence and relationship fields normalized.
    Raises:
        No exceptions are raised for normal editor values.
    """
    rows = []
    for original in editor.to_dict(orient="records"):
        row = dict(original)
        for field in ("related_risks", "related_treatment_plans", "evidence"):
            value = row.get(field)
            if isinstance(value, str):
                row[field] = [
                    item.strip() for item in value.replace("\n", ",").split(",") if item.strip()
                ]
        rows.append(row)
    return _soa_rows_for_export(rows)


def _render_iso_workbook_download(
    client_name: str,
    gap_rows: Sequence[Mapping[str, Any]],
    soa_rows: Sequence[Mapping[str, Any]],
    *,
    key_suffix: str,
) -> None:
    """Render one complete workbook download containing tables and charts."""

    try:
        audit_scope = load_audit_scope(client_name)
        risks = list_risk_register(client_name)
    except (GrcRepositoryError, DatabaseConfigurationError) as exc:
        audit_scope = None
        risks = []
        st.caption(
            (
                "Workbook export will include the available data; optional "
                "registers unavailable: "
                f"{exc}"
            )
        )
    schedule = list((audit_scope or {}).get("schedule") or default_schedule_rows())
    try:
        workbook_bytes = build_iso_assurance_workbook(
            client_name=client_name,
            gap_rows=gap_rows,
            soa_rows=soa_rows,
            audit_scope=audit_scope,
            schedule_rows=schedule,
            risks=risks,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:  # pragma: no cover - UI boundary
        st.error(f"Excel export could not be prepared: {type(exc).__name__}: {exc}")
        return
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in client_name)
    st.download_button(
        "Export ISO workbook with charts",
        data=workbook_bytes,
        file_name=f"securescope_iso_assurance_{safe_name}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        icon=":material/table_view:",
        key=f"iso_workbook_export::{key_suffix}",
        on_click="ignore",
    )


def _render_assessment_workflow_guide() -> None:
    """Explain the control-assessment decision path before the form."""

    st.info(
        "Assess controls in order: define the approved scope → record the current state → "
        "compare it with the target → attach current evidence → validate effectiveness → "
        "record the gap and treatment. SecureScope signals are advisory; the assessor and "
        "authorized validator make the final decision."
    )
    steps = st.columns(5, gap="small")
    for column, number, title, detail in zip(
        steps,
        ("1", "2", "3", "4", "5"),
        ("Scope", "State", "Evidence", "Validate", "Treat"),
        (
            "Use the approved profile and target.",
            "Describe what is implemented today.",
            "Cite a current, traceable source.",
            "Record a test or reviewer decision.",
            "Open or update the gap when required.",
        ),
    ):
        with column:
            st.markdown(
                (
                    '<div class="ss-workflow-step"><strong>'
                    f"{safe_text(number)}"
                    " · "
                    f"{safe_text(title)}"
                    "</strong><span>"
                    f"{safe_text(detail)}"
                    "</span></div>"
                ),
                unsafe_allow_html=True,
            )


def _render_audit_scope_workspace(client_name: str, rows: Sequence[Mapping[str, Any]]) -> None:
    """Render an auditable scope-of-audit record and twelve-month schedule."""

    del rows
    st.subheader("Audit Scope")
    st.caption(
        "Set the audit boundary first. Then assign audit numbers and months to clauses 4–10 "
        "and Annex A families so users can see what is planned, in fieldwork or closed."
    )
    try:
        saved = load_audit_scope(client_name)
    except (GrcRepositoryError, DatabaseConfigurationError) as exc:
        saved = None
        st.warning(f"Audit scope is not available yet: {exc}")
    saved = saved or {}
    edit_key = f"audit_scope_edit::{client_name}"
    if notice := st.session_state.pop(edit_key + "::notice", None):
        st.success(notice)
    if not st.session_state.get(edit_key):
        from securescope.ui.components.primitives import status_pill

        header, action = st.columns([4, 1], vertical_alignment="center")
        with header:
            st.markdown(f"### {saved.get('audit_year') or date.today().year} ISMS Audit")
            st.html(
                escape(str(saved.get("audit_no") or "AUD-001"))
                + " · "
                + status_pill(saved.get("status") or "Draft")
            )
        if action.button("Edit Audit Scope", key=edit_key + "::open"):
            st.session_state[edit_key] = True
            st.rerun()
        with st.container(border=True):
            lead, period = st.columns(2)
            lead.markdown(f"**Lead auditor**\n\n{saved.get('lead_auditor') or 'Unassigned'}")
            period.markdown(
                f"**Planned period**\n\n{saved.get('planned_start') or '—'} "
                f"→ {saved.get('planned_end') or '—'}"
            )
            st.markdown("#### Scope Statement")
            st.write(saved.get("scope_statement") or "Not recorded")
        with st.container(border=True):
            st.markdown("#### Audit Boundary")
            columns = st.columns(2)
            for index, field in enumerate(("sites", "processes", "systems", "exclusions")):
                columns[index % 2].markdown(f"**{field.title()}**")
                columns[index % 2].write(saved.get(field) or "Not recorded")
        with st.container(border=True):
            st.markdown("#### Objectives")
            st.write(saved.get("objectives") or "Not recorded")
        st.markdown("#### Annual Audit Schedule")
        st.dataframe(
            pd.DataFrame(saved.get("schedule") or default_schedule_rows()).fillna(""),
            hide_index=True,
            width="stretch",
        )
        return
    if st.button("Use Current ISMS Scope", key=edit_key + "::reuse"):
        from securescope.persistence.grc_workspace_repository import list_scope_versions
        from securescope.ui.grc_workspace.context import selected_context_ids

        engagement_id, scope_id = selected_context_ids(client_name)
        if engagement_id and scope_id:
            versions = list_scope_versions(client_name, engagement_id, scope_id)
            if versions:
                current_scope = versions[0]
                saved.update(
                    scope_statement=current_scope.get("scope_statement", ""),
                    sites="\n".join(map(str, current_scope.get("locations") or [])),
                    processes="\n".join(map(str, current_scope.get("organizational_units") or [])),
                    systems="\n".join(map(str, current_scope.get("technologies") or [])),
                )
                st.session_state[edit_key + "::prefill"] = saved
                st.success(
                    (
                        "Current scope statement and boundary copied. Adjust the audit "
                        "boundary below; the formal Scope remains unchanged."
                    )
                )
            else:
                st.info("No controlled Scope version exists yet.")
        else:
            st.info("Select an ISMS Scope first.")
    saved = st.session_state.get(edit_key + "::prefill", saved)
    schedule = list(saved.get("schedule") or default_schedule_rows())
    with st.form(f"audit_scope_form::{client_name}"):
        st.markdown("#### Audit identity")
        identity = st.columns(4, gap="small")
        with identity[0]:
            audit_no = st.text_input("Audit no", value=str(saved.get("audit_no") or "AUD-001"))
        with identity[1]:
            audit_year = st.number_input(
                "Audit year",
                min_value=2000,
                max_value=2200,
                value=int(saved.get("audit_year") or date.today().year),
                step=1,
            )
        with identity[2]:
            audit_status = st.selectbox(
                "Status",
                ["Draft", "Planned", "In progress", "Completed", "Cancelled"],
                index=["Draft", "Planned", "In progress", "Completed", "Cancelled"].index(
                    str(saved.get("status") or "Draft")
                ),
            )
        with identity[3]:
            lead_auditor = st.text_input("Lead auditor", value=str(saved.get("lead_auditor") or ""))
        st.markdown("#### Boundary")
        scope_columns = st.columns(2, gap="small")
        with scope_columns[0]:
            scope_statement = st.text_area(
                "Scope statement",
                value=str(saved.get("scope_statement") or ""),
                height=FORM_LONG_TEXT_AREA_HEIGHT,
                help="Describe the organizational, geographic and technical boundary of the audit.",
            )
            sites = st.text_area(
                "Sites / locations",
                value=str(saved.get("sites") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
            systems = st.text_area(
                "Systems / technologies",
                value=str(saved.get("systems") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with scope_columns[1]:
            processes = st.text_area(
                "Processes / organizational units",
                value=str(saved.get("processes") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
            exclusions = st.text_area(
                "Exclusions and justification",
                value=str(saved.get("exclusions") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        st.markdown("#### Objectives")
        objectives = st.text_area(
            "Audit objectives",
            value=str(saved.get("objectives") or ""),
            height=FORM_LONG_TEXT_AREA_HEIGHT,
        )
        criteria = st.text_input(
            "Audit criteria", value=str(saved.get("criteria") or "ISO/IEC 27001:2022")
        )
        date_columns = st.columns(2, gap="small")
        with date_columns[0]:
            planned_start = st.date_input(
                "Planned start", value=saved.get("planned_start") or date.today()
            )
        with date_columns[1]:
            planned_end = st.date_input(
                "Planned end", value=saved.get("planned_end") or date.today()
            )
        approval_columns = st.columns(2, gap="small")
        with approval_columns[0]:
            approved_by = st.text_input("Approved by", value=str(saved.get("approved_by") or ""))
        with approval_columns[1]:
            actor = st.text_input("Updated by", value=str(saved.get("updated_by") or ""))
        approval_comment = st.text_area(
            "Approval / planning comment",
            value=str(saved.get("approval_comment") or ""),
            height=FORM_TEXT_AREA_HEIGHT,
        )
        st.markdown("#### Annual schedule")
        edited_schedule = st.data_editor(
            pd.DataFrame(schedule).fillna(""),
            hide_index=True,
            width="stretch",
            height=620,
            key=f"audit_schedule_editor::{client_name}",
            disabled=["row_key", "iso_ref", "row_label", "row_type", "notes"],
            column_config={
                "row_key": st.column_config.TextColumn("Key", width="small"),
                "iso_ref": st.column_config.TextColumn("ISO ref", width="small"),
                "row_label": st.column_config.TextColumn("Scope of audit", width="large"),
                "row_type": st.column_config.TextColumn("Type", width="small"),
                "audit_no": st.column_config.TextColumn("Audit no", width="small"),
                **{
                    month: st.column_config.SelectboxColumn(
                        month.upper(),
                        options=["", "Planned", "Fieldwork", "Review", "Closed"],
                        width="small",
                    )
                    for month in MONTH_KEYS
                },
                "notes": st.column_config.TextColumn("Notes", width="large"),
            },
        )
        cancel_column, save_column = st.columns(2)
        cancelled = cancel_column.form_submit_button("Cancel", width="stretch")
        submitted = save_column.form_submit_button(
            "Save Audit Scope", type="primary", width="stretch"
        )
    if cancelled:
        st.session_state.pop(edit_key, None)
        st.session_state.pop(edit_key + "::prefill", None)
        st.rerun()
    if submitted:
        try:
            revision = save_audit_scope(
                client_name,
                {
                    "audit_no": audit_no,
                    "audit_year": int(audit_year),
                    "status": audit_status,
                    "scope_statement": scope_statement,
                    "objectives": objectives,
                    "criteria": criteria,
                    "sites": sites,
                    "processes": processes,
                    "systems": systems,
                    "exclusions": exclusions,
                    "lead_auditor": lead_auditor,
                    "planned_start": planned_start,
                    "planned_end": planned_end,
                    "approved_by": approved_by,
                    "approved_at": datetime.now(timezone.utc) if approved_by.strip() else None,
                    "approval_comment": approval_comment,
                },
                edited_schedule.to_dict(orient="records"),
                actor=actor,
                expected_revision=int(saved.get("revision") or 0),
            )
        except (GrcRepositoryError, DatabaseConfigurationError) as exc:
            st.error(str(exc))
        else:
            st.session_state.pop(edit_key, None)
            st.session_state.pop(edit_key + "::prefill", None)
            st.session_state[edit_key + "::notice"] = (
                f"Audit scope {audit_no} saved at revision {revision}."
            )
            st.rerun()


def _optional_score_selectbox(label: str, value: Any, key: str) -> int | None:
    """Render a score selector that preserves an unassessed state."""

    options: list[Any] = [None, 1, 2, 3, 4, 5]
    selected = value if value in options else None
    result = st.selectbox(
        label,
        options,
        index=options.index(selected),
        key=key,
        format_func=lambda item: "Not assessed" if item is None else str(item),
        help=(
            "Use 1 (rare/minor) to 5 (almost certain/severe). Leave blank "
            "until the risk owner has assessed it."
        ),
    )
    return result


def _render_risk_register_workspace(client_name: str) -> None:
    """Render the professional risk description, treatment and residual-risk workflow."""

    st.subheader("Risk register and treatment plan")
    st.caption(
        "Record the risk in plain language, score likelihood and impact before treatment, "
        "assign a decision and owner, then record the residual risk after evidence of treatment."
    )
    try:
        risks = list_risk_register(client_name)
    except (GrcRepositoryError, DatabaseConfigurationError) as exc:
        risks = []
        st.warning(f"Risk register is unavailable: {exc}")
    if not risks:
        st.info("No risks have been recorded in this workspace yet.")
        if st.button(
            "Load ISO starter risks",
            icon=":material/playlist_add:",
            key=f"seed_risks::{client_name}",
        ):
            try:
                seeded = seed_starter_risks(client_name)
            except (GrcRepositoryError, DatabaseConfigurationError) as exc:
                st.error(str(exc))
            else:
                st.success(
                    f"{seeded} starter risks added. Review every field before relying on them."
                )
                st.rerun()
        return
    summary_rows = []
    for row in risks:
        summary_rows.append(
            {
                "Ref": row.get("risk_ref"),
                "Asset": row.get("asset") or "—",
                "Owner": row.get("risk_owner") or "Unassigned",
                "Pre score": row.get("pre_risk_score") or "—",
                "Pre level": row.get("pre_risk_level"),
                "Treatment": row.get("treatment_option"),
                "Status": row.get("treatment_action_status"),
                "Post score": row.get("post_risk_score") or "—",
                "Post level": row.get("post_risk_level"),
            }
        )
    st.dataframe(pd.DataFrame(summary_rows), hide_index=True, width="stretch", height=260)
    chart_columns = st.columns(2, gap="medium")
    levels = ("Low", "Medium", "High", "Critical")
    chart_data = pd.DataFrame(
        {
            "Risk level": levels,
            "Pre-treatment": [
                sum(1 for row in risks if row.get("pre_risk_level") == level) for level in levels
            ],
            "Post-treatment": [
                sum(1 for row in risks if row.get("post_risk_level") == level) for level in levels
            ],
        }
    )
    with chart_columns[0]:
        st.markdown("**Risk levels before and after treatment**")
        st.bar_chart(
            chart_data,
            x="Risk level",
            y=["Pre-treatment", "Post-treatment"],
            color=["#D94841", "#00685F"],
        )
    with chart_columns[1]:
        treatment_counts = pd.DataFrame(
            {
                "Treatment option": list(TREATMENT_OPTIONS),
                "Risks": [
                    sum(1 for row in risks if row.get("treatment_option") == option)
                    for option in TREATMENT_OPTIONS
                ],
            }
        )
        st.markdown("**Risks by treatment option**")
        st.bar_chart(treatment_counts, x="Treatment option", y="Risks", color="#3C78D8")
    labels = {
        f"Risk {row['risk_ref']} · {row.get('asset') or 'Unspecified asset'}": row for row in risks
    }
    selected_label = st.selectbox(
        "Risk record to edit", list(labels), key=f"risk_selected::{client_name}"
    )
    selected = labels[selected_label]
    form_context = f"{client_name}::{selected['risk_ref']}"
    with st.form(f"risk_record_form::{form_context}"):
        st.markdown("#### 1. Risk description")
        identity_columns = st.columns(4, gap="small")
        with identity_columns[0]:
            risk_ref = st.number_input(
                "Ref", min_value=1, value=int(selected.get("risk_ref") or 1), step=1
            )
        with identity_columns[1]:
            asset_group = st.selectbox(
                "Asset group",
                list(ASSET_GROUPS),
                index=(
                    list(ASSET_GROUPS).index(selected.get("asset_group"))
                    if selected.get("asset_group") in ASSET_GROUPS
                    else 0
                ),
            )
        with identity_columns[2]:
            subcategories = list(ASSET_TAXONOMY.get(asset_group, {})) or [""]
            existing_subcategory = (
                selected.get("asset_subcategory")
                if selected.get("asset_subcategory") in subcategories
                else subcategories[0]
            )
            asset_subcategory = st.selectbox(
                "Sub-category", subcategories, index=subcategories.index(existing_subcategory)
            )
        with identity_columns[3]:
            asset_options = list(ASSET_TAXONOMY.get(asset_group, {}).get(asset_subcategory, ()))
            current_asset = str(selected.get("asset") or "")
            if current_asset and current_asset not in asset_options:
                asset_options = [current_asset, *asset_options]
            asset = st.selectbox(
                "Asset",
                ["", *asset_options],
                index=(
                    ["", *asset_options].index(current_asset)
                    if current_asset in ["", *asset_options]
                    else 0
                ),
            )
        description_columns = st.columns(2, gap="small")
        with description_columns[0]:
            threat = st.text_area(
                "Threat", value=str(selected.get("threat") or ""), height=FORM_TEXT_AREA_HEIGHT
            )
            vulnerability = st.text_area(
                "Vulnerability",
                value=str(selected.get("vulnerability") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with description_columns[1]:
            existing_controls = st.text_area(
                "Existing controls",
                value=str(selected.get("existing_controls") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
            risk_owner = st.text_input("Risk owner", value=str(selected.get("risk_owner") or ""))
        risk_type = st.selectbox(
            "Risk type",
            list(RISK_TYPES),
            index=(
                list(RISK_TYPES).index(selected.get("risk_type"))
                if selected.get("risk_type") in RISK_TYPES
                else 0
            ),
        )
        st.markdown("#### 2. Pre-treatment assessment")
        pre_columns = st.columns(4, gap="small")
        with pre_columns[0]:
            pre_likelihood = _optional_score_selectbox(
                "Likelihood", selected.get("pre_likelihood"), f"risk_pre_likelihood::{form_context}"
            )
        with pre_columns[1]:
            pre_impact = _optional_score_selectbox(
                "Impact", selected.get("pre_impact"), f"risk_pre_impact::{form_context}"
            )
        with pre_columns[2]:
            st.metric("Risk score", risk_score(pre_likelihood, pre_impact) or "—")
        with pre_columns[3]:
            st.metric("Risk level", risk_level(risk_score(pre_likelihood, pre_impact)))
        rationale_columns = st.columns(2, gap="small")
        with rationale_columns[0]:
            pre_likelihood_rationale = st.text_area(
                "Likelihood rationale",
                value=str(selected.get("pre_likelihood_rationale") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with rationale_columns[1]:
            pre_impact_rationale = st.text_area(
                "Impact rationale",
                value=str(selected.get("pre_impact_rationale") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        st.markdown("#### 3. Treatment plan")
        treatment_columns = st.columns(3, gap="small")
        with treatment_columns[0]:
            treatment_option = st.selectbox(
                "Treatment option",
                list(TREATMENT_OPTIONS),
                index=(
                    list(TREATMENT_OPTIONS).index(selected.get("treatment_option"))
                    if selected.get("treatment_option") in TREATMENT_OPTIONS
                    else 0
                ),
            )
        with treatment_columns[1]:
            action_owner = st.text_input(
                "Action owner", value=str(selected.get("treatment_action_owner") or "")
            )
        with treatment_columns[2]:
            action_status = st.selectbox(
                "Action status",
                list(TREATMENT_STATUSES),
                index=(
                    list(TREATMENT_STATUSES).index(selected.get("treatment_action_status"))
                    if selected.get("treatment_action_status") in TREATMENT_STATUSES
                    else 0
                ),
            )
        treatment_action = st.text_area(
            "Proposed treatment action",
            value=str(selected.get("treatment_action") or ""),
            height=FORM_TEXT_AREA_HEIGHT,
        )
        treatment_details = st.columns(3, gap="small")
        with treatment_details[0]:
            control_refs = st.text_input(
                "Annex A / control references",
                value=", ".join(str(item) for item in selected.get("control_references") or []),
            )
        with treatment_details[1]:
            treatment_cost = st.number_input(
                "Treatment cost",
                min_value=0.0,
                value=float(selected.get("treatment_cost") or 0),
                step=100.0,
            )
        with treatment_details[2]:
            timescale = st.text_input(
                "Timescale", value=str(selected.get("treatment_action_timescale") or "")
            )
        treatment_progress = st.text_area(
            "Treatment action progress",
            value=str(selected.get("treatment_action_progress") or ""),
            height=FORM_TEXT_AREA_HEIGHT,
        )
        st.markdown("#### 4. Post-treatment assessment")
        post_columns = st.columns(4, gap="small")
        with post_columns[0]:
            post_likelihood = _optional_score_selectbox(
                "Post likelihood",
                selected.get("post_likelihood"),
                f"risk_post_likelihood::{form_context}",
            )
        with post_columns[1]:
            post_impact = _optional_score_selectbox(
                "Post impact", selected.get("post_impact"), f"risk_post_impact::{form_context}"
            )
        with post_columns[2]:
            st.metric("Residual score", risk_score(post_likelihood, post_impact) or "—")
        with post_columns[3]:
            st.metric("Residual level", risk_level(risk_score(post_likelihood, post_impact)))
        post_rationale_columns = st.columns(2, gap="small")
        with post_rationale_columns[0]:
            post_likelihood_rationale = st.text_area(
                "Post likelihood rationale",
                value=str(selected.get("post_likelihood_rationale") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        with post_rationale_columns[1]:
            post_impact_rationale = st.text_area(
                "Post impact rationale",
                value=str(selected.get("post_impact_rationale") or ""),
                height=FORM_TEXT_AREA_HEIGHT,
            )
        comments = st.text_area(
            "Comments", value=str(selected.get("comments") or ""), height=FORM_TEXT_AREA_HEIGHT
        )
        actor = st.text_input("Updated by", value=str(selected.get("updated_by") or ""))
        submitted = st.form_submit_button("Save risk record", type="primary", width="stretch")
    if submitted:
        try:
            revision = save_risk_record(
                client_name,
                {
                    "risk_ref": int(risk_ref),
                    "asset_group": asset_group,
                    "asset_subcategory": asset_subcategory,
                    "asset": asset,
                    "threat": threat,
                    "vulnerability": vulnerability,
                    "risk_type": risk_type,
                    "risk_owner": risk_owner,
                    "existing_controls": existing_controls,
                    "pre_likelihood": pre_likelihood,
                    "pre_likelihood_rationale": pre_likelihood_rationale,
                    "pre_impact": pre_impact,
                    "pre_impact_rationale": pre_impact_rationale,
                    "treatment_option": treatment_option,
                    "treatment_action": treatment_action,
                    "control_references": [
                        item.strip() for item in control_refs.split(",") if item.strip()
                    ],
                    "treatment_cost": treatment_cost or None,
                    "treatment_action_owner": action_owner,
                    "treatment_action_timescale": timescale,
                    "treatment_action_progress": treatment_progress,
                    "treatment_action_status": action_status,
                    "post_likelihood": post_likelihood,
                    "post_likelihood_rationale": post_likelihood_rationale,
                    "post_impact": post_impact,
                    "post_impact_rationale": post_impact_rationale,
                    "comments": comments,
                },
                actor=actor,
                expected_revision=int(selected.get("revision") or 0),
            )
        except (GrcRepositoryError, DatabaseConfigurationError) as exc:
            st.error(str(exc))
        else:
            st.success(f"Risk {int(risk_ref)} saved at revision {revision}.")
            st.rerun()


@st.fragment
def render_gap_assessment_page(
    client_name: str,
    assets: Sequence[Mapping[str, Any]],
) -> None:
    """Render multi-model control profiles, targets and gap results.

    Args:
        client_name: Exact active workspace name.
        assets: Workspace-filtered asset inventory.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository errors are displayed safely.
    """

    from securescope.ui.components.stitch import apply_assurance_design

    apply_assurance_design()
    st.title("Control Assurance")
    st.caption(
        "Assess ISO/IEC 27001:2022 controls using technical, documentary and "
        "human-reviewed evidence. SecureScope recommendations remain advisory "
        "until human validation."
    )
    try:
        from securescope.ui.grc_workspace.context import selected_context_ids

        _, active_scope_id = selected_context_ids(client_name)
        rows = list_control_overview(client_name, scope_id=active_scope_id)
    except GrcRepositoryError as exc:
        st.error(f"Control assessment profiles are unavailable: {exc}")
        return
    rows = sorted(rows, key=lambda row: _control_sort_key(row.get("control_id")))

    pending_tab = st.session_state.pop(f"assurance_pending_tab::{client_name}", None)
    if pending_tab:
        st.session_state[f"assurance_active_tab::{client_name}"] = pending_tab

    (
        dashboard_tab,
        project_plan_tab,
        assessment_tab,
        manual_tab,
        evidence_tab,
        action_tab,
        soa_tab,
    ) = module_tabs(
        [
            DASHBOARD_TAB,
            PROJECT_PLAN_TAB,
            ":material/table_view: Control profiles",
            ":material/fact_check: Assess control",
            ":material/folder_open: Evidence",
            ":material/assignment_late: Gap actions",
            ":material/description: Statement of Applicability",
        ],
        container=st.container(key="control_assurance_tabs"),
        key=f"assurance_active_tab::{client_name}",
        on_change="rerun",
    )
    if dashboard_tab.open:
        with dashboard_tab:
            render_gap_dashboard(client_name, rows)
    if project_plan_tab.open:
        with project_plan_tab:
            render_project_plan(client_name)
    if assessment_tab.open:
        with assessment_tab:
            if st.session_state.get(f"control_drawers::{client_name}::implementation"):
                for prefix in ("control_profile_assessment_filter", "control_profile_search"):
                    filter_key = f"{prefix}::{client_name}"
                    if filter_key in st.session_state:
                        st.session_state[filter_key] = st.session_state[filter_key]
                render_control_profiles(client_name, [], [])
            else:
                gap_error = False
                try:
                    gap_rows = list_control_gaps_and_actions(client_name)
                except GrcRepositoryError:
                    gap_rows = []
                    gap_error = True
                    st.warning(
                        "Gap counts are temporarily unavailable."
                        " Refresh after checking the connection."
                    )
                gap_counts: dict[str, int] = {}
                for gap in gap_rows:
                    if str(gap.get("status") or "") in {"Closed", "Accepted risk"}:
                        continue
                    control_id = str(gap.get("control_id") or "")
                    gap_counts[control_id] = gap_counts.get(control_id, 0) + 1

                use_v2_table = components_v2_available()
                if use_v2_table:
                    filter_column, count_column = st.columns(
                        [1.35, 1],
                        gap="small",
                        vertical_alignment="center",
                    )
                    search_text = ""
                else:
                    search_column, filter_column, count_column = st.columns(
                        [2.2, 1.2, 1],
                        gap="small",
                        vertical_alignment="center",
                    )
                    with search_column:
                        search_text = st.text_input(
                            "Search controls",
                            placeholder="Search control ID or title...",
                            label_visibility="collapsed",
                            key=f"control_profile_search::{client_name}",
                        )
                with filter_column:
                    assessment_filter = st.selectbox(
                        "Assessment filter",
                        [
                            "All assessments",
                            *dict.fromkeys(ASSESSMENT_LABELS.values()),
                        ],
                        label_visibility="collapsed",
                        key=f"control_profile_assessment_filter::{client_name}",
                    )

                filtered_rows = []
                query = search_text.strip().casefold()
                for row in rows:
                    human_status = _human_assessment_label(row.get("assessment_status"))
                    if assessment_filter != "All assessments" and human_status != assessment_filter:
                        continue
                    searchable = (
                        f"{row.get('control_id', '')} {row.get('control_name', '')}".casefold()
                    )
                    if query and query not in searchable:
                        continue
                    filtered_rows.append(row)
                with count_column:
                    st.caption(f"Showing {len(filtered_rows)} of {len(rows)} controls")

                overview_rows = [
                    {
                        "Control": row.get("control_id") or "—",
                        "Title": row.get("control_name") or "—",
                        "SecureScope recommendation": _securescope_recommendation(row),
                        "Human assessment": _human_assessment_label(row.get("assessment_status")),
                        "Evidence strength": _evidence_strength_label(row),
                        "Tech coverage": _technical_coverage_label(row),
                        "Open gaps": (
                            None
                            if gap_error
                            else gap_counts.get(str(row.get("control_id") or ""), 0)
                        ),
                        "Owner": row.get("control_owner")
                        or row.get("assessment_owner")
                        or "Unassigned",
                        "Last review": _review_date_label(row.get("assessed_at")),
                    }
                    for row in filtered_rows
                ]
                render_control_profiles(client_name, filtered_rows, overview_rows)

    if manual_tab.open:
        with manual_tab:
            render_assessment(client_name, [dict(row) for row in rows])

    if evidence_tab.open:
        with evidence_tab:
            st.markdown("### Evidence workspace")
            st.caption(
                "Collect, import, review and request evidence here. Approved evidence "
                "supports control assessment but never changes a control status automatically."
            )
            render_iso_evidence_hub(client_name, embedded=True)
            with st.expander("Detailed A.8 technical assurance", expanded=False):
                st.caption(
                    "Use the technical drill-down when you need the original Nmap, "
                    "OpenVAS/Nuclei and Wazuh reasoning for Annex A.8 controls."
                )
                if st.button(
                    "Open A.8 technical assurance",
                    width="stretch",
                    key="control_assurance_open_a8",
                ):
                    navigate_to("6 · ISO 27001 Assessment")

    if action_tab.open:
        with action_tab:
            st.markdown("### Control gaps and improvement actions")
            st.caption("Track and resolve control gaps identified during assessment.")
            _render_gap_action_workflow(client_name)

    if soa_tab.open:
        with soa_tab:
            soa_workspace_tab, audit_scope_tab = module_tabs(
                [":material/description: SoA register", ":material/event_available: Scope of audit"]
            )
            with audit_scope_tab:
                _render_audit_scope_workspace(client_name, rows)
            with soa_workspace_tab:
                from securescope.ui.grc_workspace.context import selected_context_ids
                from securescope.ui.soa_ownership import render_legacy_soa

                soa_engagement, soa_scope = selected_context_ids(client_name)
                if soa_scope is None:
                    st.warning(
                        "Select an ISMS scope before preparing a new SoA version. Legacy v"
                        "ersions remain available below."
                    )
                render_legacy_soa(client_name, soa_engagement, soa_scope)
                try:
                    latest_soa = latest_statement_of_applicability(
                        client_name, engagement_id=soa_engagement, scope_id=soa_scope
                    )
                    soa_versions = list_statement_of_applicability_versions(
                        client_name, engagement_id=soa_engagement, scope_id=soa_scope
                    )
                except (GrcRepositoryError, DatabaseConfigurationError) as exc:
                    latest_soa = None
                    soa_versions = []
                    st.warning(f"SoA version history is unavailable: {exc}")
                soa_rows = _soa_rows_for_export(rows, latest_soa)
                if latest_soa:
                    st.caption(
                        f"SoA version {latest_soa['version_number']} · {latest_soa['status']} · "
                        f"Prepared by {latest_soa['prepared_by']}"
                    )
                if soa_versions:
                    with st.expander("Statement of Applicability version history"):
                        st.dataframe(
                            pd.DataFrame(soa_versions),
                            hide_index=True,
                            width="stretch",
                        )
                soa_import_prefix = f"soa_toolkit_import::{client_name}"
                st.session_state.pop(f"{soa_import_prefix}::applied", None)

                @st.dialog("Upload SoA template", width="large")
                def upload_soa_dialog():
                    """Preview the existing XLSX importer without changing persistence."""
                    st.caption(
                        "Upload a completed toolkit SoA for a row-level preview. "
                        "Import preview only — applying imports is not enabled in this version."
                    )
                    soa_upload = st.file_uploader(
                        "Completed Statement of Applicability workbook",
                        type=["xlsx"],
                        key=f"{soa_import_prefix}::upload",
                    )
                    preview_clicked = st.button(
                        "Preview toolkit controls",
                        disabled=soa_upload is None,
                        key=f"{soa_import_prefix}::preview",
                    )
                    if preview_clicked and soa_upload is not None:
                        try:
                            imported_rows, import_errors = import_soa_template(
                                soa_upload.getvalue()
                            )
                        except (ValueError, TypeError) as exc:
                            st.error(str(exc))
                        else:
                            st.session_state[f"{soa_import_prefix}::rows"] = imported_rows
                            st.session_state[f"{soa_import_prefix}::errors"] = import_errors
                    preview_rows = st.session_state.get(f"{soa_import_prefix}::rows")
                    preview_errors = st.session_state.get(f"{soa_import_prefix}::errors", [])
                    if preview_rows is not None:
                        st.dataframe(
                            pd.DataFrame(preview_rows),
                            hide_index=True,
                            width="stretch",
                            height=260,
                        )
                        if preview_errors:
                            st.error(
                                f"{len(preview_errors)} row validation issue(s) must be resolved "
                                "before this preview can enter the editor."
                            )
                            st.caption(" · ".join(preview_errors[:5]))
                        st.button(
                            "Use preview in SoA editor",
                            disabled=True,
                            help="The live database mapping must be reviewed first.",
                            key=f"{soa_import_prefix}::apply",
                        )

                if st.button("Upload SoA template", key=soa_import_prefix + "::open"):
                    upload_soa_dialog()
                missing_inclusion = [
                    r
                    for r in soa_rows
                    if r.get("applicability") == "Applicable"
                    and not str(r.get("inclusion_justification") or "").strip()
                ]
                missing_exclusion = [
                    r
                    for r in soa_rows
                    if r.get("applicability") == "Not applicable"
                    and not str(r.get("exclusion_justification") or "").strip()
                ]
                if missing_inclusion or missing_exclusion:
                    st.warning(
                        f"{len(missing_inclusion)} applicable entries "
                        "need inclusion justification; "
                        f"{len(missing_exclusion)} excluded entries need exclusion justification."
                    )
                    st.caption(
                        (
                            "Add the missing justification directly in the corresponding row "
                            "below before approval."
                        )
                    )
                from securescope.ui.soa_ownership import render_soa_working_editor

                edited_soa = render_soa_working_editor(
                    client_name, soa_engagement, soa_scope, soa_rows
                )
                st.warning(
                    "This is the structured SoA working view. Not Applicable requires "
                    "documented exclusion justification and authorized approval; "
                    "scanners cannot decide it."
                )
                current_soa_rows = _soa_editor_rows(edited_soa)
                _render_iso_workbook_download(
                    client_name,
                    rows,
                    current_soa_rows,
                    key_suffix=f"soa::{client_name}",
                )
                render_populated_toolkit_download(
                    "soa",
                    current_soa_rows,
                    client_name=client_name,
                    key=f"soa_toolkit::{client_name}",
                )
                with workflow_section(
                    "Create a versioned SoA snapshot",
                    "Review applicability and save a version for approval.",
                ):
                    with st.form(
                        f"soa_snapshot_form::{client_name}::{soa_engagement}::{soa_scope}"
                    ):
                        prepared_by = st.text_input(
                            "Prepared by", value=current_actor(), disabled=True
                        )
                        approve_soa = st.checkbox("Approve this SoA version")
                        approved_by = st.text_input(
                            "Approved by", value=current_actor(), disabled=True
                        )
                        soa_notes = st.text_area("Version notes")
                        soa_clicked = st.form_submit_button(
                            "Create SoA version", disabled=soa_scope is None
                        )
                    if soa_clicked:
                        items = []
                        for row in edited_soa.to_dict(orient="records"):
                            item = dict(row)
                            for list_field in (
                                "related_risks",
                                "related_treatment_plans",
                                "evidence",
                            ):
                                item[list_field] = [
                                    value.strip()
                                    for value in str(item.get(list_field) or "").split(",")
                                    if value.strip()
                                ]
                            # A version approval is not a substitute for the
                            # row-level approval required for exclusions.
                            item["approved"] = bool(item.get("approved")) and approve_soa
                            items.append(item)
                        try:
                            soa_version = save_statement_of_applicability(
                                client_name,
                                items,
                                prepared_by=prepared_by,
                                approved_by=approved_by,
                                approve=approve_soa,
                                notes=soa_notes,
                                engagement_id=soa_engagement,
                                scope_id=soa_scope,
                                actor=current_actor(),
                            )
                        except (GrcRepositoryError, DatabaseConfigurationError) as exc:
                            st.error(str(exc))
                        else:
                            st.session_state.pop(
                                f"soa_working_editor::{client_name}::{soa_engagement}::"
                                f"{soa_scope}::source",
                                None,
                            )
                            st.session_state.pop(
                                f"soa_working_editor::{client_name}::{soa_engagement}::"
                                f"{soa_scope}::baseline",
                                None,
                            )
                            st.success(f"SoA version {soa_version} created.")
                            st.rerun()
