"""ISO/IEC 27001 Command Center page.

The page is deliberately decision-oriented: programme foundation, human control
assessment, evidence coverage and technical-source coverage are summarized here,
while detailed editing remains in the dedicated workspaces.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

import pandas as pd
import streamlit as st

from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.grc.program_progress_service import calculate_program_progress
from securescope.persistence.db_wazuh_service import (
    WazuhDatabaseError,
    load_latest_wazuh_status,
)
from securescope.persistence.grc_repository import (
    GrcRepositoryError,
    list_control_overview,
)
from securescope.ui.components import (
    StitchMetric,
    render_assurance_distribution,
    render_attention_panel,
    render_certification_journey,
    render_register_table,
    render_stitch_metrics,
    render_technical_coverage,
)
from securescope.ui.control_presenter import (
    evidence_coverage_counts,
    human_assessment_label,
)
from securescope.ui.grc_workspace.context import open_selected_context
from securescope.ui.grc_workspace.router import select_programme_section
from securescope.ui.navigation_runtime import navigate_to

SERVICE = GrcWorkspaceService()


def _select_route(route: str) -> None:
    """Select one top-level application route.

    Args:
        route: Sidebar navigation key to activate.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    navigate_to(route)


def _open_setup_section(client_name: str, section: str) -> None:
    """Open Programme Foundation at one validated section.

    Args:
        client_name: Active client workspace name.
        section: Validated Programme Foundation section key.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    select_programme_section(client_name, section)
    navigate_to("Programme Setup")


def _milestone_frame(
    milestones: Sequence[Mapping[str, Any]],
) -> pd.DataFrame:
    """Create a compact next-milestones data frame.

    Args:
        milestones: Tenant-scoped engagement milestone rows.

    Returns:
        Consultant-facing milestone frame.

    Raises:
        No exceptions are raised.
    """

    return pd.DataFrame(
        [
            {
                "Milestone": row.get("title"),
                "Type": row.get("milestone_type"),
                "Owner": row.get("owner_name") or "Unassigned",
                "Due date": row.get("due_date"),
                "Status": row.get("status"),
            }
            for row in milestones
        ],
        columns=("Milestone", "Type", "Owner", "Due date", "Status"),
    )


def _control_metrics(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[int, int, int]:
    """Return applicable, assessed, and open-gap control counts.

    Args:
        rows: Latest client-wide control-overview records.

    Returns:
        Applicable controls, assessed controls, and controls with open gaps.

    Raises:
        No exceptions are raised.
    """

    applicable_rows = [row for row in rows if str(row.get("applicability")) != "Not applicable"]
    statuses = [str(row.get("assessment_status") or "Not assessed") for row in applicable_rows]
    assessed = sum(
        1 for status in statuses if status not in {"Not assessed", "Manual assessment required"}
    )
    gaps = sum(
        1
        for status in statuses
        if status
        in {
            "Gap identified",
            "Not implemented",
            "Partially implemented",
        }
    )
    return len(applicable_rows), assessed, gaps


def _assessment_distribution(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[tuple[str, int, str], ...]:
    """Group stored human assessment states for the Command Center.

    Args:
        rows: Latest client-wide control overview rows.

    Returns:
        Ordered display groups with counts and semantic tones.

    Raises:
        No exceptions are raised.
    """

    counts: Counter[str] = Counter()
    for row in rows:
        if str(row.get("applicability")) == "Not applicable":
            continue
        counts[human_assessment_label(row.get("assessment_status"))] += 1
    return (
        ("Implemented", counts["Implemented"], "success"),
        ("Verification Pending", counts["Verification Pending"], "warning"),
        ("Target Achieved", counts["Target Achieved"], "warning"),
        ("Accepted Risk", counts["Accepted Risk"], "warning"),
        ("Partially Implemented", counts["Partially Implemented"], "info"),
        ("Gap Identified", counts["Not Implemented"], "danger"),
        ("Insufficient Evidence", counts["Insufficient Evidence"], "warning"),
        ("Not Assessed", counts["Not Reviewed"], "muted"),
    )


def _asset_identity(asset: Mapping[str, Any]) -> str:
    """Return a stable asset identity for coverage matching.

    Args:
        asset: Workspace-filtered inventory row.

    Returns:
        Normalized IP when present, otherwise the asset tag.

    Raises:
        No exceptions are raised.
    """

    return str(
        asset.get("ip")
        or asset.get("ip_address")
        or asset.get("asset_ip")
        or asset.get("asset_tag")
        or ""
    ).strip()


def _engine_name(row: Mapping[str, Any]) -> str:
    """Resolve a normalized scanner engine name from one scan-history row.

    Args:
        row: Persisted scan/report record.

    Returns:
        ``OPENVAS``, ``NUCLEI`` or an empty string when unknown.

    Raises:
        No exceptions are raised.
    """

    raw = (
        str(row.get("engine") or row.get("scanner_engine") or row.get("scanner") or "")
        .strip()
        .upper()
    )
    if "NUCLEI" in raw:
        return "NUCLEI"
    if "OPENVAS" in raw or "GREENBONE" in raw or raw == "GVM":
        return "OPENVAS"
    return ""


def _scan_asset_identity(row: Mapping[str, Any]) -> str:
    """Return the inventory identity targeted by one scan-history row.

    Args:
        row: Scan/report record.

    Returns:
        Normalized asset/IP identity.

    Raises:
        No exceptions are raised.
    """

    return str(
        row.get("asset_ip") or row.get("ip") or row.get("target") or row.get("asset_tag") or ""
    ).strip()


def _technical_coverage_rows(
    client_name: str,
    assets: Sequence[Mapping[str, Any]],
    scan_history: Sequence[Mapping[str, Any]],
) -> tuple[tuple[str, str, str], ...]:
    """Calculate conservative coverage for evidence-producing technical sources.

    Missing data renders as unavailable rather than as zero so the Command
    Center never implies a failed control from absent telemetry.

    Args:
        client_name: Active client workspace name.
        assets: Current workspace inventory.
        scan_history: Current workspace scan/report history.

    Returns:
        Coverage rows for OpenVAS, Nuclei, Wazuh and asset discovery.

    Raises:
        No exceptions are raised; repository failures become unavailable rows.
    """

    identities = {_asset_identity(asset) for asset in assets if _asset_identity(asset)}
    denominator = len(identities)
    engine_targets: dict[str, set[str]] = {"OPENVAS": set(), "NUCLEI": set()}
    for row in scan_history:
        engine = _engine_name(row)
        target = _scan_asset_identity(row)
        if engine in engine_targets and target and target in identities:
            engine_targets[engine].add(target)

    rows: list[tuple[str, str, str]] = []
    for label, key in (("OpenVAS", "OPENVAS"), ("Nuclei", "NUCLEI")):
        observed = len(engine_targets[key])
        if not denominator:
            rows.append((label, "—", "No inventoried assets"))
        elif not observed:
            rows.append((label, "—", "No current engine-specific coverage data"))
        else:
            coverage = round((observed / denominator) * 100)
            rows.append((label, f"{coverage}%", f"{observed}/{denominator} assets observed"))

    try:
        wazuh_rows = load_latest_wazuh_status(client_name)
    except (WazuhDatabaseError, RuntimeError, ValueError):
        wazuh_rows = []
    if denominator and wazuh_rows:
        monitored = {
            str(row.get("asset_ip") or row.get("asset_tag") or "").strip()
            for row in wazuh_rows
            if str(row.get("monitoring_status") or "").casefold() == "monitored"
        }
        monitored.discard("")
        covered = len(monitored & identities) if identities else len(monitored)
        rows.append(
            (
                "Wazuh",
                f"{round((covered / denominator) * 100)}%",
                f"{covered}/{denominator} assets monitored",
            )
        )
    elif denominator:
        rows.append(("Wazuh", "—", "No current Wazuh snapshot"))
    else:
        rows.append(("Wazuh", "—", "No inventoried assets"))

    if not assets:
        rows.append(("Asset Discovery", "—", "No inventory yet"))
    else:
        classified = sum(1 for asset in assets if str(asset.get("asset_tag") or "").strip())
        rows.append(
            (
                "Asset Discovery",
                f"{round((classified / len(assets)) * 100)}%",
                f"{classified}/{len(assets)} assets tagged",
            )
        )
    return tuple(rows)


def _journey_steps(
    *,
    foundation_percent: int,
    scope_approved: bool,
    applicable_controls: int,
    assessed_controls: int,
    evidence_coverage: int,
    open_gaps: int,
) -> tuple[tuple[str, str], ...]:
    """Resolve lifecycle states from real programme state.

    Args:
        foundation_percent: Current foundation completion percentage.
        scope_approved: Whether the active scope has an approved version.
        applicable_controls: Number of applicable controls.
        assessed_controls: Number of controls with a human assessment outcome.
        evidence_coverage: Percentage of applicable controls with validated mapping.
        open_gaps: Number of controls requiring treatment attention.

    Returns:
        Ordered certification journey steps.

    Raises:
        No exceptions are raised.
    """

    organization = "complete" if foundation_percent >= 75 else "active"
    if foundation_percent == 0:
        organization = "active"
    scope_state = (
        "complete" if scope_approved else ("active" if foundation_percent >= 25 else "pending")
    )
    controls_state = "pending"
    if applicable_controls:
        if assessed_controls >= applicable_controls:
            controls_state = "complete"
        elif assessed_controls:
            controls_state = "active"
    evidence_state = (
        "complete"
        if evidence_coverage >= 100
        else ("active" if evidence_coverage > 0 else "pending")
    )
    treatment_state = (
        "active"
        if open_gaps > 0
        else ("pending" if assessed_controls < applicable_controls else "complete")
    )
    audit_state = (
        "active"
        if (
            foundation_percent == 100
            and applicable_controls > 0
            and assessed_controls >= applicable_controls
            and open_gaps == 0
        )
        else "pending"
    )
    return (
        ("Organization", organization),
        ("Scope", scope_state),
        ("Controls", controls_state),
        ("Evidence", evidence_state),
        ("Treatment", treatment_state),
        ("Audit", audit_state),
    )


def _primary_action(
    *,
    client_name: str,
    foundation_percent: int,
    applicable_controls: int,
    assessed_controls: int,
    evidence_coverage: int,
    open_gaps: int,
) -> tuple[str, Any, tuple[Any, ...]]:
    """Return the current best next action for the programme.

    Args:
        client_name: Active client workspace name.
        foundation_percent: Programme foundation percentage.
        applicable_controls: Number of applicable controls.
        assessed_controls: Number with assessment outcomes.
        evidence_coverage: Validated evidence coverage percentage.
        open_gaps: Controls requiring treatment attention.

    Returns:
        Button label, callback and callback arguments.

    Raises:
        No exceptions are raised.
    """

    if foundation_percent < 100:
        return (
            "Continue Programme",
            _open_setup_section,
            (client_name, "overview"),
        )
    if applicable_controls and assessed_controls < applicable_controls:
        return ("Review Controls", _select_route, ("Gap Assessment",))
    if evidence_coverage < 100:
        return ("Review Evidence", _select_route, ("ISO Evidence Hub",))
    if open_gaps:
        return ("Review Gap Actions", _select_route, ("Gap Assessment",))
    return ("Prepare for Audit", _select_route, ("Client History",))


@st.fragment(parallel=True)
def _render_technical_coverage_fragment(
    client_name: str,
    assets: Sequence[Mapping[str, Any]],
    scan_history: Sequence[Mapping[str, Any]],
) -> None:
    """Render technical-source coverage independently from the main dashboard.

    Args:
        client_name: Active workspace name.
        assets: Current normalized workspace assets.
        scan_history: Current saved scanner history.

    Returns:
        None.

    Raises:
        No exceptions are intentionally raised; source-specific failures are
        converted to unavailable coverage rows by ``_technical_coverage_rows``.
    """

    render_technical_coverage(_technical_coverage_rows(client_name, assets, scan_history))


def render_iso_command_center(client_name: str) -> None:
    """Render the Stitch-aligned ISO programme decision dashboard.

    Args:
        client_name: Exact active client workspace name.

    Returns:
        None.

    Raises:
        No exceptions are raised; known service failures become safe UI states.
    """

    try:
        context = open_selected_context(client_name)
    except GrcWorkspaceServiceError as exc:
        st.error(f"ISO programme context is unavailable: {exc}")
        return

    engagement_id = int(context["selected_engagement_id"])
    scope_id = context.get("selected_scope_id")
    try:
        registers = SERVICE.load_section(
            client_name,
            engagement_id,
            int(scope_id) if scope_id is not None else None,
            "overview",
        )
    except GrcWorkspaceServiceError as exc:
        st.error(f"Programme overview is unavailable: {exc}")
        return

    overview = context["overview"]
    engagement = overview.get("engagement") or {}
    scope = overview.get("scope") or {}
    snapshot = calculate_program_progress(
        overview,
        registers.get("climate_determinations", ()),
        registers.get("milestones", ()),
    )

    control_rows: list[dict[str, Any]] = []
    control_error = False
    try:
        control_rows = list_control_overview(client_name)
    except GrcRepositoryError:
        control_error = True

    applicable_controls, assessed_controls, open_gaps = _control_metrics(control_rows)
    mapped_controls, evidence_applicable = evidence_coverage_counts(control_rows)
    evidence_coverage = (
        round((mapped_controls / evidence_applicable) * 100)
        if evidence_applicable and not control_error
        else 0
    )
    scope_approved = bool(
        scope.get("latest_status") == "Approved" or overview.get("approved_scope_version")
    )

    st.title("Command Center")
    st.caption("Executive ISO/IEC 27001 dashboard and assurance posture.")
    st.caption(
        " · ".join(
            [
                str(engagement.get("name") or "ISO 27001 Programme"),
                str(scope.get("name") or "No ISMS scope selected"),
            ]
        )
    )

    render_stitch_metrics(
        (
            StitchMetric(
                "Programme Foundation",
                f"{snapshot.percentage}%",
                f"{snapshot.completed}/{snapshot.total} required foundation items",
                "primary",
            ),
            StitchMetric(
                "Controls Assessed",
                "—" if control_error else f"{assessed_controls}/{applicable_controls}",
                "Human-reviewed applicable controls",
                "neutral",
            ),
            StitchMetric(
                "Open Gaps",
                "—" if control_error else str(open_gaps),
                "Controls requiring gap/treatment attention",
                "danger" if open_gaps else "neutral",
            ),
            StitchMetric(
                "Evidence Coverage",
                "—" if control_error or not evidence_applicable else f"{evidence_coverage}%",
                "Applicable controls with current, validated evidence mapping",
                "info",
            ),
        )
    )

    main_column, attention_column = st.columns([2.15, 1], gap="large")
    with main_column:
        render_certification_journey(
            _journey_steps(
                foundation_percent=int(snapshot.percentage),
                scope_approved=scope_approved,
                applicable_controls=applicable_controls,
                assessed_controls=assessed_controls,
                evidence_coverage=evidence_coverage,
                open_gaps=open_gaps,
            )
        )
        assurance_column, technical_column = st.columns(2, gap="large")
        with assurance_column:
            if control_error:
                render_attention_panel(
                    (
                        {
                            "title": "Control register unavailable",
                            "detail": (
                                "No control-assurance conclusion is inferred while the register "
                                "cannot be read."
                            ),
                            "status": "Unavailable",
                            "tone": "warning",
                        },
                    ),
                    title="Control Assurance",
                )
            else:
                render_assurance_distribution(_assessment_distribution(control_rows))
        with technical_column:
            assets = list(st.session_state.get("assets") or [])
            scan_history = list(st.session_state.get("scan_history") or [])
            _render_technical_coverage_fragment(
                client_name,
                assets,
                scan_history,
            )

    attention_items: list[dict[str, str]] = []
    if snapshot.percentage < 100:
        incomplete = [item for item in snapshot.items if not item.complete]
        for item in incomplete[:2]:
            attention_items.append(
                {
                    "title": str(item.label),
                    "detail": str(item.action),
                    "status": "Review",
                    "tone": "warning",
                }
            )
    if not control_error and open_gaps:
        attention_items.append(
            {
                "title": f"{open_gaps} control gaps require attention",
                "detail": "Review persistent Gap Actions and treatment ownership.",
                "status": "Gap",
                "tone": "danger",
            }
        )
    if not control_error and applicable_controls and evidence_coverage < 100:
        missing = max(applicable_controls - mapped_controls, 0)
        attention_items.append(
            {
                "title": f"{missing} controls lack current, validated evidence mapping",
                "detail": "Collect or review evidence before relying on assurance conclusions.",
                "status": "Evidence",
                "tone": "warning",
            }
        )
    if not attention_items:
        attention_items.append(
            {
                "title": "No immediate programme action",
                "detail": (
                    "The current programme state has no unresolved priority signal in "
                    "this summary."
                ),
                "status": "Current",
                "tone": "info",
            }
        )
    with attention_column:
        render_attention_panel(attention_items, title="Programme Attention")
        if len(attention_items) > 3:
            st.caption(
                (
                    f"{len(attention_items) - 3}"
                    " additional programme items remain available in their "
                    "workspaces."
                )
            )

    with st.expander("Programme milestones and assurance lineage", expanded=False):
        st.caption(
            (
                "SecureScope lineage: technical observation → asset/risk context →"
                " ISO control → evidence → human assessment."
            )
        )
        render_register_table(
            _milestone_frame(registers.get("milestones", ())),
            empty_title="No upcoming milestones",
            empty_message=("Schedule the next workshop, internal audit, or certification date."),
            key="command_center_milestone_register",
        )
