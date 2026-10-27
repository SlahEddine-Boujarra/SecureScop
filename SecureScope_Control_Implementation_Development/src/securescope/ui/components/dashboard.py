"""Reusable decision-dashboard components for SecureScope."""

from __future__ import annotations

import html
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import streamlit as st

from securescope.grc.program_progress_service import ProgramProgressSnapshot
from securescope.ui.components.html_renderer import render_html
from securescope.ui.components.primitives import metric_card


@dataclass(frozen=True)
class DashboardMetric:
    """Describe one compact dashboard metric card.

    Args:
        label: Short metric title.
        value: Primary metric value.
        detail: Supporting context shown below the value.
        tone: Visual palette identifier between one and four.

    Raises:
        No exceptions are raised.
    """

    label: str
    value: str
    detail: str
    tone: int = 1


def render_dashboard_metrics(metrics: Sequence[DashboardMetric]) -> None:
    """Render a Figma-inspired row of compact programme metrics.

    Args:
        metrics: Ordered metric definitions.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    if not metrics:
        return
    columns = st.columns(len(metrics), gap="small")
    for column, metric in zip(columns, metrics):
        with column:
            metric_card(metric.label, metric.value, metric.detail)


def _group_control_statuses(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[tuple[str, int, str], ...]:
    """Group detailed assessment statuses into dashboard assurance buckets.

    Args:
        rows: Control overview records from the GRC repository.

    Returns:
        Ordered label, count and CSS-tone tuples.

    Raises:
        No exceptions are raised.
    """

    status_counts = Counter(str(row.get("assessment_status") or "Not assessed") for row in rows)
    implemented = sum(
        status_counts[value]
        for value in (
            "Target achieved",
            "Implemented and effective",
            "Implemented but not verified",
            "Accepted residual risk",
        )
    )
    partial = status_counts["Partially implemented"]
    gap = status_counts["Gap identified"] + status_counts["Not implemented"]
    evidence = status_counts["Insufficient evidence"]
    manual = status_counts["Manual assessment required"]
    not_assessed = status_counts["Not assessed"]
    return (
        ("Implemented / achieved", implemented, "success"),
        ("Partially implemented", partial, "warning"),
        ("Gap identified", gap, "danger"),
        ("Insufficient evidence", evidence, "info"),
        ("Manual assessment", manual, "neutral"),
        ("Not assessed", not_assessed, "muted"),
    )


def render_control_assurance_card(
    rows: Sequence[Mapping[str, Any]],
) -> None:
    """Render the current client-wide control assurance distribution.

    Args:
        rows: Latest control-overview rows for the active client workspace.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    grouped = _group_control_statuses(rows)
    total = max(sum(count for _label, count, _tone in grouped), 1)
    bars = []
    for label, count, tone in grouped:
        percentage = round((count / total) * 100)
        bars.append(
            f"""
            <div class="ss-assurance-row">
                <div class="ss-assurance-row__meta">
                    <span>{html.escape(label)}</span><strong>{count}</strong>
                </div>
                <div class="ss-assurance-track"
                     aria-label="{html.escape(label)} {count}">
                    <span class="ss-assurance-fill ss-assurance-fill--{tone}"
                          style="width:{percentage}%"></span>
                </div>
            </div>
            """
        )
    render_html(
        """
        <section class="ss-dashboard-panel">
            <div class="ss-dashboard-panel__header">
                <div><span>Control assurance</span>
                    <h3>Assessment distribution</h3></div>
                <small>Client-wide register</small>
            </div>
        """
        + "".join(bars)
        + "</section>"
    )


def render_evidence_coverage_card(
    summary: Mapping[str, Any] | None,
    *,
    applicable_controls: int,
) -> None:
    """Render evidence coverage and review-state metrics.

    Args:
        summary: Evidence Hub summary or ``None`` when unavailable.
        applicable_controls: Current applicable-control denominator.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    summary = summary or {}
    mapped_controls = int(summary.get("mapped_controls") or 0)
    validated = int(summary.get("validated") or 0)
    pending = int(summary.get("pending") or 0)
    expired = int(summary.get("expired") or 0)
    denominator = max(int(applicable_controls or 0), 0)
    coverage = round((mapped_controls / denominator) * 100) if denominator else 0
    coverage = max(0, min(coverage, 100))
    render_html(
        f"""
        <section class="ss-dashboard-panel ss-evidence-panel">
            <div class="ss-dashboard-panel__header">
                <div><span>Evidence coverage</span>
                    <h3>Validated assurance evidence</h3></div>
                <small>Client-wide register</small>
            </div>
            <div class="ss-evidence-layout">
                <div class="ss-donut" style="--value:{coverage * 3.6}deg">
                    <div><strong>{coverage}%</strong><span>mapped</span></div>
                </div>
                <div class="ss-evidence-stats">
                    <div><strong>{mapped_controls}</strong>
                        <span>controls with approved mapping</span></div>
                    <div><strong>{validated}</strong>
                        <span>validated evidence records</span></div>
                    <div><strong>{pending}</strong><span>pending review</span></div>
                    <div><strong>{expired}</strong><span>expired / stale</span></div>
                </div>
            </div>
        </section>
        """
    )


def render_foundation_work(snapshot: ProgramProgressSnapshot) -> None:
    """Render foundation tasks as readable status rows instead of a raw table.

    Args:
        snapshot: Programme foundation snapshot.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    rows = []
    for item in snapshot.items:
        state_class = "complete" if item.complete else "required"
        state = "Complete" if item.complete else "Action required"
        detail = "No action required" if item.complete else item.action
        rows.append(
            f"""
            <div class="ss-foundation-row ss-foundation-row--{state_class}">
                <span class="ss-foundation-state" aria-hidden="true"></span>
                <div class="ss-foundation-copy">
                    <strong>{html.escape(item.label)}</strong>
                    <span>{html.escape(detail)}</span>
                </div>
                <small>{html.escape(state)}</small>
            </div>
            """
        )
    render_html('<section class="ss-foundation-list">' + "".join(rows) + "</section>")
