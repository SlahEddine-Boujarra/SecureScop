"""Stitch-aligned reusable presentation components for SecureScope.

These helpers render presentation-only HTML from already resolved application
state. They deliberately do not perform persistence, scanner execution, ISO
assessment, or navigation decisions.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.components.html_renderer import render_html
from securescope.ui.components_v2 import render_journey_v2, render_metric_grid_v2


@dataclass(frozen=True)
class StitchMetric:
    """Describe one enterprise KPI card.

    Args:
        label: Compact card label.
        value: Primary value rendered with strong hierarchy.
        detail: Optional supporting description.
        tone: Semantic tone: neutral, primary, danger, warning, or info.

    Raises:
        No exceptions are raised.
    """

    label: str
    value: str
    detail: str = ""
    tone: str = "neutral"


def render_stitch_metrics(metrics: Sequence[StitchMetric]) -> None:
    """Render a responsive KPI grid using the SecureScope design system.

    Args:
        metrics: Ordered KPI definitions.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    if not metrics:
        return
    if render_metric_grid_v2(
        [
            {
                "label": metric.label,
                "value": metric.value,
                "detail": metric.detail,
                "tone": metric.tone,
            }
            for metric in metrics
        ],
        key="securescope_stitch_metric_grid",
    ):
        return
    cards = []
    for metric in metrics:
        tone = (
            metric.tone
            if metric.tone
            in {
                "neutral",
                "primary",
                "danger",
                "warning",
                "info",
            }
            else "neutral"
        )
        detail = f"<small>{html.escape(metric.detail)}</small>" if metric.detail else ""
        cards.append(
            '<article class="ss-stitch-kpi '
            f'ss-stitch-kpi--{tone}">'
            f"<span>{html.escape(metric.label)}</span>"
            f"<strong>{html.escape(metric.value)}</strong>"
            f"{detail}</article>"
        )
    render_html('<section class="ss-stitch-kpi-grid">' + "".join(cards) + "</section>")


def render_certification_journey(
    steps: Sequence[tuple[str, str]],
) -> None:
    """Render a compact ISO programme journey.

    Args:
        steps: Ordered ``(label, state)`` tuples. State is one of ``complete``,
            ``active``, ``pending``, or ``blocked``.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    if render_journey_v2(
        [{"label": label, "state": state} for label, state in steps],
        key="securescope_certification_journey",
    ):
        return
    nodes = []
    for label, state in steps:
        resolved = state if state in {"complete", "active", "pending", "blocked"} else "pending"
        nodes.append(
            '<div class="ss-journey-step '
            f'ss-journey-step--{resolved}">'
            '<span class="ss-journey-dot" aria-hidden="true"></span>'
            f"<strong>{html.escape(label)}</strong>"
            "</div>"
        )
    render_html(
        '<section class="ss-stitch-panel ss-journey-panel">'
        '<div class="ss-stitch-panel__heading">'
        "<div><h3>Certification Journey</h3>"
        "<p>Current readiness stage across the ISO/IEC 27001 lifecycle.</p></div>"
        "</div>"
        '<div class="ss-journey-track">' + "".join(nodes) + "</div></section>"
    )


def render_assurance_distribution(
    rows: Sequence[tuple[str, int, str]],
) -> None:
    """Render the control assessment distribution card.

    Args:
        rows: Ordered ``(label, count, tone)`` tuples.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    items = []
    for label, count, tone in rows:
        resolved = tone if tone in {"success", "warning", "danger", "info", "muted"} else "muted"
        items.append(
            '<div class="ss-assurance-summary-row">'
            f'<span class="ss-assurance-summary-dot ss-tone-{resolved}"></span>'
            f"<span>{html.escape(label)}</span>"
            f"<strong>{int(count)}</strong>"
            "</div>"
        )
    render_html(
        '<section class="ss-stitch-panel ss-assurance-summary">'
        '<div class="ss-assurance-summary__header">'
        "<h3>Control Assurance</h3><span>Human-reviewed outcomes</span>"
        "</div>" + "".join(items) + "</section>"
    )


def render_technical_coverage(
    rows: Sequence[tuple[str, str, str]],
) -> None:
    """Render technical assurance source coverage.

    Args:
        rows: Ordered ``(source, coverage, detail)`` tuples.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    items = []
    for source, coverage, detail in rows:
        items.append(
            '<div class="ss-technical-row">'
            "<div><strong>"
            f"{html.escape(source)}</strong>"
            f"<span>{html.escape(detail)}</span></div>"
            f"<b>{html.escape(coverage)}</b>"
            "</div>"
        )
    render_html(
        '<section class="ss-stitch-panel">'
        '<div class="ss-stitch-panel__heading">'
        "<div><h3>Technical Assurance</h3>"
        "<p>Coverage of evidence-producing technical sources.</p></div>"
        "</div>"
        '<div class="ss-technical-list">' + "".join(items) + "</div></section>"
    )


def render_attention_panel(
    items: Sequence[Mapping[str, Any]],
    *,
    title: str = "Programme Attention",
) -> None:
    """Render a compact decision queue instead of a tall action-button list.

    Args:
        items: Mapping rows containing title, detail, status and tone.
        title: Panel title.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    fragments = []
    for item in items[:4]:
        tone = str(item.get("tone") or "warning")
        if tone not in {"danger", "warning", "info", "neutral"}:
            tone = "neutral"
        fragments.append(
            '<div class="ss-attention-row">'
            '<div class="ss-attention-row__copy">'
            f'<strong>{html.escape(str(item.get("title") or "Action required"))}</strong>'
            f'<span>{html.escape(str(item.get("detail") or ""))}</span>'
            "</div>"
            f'<small class="ss-attention-chip ss-attention-chip--{tone}">'
            f'{html.escape(str(item.get("status") or "Review"))}</small>'
            "</div>"
        )
    if not fragments:
        fragments.append(
            '<div class="ss-attention-empty">No immediate programme action is flagged.</div>'
        )
    render_html(
        '<section class="ss-stitch-panel ss-attention-panel">'
        '<div class="ss-stitch-panel__heading">'
        f"<div><h3>{html.escape(title)}</h3>"
        "<p>Highest-priority items that require a consultant decision.</p></div>"
        "</div>" + "".join(fragments) + "</section>"
    )


def render_severity_bars(counts: Mapping[str, int]) -> None:
    """Render severity distribution as proportion bars.

    Args:
        counts: Severity-count mapping.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    order = ("Critical", "High", "Medium", "Low")
    maximum = max((int(counts.get(label, 0) or 0) for label in order), default=0)
    maximum = max(maximum, 1)
    fragments = []
    for label in order:
        count = int(counts.get(label, 0) or 0)
        percentage = max(0, min(100, round((count / maximum) * 100)))
        fragments.append(
            '<div class="ss-severity-row">'
            '<div class="ss-severity-row__meta">'
            f"<span>{html.escape(label)}</span><strong>{count} findings</strong>"
            "</div>"
            '<div class="ss-severity-track">'
            f'<span class="ss-severity-fill ss-severity-fill--{label.lower()}" '
            f'style="width:{percentage}%"></span>'
            "</div></div>"
        )
    render_html("".join(fragments))


def render_coverage_gaps(
    *,
    unscanned: int,
    unmonitored: int | None,
) -> None:
    """Render in-scope coverage gaps without implying scope exclusion.

    Args:
        unscanned: Number of in-scope inventory assets lacking current scans.
        unmonitored: Number lacking Wazuh monitoring, or ``None`` if unknown.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    monitored_value = "—" if unmonitored is None else str(max(0, int(unmonitored)))
    render_html(
        (
            '<section class="ss-coverage-gap-card"><div '
            'class="ss-coverage-gap-card__header"><h3>Coverage '
            "Gaps</h3><p>Inventory assets awaiting scan or "
            "monitoring coverage.</p></div><div "
            'class="ss-coverage-gap-grid"><div><strong>'
            f"{max(0, int(unscanned))}"
            "</strong><span>Unscanned "
            "assets</span></div><div><strong>"
            f"{html.escape(monitored_value)}"
            "</strong><span>Monitoring unverified "
            "endpoints</span></div></div></section>"
        )
    )


def render_programme_workflow(active_step: str) -> None:
    """Render Discover → Suggest → Review → Approve workflow state.

    Args:
        active_step: Current step label, case-insensitive.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    steps = ("Discover", "Suggest", "Review", "Approve")
    normalized = str(active_step or "Discover").strip().casefold()
    try:
        active_index = [step.casefold() for step in steps].index(normalized)
    except ValueError:
        active_index = 0
    fragments = []
    for index, step in enumerate(steps):
        if index < active_index:
            state = "complete"
        elif index == active_index:
            state = "active"
        else:
            state = "pending"
        fragments.append(
            '<div class="ss-programme-step '
            f'ss-programme-step--{state}">'
            f"<span>{index + 1}</span><strong>{html.escape(step)}</strong>"
            "</div>"
        )
    render_html('<section class="ss-programme-workflow">' + "".join(fragments) + "</section>")


def render_foundation_review_cards(
    items: Sequence[Mapping[str, Any]],
) -> None:
    """Render foundation areas that are ready for review.

    Args:
        items: Mapping rows with title, description, state and detail.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    cards = []
    for item in items:
        detail_text = str(item.get("detail") or "Open the formal register to review.")
        cards.append(
            '<article class="ss-foundation-review-card">'
            '<div class="ss-foundation-review-card__top">'
            f'<h3>{html.escape(str(item.get("title") or "Review item"))}</h3>'
            "<span>Review pending</span>"
            "</div>"
            f'<p>{html.escape(str(item.get("description") or ""))}</p>'
            f"<small>{html.escape(detail_text)}</small>"
            "</article>"
        )
    render_html('<div class="ss-foundation-review-grid">' + "".join(cards) + "</div>")


def render_attention_actions(items, *, key, descriptions=None):
    """Render compact action rows with optional explanatory copy.

    Args:
        items: Existing category/count pairs.
        key: Unique widget namespace.
        descriptions: Optional category-to-description mapping.
    Returns:
        Selected category label, or None when no action was clicked.
    Raises:
        No exceptions are raised for valid category/count pairs.
    """
    selected = None
    with st.container(key="attention_actions_" + key):
        for index, (label, count) in sorted(enumerate(items), key=lambda pair: -pair[1][1]):
            with st.container(key=f"attention_row_{key}_{index}"):
                copy, number, action = st.columns([7, 1, 1], vertical_alignment="center")
                with copy:
                    if count:
                        st.markdown("**" + label + "**")
                    else:
                        st.caption(label)
                    if descriptions and descriptions.get(label):
                        st.caption(descriptions[label])
                with number:
                    st.markdown(
                        f"**{count}**" if count else "<span class='ss-muted'>0</span>",
                        unsafe_allow_html=True,
                    )
                if count and action.button("View", key=f"{key}::{index}", help=f"View {label}"):
                    selected = label
    return selected


def apply_assurance_design() -> None:
    """Load the scoped assurance presentation shared by the four workspaces.

    Returns:
        None.
    Raises:
        OSError: If the packaged stylesheet cannot be read.
    """
    stylesheet = Path(__file__).parents[1] / "styles" / "assurance_redesign.css"
    st.html("<style>" + stylesheet.read_text(encoding="utf-8") + "</style>")


def render_assurance_summary(items: Sequence[tuple[str, Any, str]]) -> None:
    """Present resolved values without recalculating business state.

    Args:
        items: Label, value and explanatory detail triples.
    Returns:
        None.
    Raises:
        No exceptions are raised for valid presentation triples.
    """
    cards = []
    for label, value, detail in items:
        cards.append(
            '<article class="ss-assurance-summary-card">'
            f"<span>{html.escape(str(label))}</span>"
            f"<strong>{html.escape(str(value))}</strong>"
            f"<small>{html.escape(str(detail))}</small></article>"
        )
    render_html('<div class="ss-assurance-summary-grid">' + "".join(cards) + "</div>")
