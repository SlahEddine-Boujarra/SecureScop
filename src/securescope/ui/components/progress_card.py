"""ISO programme progress-card components."""

from __future__ import annotations

from collections.abc import Sequence

import streamlit as st

from securescope.core.presentation import safe_text
from securescope.grc.program_progress_service import (
    ProgramProgressSnapshot,
    ProgressDimension,
)
from securescope.ui.components.html_renderer import render_html


def render_program_progress_card(
    snapshot: ProgramProgressSnapshot,
    *,
    engagement_name: str,
    scope_name: str,
) -> None:
    """Render a prominent, non-certification ISO programme progress card.

    Args:
        snapshot: Deterministic programme progress snapshot.
        engagement_name: Active engagement display name.
        scope_name: Active scope display name.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    render_html(
        (
            '\n        <section class="ss-foundation-card" '
            'aria-label="ISO 27001 programme progress">\n            <div '
            'class="ss-foundation-card__copy">\n                <span '
            'class="ss-eyebrow">ISO/IEC 27001:2022</span>\n               '
            " <h2>"
            f"{safe_text(engagement_name)}"
            "</h2>\n                "
            "<p>"
            f"{safe_text(scope_name)}"
            " · "
            f"{safe_text(snapshot.readiness)}"
            "</p>\n                <div "
            'class="ss-foundation-progress-header"><span>programme '
            "foundation</span>\n                    "
            "<strong>"
            f"{safe_text(snapshot.percentage)}"
            "%</strong></div>\n                <div "
            'class="ss-foundation-progress-track" role="progressbar"\n    '
            '                 aria-valuemin="0" aria-valuemax="100"\n     '
            '                aria-valuenow="'
            f"{snapshot.percentage}"
            '">\n                    <span '
            'class="ss-foundation-progress-fill" style="width: '
            f"{max(0, min(100, snapshot.percentage))}"
            '%"></span>\n                </div>\n                <div '
            'class="ss-foundation-progress-meta">\n                    '
            "<strong>"
            f"{snapshot.completed}"
            " of "
            f"{snapshot.total}"
            "</strong>\n                    <span>required foundation "
            "items complete</span>\n                </div>\n            "
            "</div>\n            <small>Not a compliance or certification "
            "score</small>\n        </section>\n        "
        )
    )


def render_dimension_grid(dimensions: Sequence[ProgressDimension]) -> None:
    """Render programme dimensions with explicit measurement states.

    Args:
        dimensions: Ordered programme dimensions.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    columns = st.columns(min(len(dimensions), 5), gap="small")
    for column, dimension in zip(columns, dimensions):
        percentage = dimension.percentage
        value = f"{percentage}%" if percentage is not None else "—"
        state_class = "measured" if percentage is not None else "unmeasured"
        with column:
            render_html(
                f"""
                <div class="ss-dimension-card ss-dimension-{state_class}">
                    <small>{safe_text(dimension.label)}</small>
                    <strong>{value}</strong>
                    <span>{safe_text(dimension.status)}</span>
                </div>
                """
            )
