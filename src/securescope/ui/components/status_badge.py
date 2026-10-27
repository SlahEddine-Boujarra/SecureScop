"""Accessible status-badge rendering helpers."""

from __future__ import annotations

import html

from securescope.ui.components.html_renderer import render_html


def render_status_badge(
    label: str,
    *,
    tone: str = "neutral",
    icon: str = "circle",
) -> None:
    """Render a text-and-icon status badge.

    Args:
        label: Human-readable status text.
        tone: Visual tone: neutral, success, warning, danger, or info.
        icon: Material Symbol name shown alongside the text.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    allowed_tones = {"neutral", "success", "warning", "danger", "info"}
    resolved_tone = tone if tone in allowed_tones else "neutral"
    render_html(
        (
            f'<span class="ss-status-badge ss-status-{resolved_tone}">'
            f'<span class="material-symbols-rounded" aria-hidden="true">'
            f"{html.escape(icon)}</span>"
            f"{html.escape(str(label))}</span>"
        )
    )
