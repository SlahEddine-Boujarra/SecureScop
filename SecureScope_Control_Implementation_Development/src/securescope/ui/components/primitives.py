"""Escaped presentation components shared by every workspace."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pandas as pd
import streamlit as st

from securescope.core.presentation import safe_text
from securescope.ui.components.html_renderer import render_html


def status_tone(label: str) -> str:
    """Classify status urgency without treating waiting states as warnings.

    Args:
        label: Status or severity label.
    Returns:
        Allowlisted semantic tone.
    Raises:
        No exceptions are raised.
    """
    value = str(label).strip().casefold()
    if value in {"critical", "high", "failed", "error", "overdue", "blocked"}:
        return "danger"
    if value in {
        "review pending",
        "pending review",
        "needs attention",
        "connection issue",
        "configured — not verified",
        "medium",
        "in review",
        "needs update",
        "needs review",
        "changes requested",
        "partially implemented",
    }:
        return "warning"
    if value in {"managed", "completed", "verified", "monitored", "approved", "ready", "connected"}:
        return "success"
    if value in {"in progress", "submitted for review", "reviewed"}:
        return "info"
    return "neutral"


def metric_card(
    title: str, value: Any, subtitle: str = "", tone: str = "neutral", *, compact: bool = False
) -> None:
    """Render a single, escaped metric or asset property.

    Args:
        title: Metric label.
        value: Display value, including zero.
        subtitle: Explanation of the measurement.
        tone: Semantic tone or legacy tone alias.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    aliases = {
        "ready": "success",
        "mint": "success",
        "risk": "warning",
        "medium": "warning",
        "peach": "warning",
        "critical": "danger",
        "high": "danger",
        "blue": "neutral",
        "lilac": "neutral",
    }
    tone = aliases.get(tone, tone)
    tone = tone if tone in {"neutral", "info", "success", "warning", "danger"} else "neutral"
    render_html(
        f'<article class="ss-metric{" ss-metric--compact" if compact else ""}" '
        f'data-zero="{str(value in (0, "0", "0%")).lower()}" data-tone="{safe_text(tone)}">'
        f'<div class="ss-metric__label">{safe_text(title)}</div>'
        f'<div class="ss-metric__value">{safe_text(value)}</div>'
        f'<div class="ss-metric__detail">{safe_text(subtitle) if subtitle else ""}</div>'
        "</article>"
    )


def panel_heading(title: str, subtitle: str = "") -> None:
    """Render an escaped panel heading and optional explanation.

    Args:
        title: Section title.
        subtitle: Supporting text.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    render_html(
        f'<header class="ss-panel-heading"><h3>{safe_text(title)}</h3>'
        f'<p>{safe_text(subtitle) if subtitle else ""}</p></header>'
    )


def empty_state(
    title: str,
    detail: str,
    *,
    action: str = "",
    key: str = "",
    on_action: Callable[[], None] | None = None,
    kind: str = "empty",
) -> None:
    """Render a consistent empty, loading, or error state with an optional action.

    Args:
        title: Short state label.
        detail: Explanation and next step.
        action: Optional native button text.
        key: Stable action key.
        on_action: Optional action callback.
        kind: Empty, loading, or error state.
    Returns:
        None.
    Raises:
        Callback and Streamlit rendering errors propagate.
    """
    kind = kind if kind in {"empty", "loading", "error"} else "empty"
    icon = {"empty": "○", "loading": "…", "error": "!"}[kind]
    role = "alert" if kind == "error" else "status"
    render_html(
        f'<section class="ss-state" data-kind="{safe_text(kind)}" role="{safe_text(role)}">'
        f'<span class="ss-state__icon" aria-hidden="true">{safe_text(icon)}</span>'
        f"<h3>{safe_text(title)}</h3><p>{safe_text(detail)}</p></section>"
    )
    if action and on_action:
        st.button(action, key=key, on_click=on_action)


def status_pill(label: str) -> str:
    """Return trusted pill markup with an escaped untrusted label.

    Args:
        label: State label to display.
    Returns:
        Escaped HTML for composition with other trusted markup.
    Raises:
        No exceptions are raised.
    """
    from securescope.grc.status_labels import status_label

    label = status_label(label)
    return (
        f'<span class="ss-status" data-tone="{safe_text(status_tone(label))}">'
        f"{safe_text(label)}</span>"
    )


def readable_table(
    data: pd.DataFrame | Sequence[Mapping[str, Any]],
    *,
    key: str,
    column_config: Mapping[str, Any] | None = None,
    height: int = 420,
) -> None:
    """Offer a paged reading view with wrapping and per-cell native tooltips.

    Args:
        data: Table rows or a DataFrame.
        key: Workspace-scoped widget key prefix.
        column_config: Native dataframe column definitions.
        height: Height of the optional native table.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    frame = data if isinstance(data, pd.DataFrame) else pd.DataFrame(data)
    if frame.empty:
        empty_state("No records to display", "Adjust the filters or add records to this workspace.")
        return
    if len(frame) >= 5:
        with st.popover("Search, sort and columns"):
            query = st.text_input("Search all values", key=f"{key}::query").strip()
            columns = st.multiselect(
                "Visible columns",
                list(frame.columns),
                default=list(frame.columns),
                key=f"{key}::columns",
            )
            sort = st.selectbox(
                "Sort column",
                [None, *frame.columns],
                format_func=lambda value: "Original order" if value is None else str(value),
                key=f"{key}::sort",
            )
            descending = st.checkbox("Descending order", key=f"{key}::descending")
        if query:
            matches = (
                frame.astype(str)
                .apply(lambda column: column.str.contains(query, case=False, regex=False))
                .any(axis=1)
            )
            frame = frame.loc[matches]
        if sort is not None:
            frame = frame.sort_values(
                sort,
                ascending=not descending,
                key=lambda column: (
                    column
                    if pd.api.types.is_numeric_dtype(column)
                    else column.astype(str).str.casefold()
                ),
            )
        if columns:
            frame = frame[columns]
        if frame.empty:
            empty_state("No matching records", "Change or clear the search to see saved records.")
            return
    if not st.toggle("Wrap long text", value=True, key=f"{key}::wrap"):
        st.dataframe(
            frame, width="stretch", hide_index=True, height=height, column_config=column_config
        )
        return
    pages = max(1, (len(frame) + 24) // 25)
    page = st.selectbox("Table page", range(1, pages + 1), key=f"{key}::page") if pages > 1 else 1
    shown = frame.iloc[(page - 1) * 25 : page * 25]
    headers = "".join(f'<th scope="col">{safe_text(col)}</th>' for col in frame.columns)
    body = []
    for values in shown.itertuples(index=False, name=None):
        cells = []
        for col, value in zip(frame.columns, values):
            label = "—" if value is None else str(value)
            content = (
                status_pill(label)
                if str(col).lower()
                in {"lifecycle", "status", "monitoring_status", "confirmation", "criticality"}
                else safe_text(label)
            )
            cells.append(f'<td title="{safe_text(label)}">{content}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    render_html(
        '<div class="ss-reading-table" tabindex="0" role="region" '
        'aria-label="Records with wrapped text"><table><thead><tr>'
        + headers
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )
    st.caption(f"{len(frame)} records · showing {(page - 1) * 25 + 1}–{min(page * 25, len(frame))}")


def identity_context(actor: str, role: str) -> None:
    """Display the existing identity without turning an email into a mail link."""
    render_html(
        '<div class="ss-identity"><span>'
        + safe_text(actor)
        + '</span><span class="ss-identity__role">'
        + safe_text(role)
        + "</span></div>"
    )
