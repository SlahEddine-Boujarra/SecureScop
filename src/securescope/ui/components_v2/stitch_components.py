"""Native Streamlit Components v2 for the SecureScope Stitch interface.

The component definitions contain only trusted application-owned HTML, CSS and
JavaScript. Dynamic values are passed through Streamlit's structured ``data``
channel and inserted with ``textContent`` rather than raw ``innerHTML``. This
keeps database/user-provided labels from becoming executable markup.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.component_styles import component_styles

_METRIC_COMPONENT: Any | None = None
_JOURNEY_COMPONENT: Any | None = None
_TABLE_COMPONENT: Any | None = None


def components_v2_available() -> bool:
    """Return whether this Streamlit runtime exposes Components v2.

    Returns:
        ``True`` when ``st.components.v2.component`` is available.

    Raises:
        No exceptions are raised.
    """

    components = getattr(st, "components", None)
    v2 = getattr(components, "v2", None)
    return callable(getattr(v2, "component", None))


def _metric_component() -> Any | None:
    """Return the lazily registered metric grid component.

    Returns:
        Component renderer, or ``None`` on runtimes without Components v2.

    Raises:
        StreamlitAPIException: If Streamlit rejects trusted component metadata.
    """
    global _METRIC_COMPONENT
    if not components_v2_available():
        return None
    if _METRIC_COMPONENT is None:
        _METRIC_COMPONENT = st.components.v2.component(
            name="securescope_metric_grid",
            html='<section class="ss-kpi-grid" id="ss-kpi-grid"></section>',
            css=(
                "\n                .ss-kpi-grid { display:grid; "
                "grid-template-columns:repeat(4,minmax(0,1fr)); "
                "gap:var(--ss-space-4); width:100%; "
                "font-family:var(--ss-font-sans); }\n                .ss-kpi "
                "{ min-height:126px; padding:var(--ss-space-5); "
                "box-sizing:border-box; border:1px solid var(--ss-border); "
                "border-left:4px solid var(--ss-navy); "
                "border-radius:var(--ss-radius-md); "
                "background:var(--ss-surface); "
                "box-shadow:var(--ss-shadow-sm); display:flex; "
                "flex-direction:column; justify-content:space-between; }\n    "
                '            .ss-kpi[data-tone="primary"] { '
                "border-left-color:var(--ss-accent); }\n                "
                '.ss-kpi[data-tone="danger"] { '
                "border-left-color:var(--ss-danger); }\n                "
                '.ss-kpi[data-tone="warning"] { '
                "border-left-color:var(--ss-warning); }\n                "
                '.ss-kpi[data-tone="info"] { '
                "border-left-color:var(--ss-info); }\n                "
                ".ss-kpi-label { color:var(--ss-text-muted); "
                "font-size:var(--ss-text-xs); "
                "line-height:var(--ss-leading-tight); letter-spacing:.05em; "
                "text-transform:uppercase; font-weight:700; }\n               "
                " .ss-kpi-value { color:var(--ss-text-strong); "
                "font-size:var(--ss-text-2xl); "
                "line-height:var(--ss-leading-display); font-weight:650; "
                "letter-spacing:-.01em; }\n                .ss-kpi-detail { "
                "color:var(--ss-text-muted); font-size:var(--ss-text-sm); "
                "line-height:var(--ss-leading-normal); margin-top:3px; }\n    "
                "            @media (max-width:1050px) { .ss-kpi-grid { "
                "grid-template-columns:repeat(2,minmax(0,1fr)); } }\n         "
                "       @media (max-width:620px) { .ss-kpi-grid { "
                "grid-template-columns:1fr; } }\n            "
            ),
            js="""
                export default function({ data, parentElement }) {
                    const root = parentElement.querySelector('#ss-kpi-grid');
                    if (!root) return;
                    root.replaceChildren();
                    const metrics = Array.isArray(data?.metrics) ? data.metrics : [];
                    for (const metric of metrics) {
                        const card = document.createElement('article');
                        card.className = 'ss-kpi';
                        card.dataset.tone = metric.tone || 'neutral';
                        const label = document.createElement('span');
                        label.className = 'ss-kpi-label';
                        label.textContent = metric.label ?? '';
                        const content = document.createElement('div');
                        const value = document.createElement('div');
                        value.className = 'ss-kpi-value';
                        value.textContent = metric.value ?? '—';
                        content.appendChild(value);
                        if (metric.detail) {
                            const detail = document.createElement('div');
                            detail.className = 'ss-kpi-detail';
                            detail.textContent = metric.detail;
                            content.appendChild(detail);
                        }
                        card.append(label, content);
                        root.appendChild(card);
                    }
                }
            """,
        )
    return _METRIC_COMPONENT


def render_metric_grid_v2(
    metrics: Sequence[Mapping[str, Any]],
    *,
    key: str | None = None,
) -> bool:
    """Render the metric grid through Components v2 when available.

    Args:
        metrics: Structured metric definitions.
        key: Optional stable component key.
    Returns:
        ``True`` when the v2 component rendered, otherwise ``False``.
    Raises:
        Streamlit rendering errors propagate.
    """
    renderer = _metric_component()
    if renderer is None:
        return False
    renderer(data={"metrics": [dict(metric) for metric in metrics]}, key=key)
    return True


def _journey_component() -> Any | None:
    """Return the lazily registered certification-journey component."""

    global _JOURNEY_COMPONENT
    if not components_v2_available():
        return None
    if _JOURNEY_COMPONENT is None:
        _JOURNEY_COMPONENT = st.components.v2.component(
            name="securescope_certification_journey",
            html=(
                '<section class="ss-journey-card">'
                '<div class="ss-journey-copy"><h3>Certification Journey</h3>'
                "<p>Current readiness stage across the ISO/IEC 27001 lifecycle.</p></div>"
                '<div class="ss-journey" id="ss-journey"></div></section>'
            ),
            css="""
                .ss-journey-card {
                    font-family: var(--st-font, Inter, "Segoe UI", sans-serif);
                    padding: 22px 24px 20px;
                    border: 1px solid #e2e8f0;
                    border-radius: 10px;
                    background: #fff;
                    box-shadow: 0 1px 2px rgba(16,24,40,.04);
                }
                .ss-journey-copy h3 {
                    margin: 0;
                    color: #0b1c30;
                    font-size: 20px;
                    line-height: 28px;
                    font-weight: 600;
                }
                .ss-journey-copy p {
                    margin: 3px 0 22px;
                    color: #667085;
                    font-size: 13px;
                }
                .ss-journey {
                    display: grid;
                    grid-template-columns: repeat(6, minmax(0,1fr));
                    gap: 0;
                    position: relative;
                }
                .ss-journey::before {
                    content: '';
                    position: absolute;
                    left: 8%; right: 8%; top: 18px;
                    height: 2px;
                    background: #dbe5ee;
                    z-index: 0;
                }
                .ss-step {
                    position: relative;
                    z-index: 1;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 8px;
                    color: #667085;
                    text-align: center;
                    font-size: 11px;
                    font-weight: 700;
                }
                .ss-dot {
                    width: 36px; height: 36px;
                    border-radius: 999px;
                    border: 2px solid #cbd5e1;
                    background: #eef4ff;
                    display: grid;
                    place-items: center;
                    color: #667085;
                }
                .ss-dot::after {
                    content: ''; width: 8px; height: 8px; border-radius: 999px;
                    background: currentColor;
                }
                .ss-step[data-state="complete"] .ss-dot,
                .ss-step[data-state="active"] .ss-dot {
                    border-color: #00685f;
                    background: #00685f;
                    color: white;
                }
                .ss-step[data-state="active"] .ss-dot { box-shadow: 0 0 0 5px rgba(0,104,95,.14); }
                .ss-step[data-state="active"] { color: #00685f; }
                .ss-step[data-state="blocked"] .ss-dot {
                    border-color: #b42318; color: #b42318; background: #fff1f1;
                }
                @media (max-width: 760px) {
                    .ss-journey { grid-template-columns: repeat(3, 1fr); row-gap: 18px; }
                    .ss-journey::before { display: none; }
                }
            """,
            js="""
                export default function({ data, parentElement }) {
                    const root = parentElement.querySelector('#ss-journey');
                    if (!root) return;
                    root.replaceChildren();
                    const steps = Array.isArray(data?.steps) ? data.steps : [];
                    for (const step of steps) {
                        const node = document.createElement('div');
                        node.className = 'ss-step';
                        node.dataset.state = step.state || 'pending';
                        const dot = document.createElement('div');
                        dot.className = 'ss-dot';
                        const label = document.createElement('strong');
                        label.textContent = step.label ?? '';
                        node.append(dot, label);
                        root.appendChild(node);
                    }
                }
            """,
        )
    return _JOURNEY_COMPONENT


def render_journey_v2(
    steps: Sequence[Mapping[str, Any]],
    *,
    key: str | None = None,
) -> bool:
    """Render the ISO certification journey using Components v2.

    Args:
        steps: Ordered mappings containing ``label`` and ``state``.
        key: Optional stable Streamlit key.

    Returns:
        ``True`` when the v2 renderer is available and mounted.
    """

    renderer = _journey_component()
    if renderer is None:
        return False
    renderer(data={"steps": [dict(step) for step in steps]}, key=key)
    return True


def _table_component() -> Any | None:
    """Load packaged assets and return the lazily registered table component.

    Returns:
        A Streamlit component renderer, or None on an unsupported runtime.

    Raises:
        OSError: If a packaged table asset is missing or unreadable.
        StreamlitAPIException: If component registration fails.
    """

    global _TABLE_COMPONENT
    if not components_v2_available():
        return None
    if _TABLE_COMPONENT is None:
        _TABLE_COMPONENT = st.components.v2.component(
            name="securescope_enterprise_table",
            html="""
                <section class="ss-table-shell">
                    <div class="ss-table-toolbar">
                        <div>
                            <strong id="ss-table-title"></strong>
                            <span id="ss-table-count" role="status" aria-live="polite"></span>
                        </div>
                        <div class="ss-table-actions">
                            <label class="ss-table-search">
                                <span>Search</span><input id="ss-table-query" type="search" />
                            </label>
                            <button id="ss-clear" type="button">Clear</button>
                            <button id="ss-export" type="button">Export CSV</button>
                        </div>
                    </div>
                    <div class="ss-table-scroll">
                        <table aria-label="Control profiles">
                            <thead id="ss-table-head"></thead><tbody id="ss-table-body"></tbody>
                        </table>
                    </div>
                    <div class="ss-table-footer">
                        <button id="ss-prev" type="button">Previous</button>
                        <span id="ss-page"></span>
                        <button id="ss-next" type="button">Next</button>
                    </div>
                </section>
            """,
            css=component_styles("table.css"),
            js=Path(__file__).with_name("table.js").read_text(encoding="utf-8"),
        )
    return _TABLE_COMPONENT


def render_enterprise_table_v2(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[Mapping[str, str]],
    *,
    title: str,
    key: str,
    page_size: int = 15,
    on_selected_row_change: Any | None = None,
) -> Any | None:
    """Render a searchable, sortable table with stable row selection and CSV export.

    Args:
        rows: JSON-serializable row mappings.
        columns: Column definitions with ``key``, ``label`` and optional ``kind``.
        title: Table toolbar title.
        key: Stable Streamlit component key.
        page_size: Number of visible rows per client-side page, from 1 to 200.
        on_selected_row_change: Optional Streamlit callback for row selection.

    Returns:
        Components v2 result object, or ``None`` on unsupported runtimes.

    Raises:
        ValueError: If page_size is out of range or row identities are duplicated.
        Streamlit component errors may propagate on supported runtimes.
    """

    renderer = _table_component()
    if renderer is None:
        return None
    if not 1 <= page_size <= 200:
        raise ValueError("Table page_size must be between 1 and 200.")
    prepared_rows = []
    identities: set[str] = set()
    for index, row in enumerate(rows):
        prepared = dict(row)
        row_id = str(prepared.get("__row_id", prepared.get("id", f"row:{index}")))
        if row_id in identities:
            raise ValueError(f"Duplicate table row identity: {row_id}")
        identities.add(row_id)
        prepared["__row_id"] = row_id
        prepared_rows.append(prepared)
    kwargs: dict[str, Any] = {
        "data": {
            "rows": prepared_rows,
            "columns": [dict(column) for column in columns],
            "title": title,
            "page_size": int(page_size),
        },
        "key": key,
    }
    kwargs["on_selected_row_change"] = (
        on_selected_row_change if on_selected_row_change is not None else (lambda: None)
    )
    return renderer(**kwargs)
