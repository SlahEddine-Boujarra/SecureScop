"""Consistent register table and empty-state presentation."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

import pandas as pd
import streamlit as st


def _normalize_cell(value: Any) -> Any:
    """Normalize one table value for consultant-facing presentation.

    Args:
        value: Raw dataframe cell value.

    Returns:
        Display-safe value. Empty scalar values become an em dash and booleans
        become ``Yes``/``No`` while dates and numeric values remain sortable.

    Raises:
        No exceptions are raised.
    """

    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        return value if value.strip() else "—"
    if isinstance(value, (date, datetime)):
        return value
    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        return value
    if isinstance(missing, bool) and missing:
        return "—"
    return value


def prepare_register_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy normalized for SecureScope register rendering.

    Args:
        frame: Source dataframe.

    Returns:
        Copy with ambiguous empty values and raw booleans normalized.

    Raises:
        No exceptions are raised.
    """

    if frame.empty:
        return frame.copy()
    prepared = frame.copy()
    for column in prepared.columns:
        prepared[column] = prepared[column].map(_normalize_cell)
    return prepared


def render_register_table(
    frame: pd.DataFrame,
    *,
    empty_title: str,
    empty_message: str,
    key: str | None = None,
    height: int | None = None,
    column_config: dict[str, Any] | None = None,
    title: str | None = None,
    description: str | None = None,
    show_row_count: bool = False,
) -> None:
    """Render a readable register or a purposeful empty state.

    Args:
        frame: Prepared consultant-facing data frame.
        empty_title: Short empty-state heading.
        empty_message: Guidance shown when the register contains no rows.
        key: Optional stable Streamlit element key.
        height: Optional data-frame height.
        column_config: Optional Streamlit column configuration.
        title: Optional register title rendered above the table.
        description: Optional short register purpose or data-source description.
        show_row_count: Show the current number of rows beside the register title.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    if title:
        heading, count = st.columns([4, 1], vertical_alignment="bottom")
        with heading:
            st.markdown(f"### {title}")
            if description:
                st.caption(description)
        with count:
            if show_row_count:
                count_label = "record" if len(frame.index) == 1 else "records"
                st.caption(f"{len(frame.index)} {count_label}")
    elif description:
        st.caption(description)

    if frame.empty:
        with st.container(border=True):
            st.markdown(f"**{empty_title}**")
            st.caption(empty_message)
        return

    prepared = prepare_register_frame(frame)
    dataframe_options: dict[str, Any] = {
        "hide_index": True,
        "width": "stretch",
        "key": key,
        "column_config": column_config,
    }
    # Streamlit >= 1.49 validates ``height`` before rendering and rejects
    # ``None``. Omitting the keyword preserves Streamlit's content-aware
    # default while still allowing an explicit pixel height.
    if height is not None:
        dataframe_options["height"] = height

    st.dataframe(prepared, **dataframe_options)
