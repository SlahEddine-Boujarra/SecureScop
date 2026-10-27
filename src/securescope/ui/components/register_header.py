"""Reusable heading for decision-oriented registers."""

from __future__ import annotations

import streamlit as st


def render_register_header(
    title: str,
    description: str,
    *,
    row_count: int | None = None,
    action_label: str | None = None,
    action_icon: str = ":material/add:",
    action_type: str = "secondary",
    action_key: str | None = None,
) -> bool:
    """Render a register title, purpose, count, and at most one local action.

    Args:
        title: Register title.
        description: Concise explanation of what the register is for.
        row_count: Optional number of visible records.
        action_label: Optional local action label.
        action_icon: Streamlit Material icon for the action.
        action_type: Streamlit button type, normally ``primary`` or ``secondary``.
        action_key: Stable widget key.

    Returns:
        ``True`` when the optional action is clicked.

    Raises:
        No exceptions are raised.
    """

    copy, action = st.columns([4, 1], gap="medium", vertical_alignment="center")
    with copy:
        st.markdown(f"### {title}")
        meta = description
        if row_count is not None:
            label = "record" if row_count == 1 else "records"
            meta = f"{description} · {row_count} {label}"
        st.caption(meta)
    if not action_label:
        return False
    with action:
        return st.button(
            action_label,
            icon=action_icon,
            type=action_type,
            width="stretch",
            key=action_key,
        )
