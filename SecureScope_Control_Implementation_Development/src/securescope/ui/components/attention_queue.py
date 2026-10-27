"""Clickable programme attention queue."""

from __future__ import annotations

from collections.abc import Callable, Sequence

import streamlit as st

from securescope.grc.program_progress_service import AttentionItem


def render_attention_queue(
    items: Sequence[AttentionItem],
    *,
    on_open: Callable[[str], None],
    key_prefix: str,
) -> None:
    """Render priorities that route directly to their resolving section.

    Args:
        items: Ordered attention items.
        on_open: Callback accepting a Programme Setup section key.
        key_prefix: Stable widget-key prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    st.markdown("### Needs attention")
    if not items:
        st.success("No foundation actions require attention.")
        return
    with st.container(border=True):
        for index, item in enumerate(items[:6]):
            label = f"{item.count} · {item.label}" if item.count > 1 else item.label
            st.button(
                label,
                icon=(
                    ":material/error:" if item.severity == "Overdue" else ":material/arrow_forward:"
                ),
                type="secondary",
                width="stretch",
                key=f"{key_prefix}_{index}_{item.section}",
                on_click=on_open,
                args=(item.section,),
            )
        if len(items) > 6:
            st.caption(f"{len(items) - 6} additional setup actions are available.")
