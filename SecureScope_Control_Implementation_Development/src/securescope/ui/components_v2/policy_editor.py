"""Isolated Components v2 structured policy editor."""

from pathlib import Path
from typing import Any

import streamlit as st

from securescope.ui.component_styles import component_styles

_EDITOR: Any = None


def policy_editor(blocks: list[dict], *, key: str, read_only: bool, saved: bool = True) -> Any:
    """Render editable document blocks with an atomic save event.

    Args:
        blocks: Validated structured paragraphs.
        key: Policy/version-specific component key.
        read_only: Whether editing must be disabled.
        saved: Whether the initial content is already a persisted version.
    Returns:
        Component result containing an optional save event.
    Raises:
        StreamlitAPIException: If component registration fails.
    """
    global _EDITOR
    if _EDITOR is None:
        root = Path(__file__).parent
        _EDITOR = st.components.v2.component(
            name="securescope_policy_editor",
            html='<article id="policy-editor"></article>',
            css=component_styles("policy_editor.css"),
            js=(root / "policy_editor.js").read_text(encoding="utf-8"),
        )
    return _EDITOR(
        data={"blocks": blocks, "read_only": read_only, "saved": saved},
        key=key,
        on_save_change=lambda: None,
    )
