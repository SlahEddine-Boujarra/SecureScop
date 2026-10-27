"""Shared escaping boundary for application-owned presentation HTML."""

import html
from typing import Any


def safe_text(value: Any) -> str:
    """Escape text, preserving zero and false values.

    Args:
        value: Untrusted label, value, or HTML attribute.
    Returns:
        HTML-escaped text; missing values use an em dash.
    Raises:
        No exceptions are raised for ordinary stringable values.
    """
    if value is None:
        text = "—"
    elif isinstance(value, str):
        text = value or "—"
    else:
        text = str(value)
    return html.escape(text, quote=True)
