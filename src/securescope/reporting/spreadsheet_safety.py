"""One untrusted-text boundary for CSV and workbook exports."""

from typing import Any

from securescope.core.output_sanitizer import strip_ansi_sequences


def spreadsheet_text(value: Any) -> str:
    """Neutralize formula-like user text while preserving intentional app formulas.

    This helper is only for text inputs. Trusted generated formulas are written
    explicitly by the report builder; numeric inputs stay numeric.

    Args:
        value: An untrusted free-text input.
    Returns:
        Plain cell text, prefixed with an apostrophe when spreadsheet software
        could otherwise interpret it as a formula (including whitespace prefixes).
    Raises:
        No exceptions are raised for ordinary stringable inputs.
    """
    text = strip_ansi_sequences("" if value is None else str(value))
    probe = text.lstrip(" \t\r\n\ufeff\u200b")
    if probe.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
