"""Safe presentation helpers for scanner and worker output.

The module is intentionally independent from Streamlit and persistence so the
same normalization is applied before output reaches logs, database fields, or
the interface.
"""

from __future__ import annotations

import re
from typing import Any

ANSI_ESCAPE_PATTERN = re.compile(r"(?:\x1B\[[0-?]*[ -/]*[@-~])|(?:\x1B\][^\x07]*(?:\x07|\x1B\\))")
VERSION_PATTERN = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?")
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SGR_FRAGMENT_PATTERN = re.compile(r"(?:\\(?:x1[bB]|u001[bB]))?\[(?:\d{1,3}(?:;\d{1,3})*)?m")
USER_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:[\\/]Users[\\/]|/(?:home|Users)/)[^\r\n\"'<>]+",
    re.IGNORECASE,
)


def strip_ansi_sequences(value: Any) -> str:
    """Remove ANSI/OSC escape sequences and unsafe control characters.

    Args:
        value: Arbitrary scanner or process output.

    Returns:
        Plain Unicode text suitable for logs, persistence, and UI display.

    Raises:
        ValueError: Never raised for normal stringable values.
    """

    text = str(value or "")
    text = ANSI_ESCAPE_PATTERN.sub("", text)
    text = SGR_FRAGMENT_PATTERN.sub("", text)
    return CONTROL_CHARACTER_PATTERN.sub("", text).replace("\r\n", "\n")


def display_tool_output(value: Any, limit: int = 2000) -> str:
    """Sanitize tool output and hide user-profile filesystem paths for display.

    Args:
        value: Tool output or an exception message.
        limit: Maximum display length.
    Returns:
        Plain text without terminal styling or a local user's home path.
    Raises:
        ValueError: If the length limit is not positive.
    """
    return USER_PATH_PATTERN.sub("[local path]", concise_output(value, limit))


def concise_output(value: Any, limit: int = 1000) -> str:
    """Return bounded, whitespace-normalized scanner output.

    Args:
        value: Scanner or worker output.
        limit: Maximum number of characters to return.

    Returns:
        Sanitized output no longer than ``limit`` characters.

    Raises:
        ValueError: If ``limit`` is not positive.
    """

    if int(limit) <= 0:
        raise ValueError("Output limit must be positive.")
    cleaned = strip_ansi_sequences(value).strip()
    return cleaned[: int(limit)]


def extract_semantic_version(value: Any, fallback: str = "Not reported") -> str:
    """Extract one clean semantic version from noisy command output.

    Args:
        value: Output containing a version.
        fallback: Label used when no semantic version exists.

    Returns:
        Version prefixed with ``v`` or ``fallback``.

    Raises:
        ValueError: If ``fallback`` is empty.
    """

    if not str(fallback).strip():
        raise ValueError("Version fallback cannot be empty.")
    match = VERSION_PATTERN.search(strip_ansi_sequences(value))
    if not match:
        return str(fallback)
    version = match.group(0)
    return version if version.startswith("v") else f"v{version}"


def human_duration(seconds: Any) -> str:
    """Format an elapsed duration without exposing raw heartbeat seconds.

    Args:
        seconds: Elapsed seconds or a value coercible to an integer.

    Returns:
        Human-friendly duration such as ``12 seconds`` or ``3 minutes``.

    Raises:
        ValueError: Never raised; invalid values return ``Not reported``.
    """

    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "Not reported"
    if total < 60:
        return f"{total} second" + ("" if total == 1 else "s")
    if total < 3600:
        minutes = total // 60
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    hours = total // 3600
    minutes = (total % 3600) // 60
    suffix = f" {minutes} min" if minutes else ""
    return f"{hours} hour" + ("" if hours == 1 else "s") + suffix
