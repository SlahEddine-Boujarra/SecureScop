"""Locate the actual shared stylesheets for existing presentation contracts."""

from pathlib import Path


def read_theme_source() -> str:
    """Return the authoritative token and style sources.

    Returns:
        CSS text in production load order.
    Raises:
        OSError: If a required stylesheet is absent.
    """
    root = Path(__file__).resolve().parents[1] / "src/securescope/ui/styles"
    return "\n".join(
        (root / name).read_text(encoding="utf-8")
        for name in ("tokens.css", "legacy.css", "components.css", "sidebar.css")
    )
