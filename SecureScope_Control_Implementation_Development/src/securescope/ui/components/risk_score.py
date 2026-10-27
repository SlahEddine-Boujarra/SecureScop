"""Shared risk-score colors for tables and detail cards."""

from securescope.grc.risk_register import risk_level
from securescope.ui.components.primitives import metric_card
from securescope.ui.design_system.tokens import DESIGN_TOKENS


def score_style(value) -> str:
    """Return allowlisted CSS colors for a score; missing scores remain neutral.

    Args:
        value: Numeric 1–25 score or missing value.
    Returns:
        CSS foreground and weight declarations.
    Raises:
        No exceptions are raised.
    """
    level = risk_level(value)
    color = {
        "Low": DESIGN_TOKENS.success,
        "Medium": DESIGN_TOKENS.warning,
        "High": DESIGN_TOKENS.danger,
        "Critical": DESIGN_TOKENS.danger,
    }.get(level, DESIGN_TOKENS.muted)
    return f"color: {color}; font-weight: 700;"


def score_card(label: str, value, *, verified: bool = True) -> None:
    """Render the same risk scale in an escaped detail metric.

    Args:
        label: Metric title.
        value: Numeric score or missing value.
        verified: Whether the displayed residual measurement was verified.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    level = risk_level(value)
    tone = {"Low": "success", "Medium": "warning", "High": "danger", "Critical": "danger"}.get(
        level, "neutral"
    )
    metric_card(
        label,
        "Not assessed" if level == "Not assessed" else value,
        level + (" · Proposed, unverified" if not verified else ""),
        tone=tone,
    )
