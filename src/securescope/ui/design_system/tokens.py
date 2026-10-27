"""Canonical SecureScope Stitch design tokens.

The values in this module are presentation-only. Keeping them in one location
prevents page-specific CSS drift and makes a future React client consume the
same visual language without changing application services.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecureScopeDesignTokens:
    """Store canonical colors, geometry and spacing values.

    Attributes:
        primary: Primary SecureScope teal.
        primary_dark: Darker teal for hover/focus contrast.
        navy: Assurance/emphasis navy.
        background: Main application canvas.
        surface: Primary card/work surface.
        surface_subtle: Secondary neutral surface.
        border: Standard low-contrast outline.
        text: Main text color.
        muted: Secondary text color.
        success: Positive semantic color.
        warning: Warning semantic color.
        danger: Critical/error semantic color.
        info: Informational semantic color.
        card_radius_px: Standard card corner radius.
        control_radius_px: Standard input/button radius.
        gutter_px: Desktop grid gutter.
    """

    primary: str = "#00685f"
    primary_dark: str = "#005049"
    navy: str = "#0f172a"
    background: str = "#f8f9ff"
    surface: str = "#ffffff"
    surface_subtle: str = "#f8fafc"
    border: str = "#e2e8f0"
    border_strong: str = "#cbd5e1"
    text: str = "#0b1c30"
    muted: str = "#667085"
    success: str = "#067647"
    warning: str = "#b54708"
    danger: str = "#b42318"
    info: str = "#175cd3"
    card_radius_px: int = 10
    control_radius_px: int = 6
    gutter_px: int = 24


DESIGN_TOKENS = SecureScopeDesignTokens()


def css_variables() -> str:
    """Return the canonical design tokens as CSS custom properties.

    Returns:
        CSS variable declarations without a surrounding selector.

    Raises:
        No exceptions are raised.
    """

    token = DESIGN_TOKENS
    return "\n".join(
        (
            (
                '--ss-font-sans: Inter, "Segoe UI Variable Text", "Segoe UI '
                'Variable", "Segoe UI", system-ui, sans-serif;'
            ),
            f"--ss-primary: {token.primary};",
            f"--ss-primary-dark: {token.primary_dark};",
            f"--ss-navy: {token.navy};",
            f"--ss-background: {token.background};",
            f"--ss-surface: {token.surface};",
            f"--ss-surface-subtle: {token.surface_subtle};",
            f"--ss-border: {token.border};",
            f"--ss-border-strong: {token.border_strong};",
            f"--ss-text: {token.text};",
            f"--ss-muted: {token.muted};",
            f"--ss-success: {token.success};",
            f"--ss-warning: {token.warning};",
            f"--ss-danger: {token.danger};",
            f"--ss-info: {token.info};",
            f"--ss-card-radius: {token.card_radius_px}px;",
            f"--ss-control-radius: {token.control_radius_px}px;",
            f"--ss-gutter: {token.gutter_px}px;",
        )
    )
