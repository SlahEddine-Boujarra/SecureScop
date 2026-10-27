"""Presentation-only integration readiness; never connects or changes configuration."""

from html import escape
from urllib.parse import urlparse

import streamlit as st

from securescope.ui.components.primitives import status_pill


def configured_value(value: object, *, url: bool = False) -> bool:
    """Exclude absent/sample values from readiness without exposing credentials."""
    text = str(value or "").strip()
    normalized = text.casefold().replace("-", "_").replace(" ", "_")
    if (
        not text
        or any(
            marker in normalized
            for marker in (
                "change_me",
                "changeme",
                "replace_me",
                "your_password",
                "your_secret",
            )
        )
        or normalized
        in {"password", "secret", "example", "sample", "todo", "<secret>", "<password>"}
    ):
        return False
    if url:
        try:
            parsed = urlparse(text)
            host = (parsed.hostname or "").lower()
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if host in {
            "example.com",
            "example.org",
            "example.net",
            "your_wazuh_host",
            "your-wazuh-host",
        }:
            return False
        if host.endswith((".example", ".example.com", ".example.org", ".example.net", ".invalid")):
            return False
    return True


def api_configuration_status(url: str, user: str, secret: str) -> str:
    """Configuration alone can never claim a verified connection."""
    return (
        "Configured — Not verified"
        if configured_value(url, url=True) and configured_value(user) and configured_value(secret)
        else "Needs setup"
    )


def integration_summary(name: str, status: str, context: str) -> None:
    """Reuse the shared status component for essential, escaped integration context."""
    st.html(
        '<section class="ss-integration-summary"><div><strong>'
        + escape(name)
        + "</strong>"
        + status_pill(status)
        + "</div><p>"
        + escape(context)
        + "</p></section>"
    )
