"""Modern Streamlit page registry for SecureScope.

SecureScope keeps its custom Stitch sidebar, but delegates route ownership and
URL state to ``st.Page`` / ``st.navigation``. This removes the previous pattern
where a session-state string was the router and allows contextual drill-downs to
use stable Streamlit routes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import streamlit as st


@dataclass(frozen=True)
class PageSpec:
    """Describe one Streamlit route.

    Attributes:
        key: Stable legacy/navigation key used by existing callbacks.
        title: Human-readable browser/page title.
        url_path: Stable path segment managed by Streamlit.
        default: Whether the route is the application root.
        hidden: Whether it is omitted from the custom primary navigation.
    """

    key: str
    title: str
    url_path: str
    default: bool = False
    hidden: bool = False


PAGE_SPECS: tuple[PageSpec, ...] = (
    PageSpec("ISO Command Center", "Command Center", "command-center", default=True),
    PageSpec("Overview", "Exposure Overview", "exposure-overview"),
    PageSpec("Programme Setup", "Programme Foundation", "programme-foundation"),
    PageSpec("Gap Assessment", "Control Assurance", "control-assurance"),
    PageSpec("Risk", "Risk", "risk"),
    PageSpec("Calendar", "Calendar", "calendar"),
    PageSpec("Policies", "Policies", "policies"),
    PageSpec("2 · Asset Management", "Asset Management", "asset-management"),
    PageSpec("3 · Scan Center", "Scan Center", "scan-center"),
    PageSpec("4 · Reports & Findings", "Vulnerabilities", "vulnerabilities"),
    PageSpec("5 · SIEM & Wazuh", "SIEM", "siem"),
    PageSpec("Remediation", "Remediation", "remediation"),
    PageSpec("Client History", "Reports & Audit", "reports-audit"),
    PageSpec("Client Workspace", "Client Workspace", "client-workspace"),
    PageSpec("1 · Asset Discovery", "Asset Discovery", "asset-discovery", hidden=True),
    PageSpec(
        "6 · ISO 27001 Assessment",
        "Technical Assurance",
        "technical-assurance",
        hidden=True,
    ),
    PageSpec("ISO Evidence Hub", "Evidence Hub", "evidence-hub", hidden=True),
)


def build_page_registry(
    renderers: Mapping[str, Callable[[], None]],
) -> dict[str, Any]:
    """Create ``st.Page`` objects for all SecureScope routes.

    Args:
        renderers: Mapping from ``PageSpec.key`` to zero-argument renderers.

    Returns:
        Mapping of stable navigation keys to Streamlit ``Page`` objects.

    Raises:
        KeyError: If a required route renderer is missing.
    """

    pages: dict[str, Any] = {}
    for spec in PAGE_SPECS:
        renderer = renderers[spec.key]
        pages[spec.key] = st.Page(
            renderer,
            title=spec.title,
            url_path=spec.url_path,
            default=spec.default,
            visibility="hidden",
        )
    return pages


def navigation_sequence(page_registry: Mapping[str, Any]) -> Sequence[Any]:
    """Return pages in deterministic route-registration order.

    Args:
        page_registry: Registry returned by :func:`build_page_registry`.

    Returns:
        Ordered sequence accepted by ``st.navigation``.
    """

    return tuple(page_registry[spec.key] for spec in PAGE_SPECS)


def active_navigation_key(
    selected_page: Any,
    page_registry: Mapping[str, Any],
) -> str:
    """Resolve the stable SecureScope key for the selected Streamlit page.

    Args:
        selected_page: Page returned by ``st.navigation``.
        page_registry: Registered SecureScope page objects.

    Returns:
        Stable navigation key. Falls back to ``ISO Command Center``.
    """

    selected_path = str(getattr(selected_page, "url_path", "") or "")
    for key, page in page_registry.items():
        if page is selected_page:
            return key
        if str(getattr(page, "url_path", "") or "") == selected_path:
            return key
    return "ISO Command Center"


def run_hidden_navigation(page_registry: Mapping[str, Any]) -> Any:
    """Register routes without showing Streamlit's default navigation widget.

    Args:
        page_registry: Registered SecureScope pages.

    Returns:
        Currently selected Streamlit page.
    """

    return st.navigation(navigation_sequence(page_registry), position="hidden")
