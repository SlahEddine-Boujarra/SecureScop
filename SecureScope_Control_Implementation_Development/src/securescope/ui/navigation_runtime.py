"""Runtime bridge between legacy navigation keys and modern Streamlit pages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import streamlit as st

_REGISTRY_KEY = "_securescope_page_registry"


def configure_page_registry(page_registry: Mapping[str, Any]) -> None:
    """Publish the current ``st.Page`` registry for contextual callbacks.

    Args:
        page_registry: Stable SecureScope route keys mapped to ``st.Page`` objects.

    Returns:
        None.

    Raises:
        TypeError: If page_registry is not a mapping.
    """

    # Page callables belong to this browser session, never the shared module.
    st.session_state[_REGISTRY_KEY] = dict(page_registry)


def navigate_to(navigation_key: str) -> None:
    """Navigate to a SecureScope page with a backwards-compatible fallback.

    Args:
        navigation_key: Stable SecureScope route key.

    Returns:
        None. On modern runtimes ``st.switch_page`` interrupts the current run.

    Raises:
        ValueError: If navigation_key is absent from a configured registry.
        Streamlit routing exceptions are propagated if a registered page cannot
        be switched to; this indicates a programming/configuration error.
    """

    registry = st.session_state.get(_REGISTRY_KEY, {})
    if registry and navigation_key not in registry:
        raise ValueError(f"Unknown SecureScope route: {navigation_key}")
    st.session_state["app_navigation"] = navigation_key
    page = registry.get(navigation_key)
    if page is not None and hasattr(st, "switch_page"):
        st.switch_page(page)


def page_registry_configured() -> bool:
    """Return whether this browser session has a configured page registry.

    Returns:
        True when this session owns a nonempty route mapping.

    Raises:
        No exceptions are intentionally raised.
    """

    return bool(st.session_state.get(_REGISTRY_KEY))
