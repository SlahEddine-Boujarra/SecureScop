"""Visible workflow sections; disclosure is reserved for secondary detail."""

from contextlib import contextmanager
import streamlit as st


@contextmanager
def workflow_section(title, description="", *, status=None, step=None):
    """Show a non-collapsible section using the caller's existing workflow state.

    Args:
        title: Action-oriented heading.
        description: Short guidance, not a compliance decision.
        status: Optional state derived by the caller from saved records.
        step: Optional step number within the current workflow.
    Yields:
        A standard Streamlit container; existing forms and permissions are retained.
    Raises:
        StreamlitAPIException: If the native container cannot be rendered.
    """
    with st.container(border=True):
        heading = f"{step} · {title}" if step else title
        st.markdown(f"### {heading}")
        if status:
            from securescope.ui.components.primitives import status_pill

            st.html(status_pill(str(status)))
        if description:
            st.caption(description)
        yield


def back_link(destination: str, *, key: str, disabled: bool = False) -> bool:
    """Render a consistent keyboard-accessible Back action.

    Args:
        destination: Visible return destination.
        key: Unique widget identity.
        disabled: Whether navigation is unavailable.
    Returns:
        Whether the link was activated.
    Raises:
        StreamlitAPIException: For an invalid widget identity.
    """
    from hashlib import sha256

    container_key = "back_link_" + sha256(key.encode()).hexdigest()[:16]
    st.html(
        f'<style>[data-testid="stMain"] .st-key-{container_key} .stButton > button[kind] {{'
        "border:0 !important;background:transparent !important;"
        "color:var(--ss-accent) !important;padding:4px 0 !important;"
        "min-height:28px !important;box-shadow:none !important;} "
        f'[data-testid="stMain"] .st-key-{container_key} .stButton > button[kind]:hover '
        "{text-decoration:underline;} "
        f'[data-testid="stMain"] .st-key-{container_key} .stButton > button[kind]:focus-visible {{'
        "outline:2px solid var(--ss-accent) !important;outline-offset:3px;}"
        f'[data-testid="stMain"] .st-key-{container_key} button p '
        "{color:inherit !important;}</style>"
    )
    with st.container(key=container_key):
        return st.button(f"← Back to {destination}", key=key, disabled=disabled)
