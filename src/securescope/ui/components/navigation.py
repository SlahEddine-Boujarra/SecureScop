"""Native, overflow-aware section navigation with stable domain selection keys."""

from collections.abc import Callable, Sequence
from typing import Any

import streamlit as st


class SectionSelection(str):
    """Canonical section value with its native panel for rendering.

    Parameters:
        value: Canonical navigation value.
        panel: Native Streamlit tab container for this value.
    """

    def __new__(cls, value: str, panel: Any):
        """Return a string-compatible selection carrying its current panel.

        Args:
            value: Canonical section name.
            panel: Current run's native tab container.
        Returns:
            SectionSelection; never stored in session state.
        Raises:
            TypeError: If the value cannot be converted to a string.
        """
        selection = super().__new__(cls, value)
        selection.panel = panel
        return selection


def section_navigation(
    label: str,
    options: Sequence[str],
    *,
    key: str,
    default: str | None = None,
    format_func: Callable = str,
    on_change: Callable | None = None,
    args: tuple = (),
    selection_mode: str = "single",
    label_visibility: str = "collapsed",
) -> SectionSelection:
    """Render native tabs while retaining callers' canonical navigation values.

    Native widget labels are presentation-only; callbacks and pending navigation
    continue reading the original key. No domain records are modified.

    Args:
        label: Accessible section description retained by the adapter contract.
        options: Ordered canonical navigation values.
        key: Existing client/context-specific selection key.
        default: Initial canonical value.
        format_func: Presentation label formatter.
        on_change: Existing domain navigation callback.
        args: Arguments passed to the callback.
        selection_mode: Compatibility argument; navigation selects one section.
        label_visibility: Compatibility argument for the former selector.
    Returns:
        String-compatible canonical value with the native panel used by the caller.
    Raises:
        ValueError: If the native widget returns an unknown label.
    """
    values = list(options)
    selected = st.session_state.get(key, default or values[0])
    if selected not in values:
        selected = default or values[0]
    formatted_labels = [str(format_func(value)) for value in values]
    labels = [
        label if label.startswith(":material/") else f":material/{_icon(str(value))}: {label}"
        for value, label in zip(values, formatted_labels)
    ]
    widget_key = key + "::navigation_tabs"
    st.session_state[widget_key] = labels[values.index(selected)]

    def changed():
        """Synchronize selection before invoking the existing callback.

        Returns:
            None.
        Raises:
            ValueError: If the selected label is not in the navigation options.
        """
        chosen = st.session_state[widget_key]
        st.session_state[key] = values[labels.index(chosen)]
        if on_change is not None:
            on_change(*args)

    panels = module_tabs(labels, key=widget_key, on_change=changed)
    st.session_state[key] = selected
    return SectionSelection(selected, panels[values.index(selected)])


def _icon(value: str) -> str:
    """Choose a presentation icon without changing the canonical value.

    Args:
        value: Section name or identifier.
    Returns:
        Material icon name.
    Raises:
        No exceptions are raised for string values.
    """
    value = value.casefold()
    for term, icon in (
        ("overview", "dashboard"),
        ("dashboard", "dashboard"),
        ("profile", "shield"),
        ("assess", "fact_check"),
        ("project", "calendar_month"),
        ("collect", "download"),
        ("import", "upload_file"),
        ("manual", "edit_document"),
        ("consultant", "fact_check"),
        ("request", "assignment"),
        ("auditor", "inventory_2"),
        ("settings", "settings"),
        ("evidence", "folder_open"),
        ("network", "lan"),
        ("endpoint", "computer"),
        ("fleet", "devices"),
        ("workspace", "business"),
        ("scan", "radar"),
        ("health", "monitor_heart"),
        ("discover", "explore"),
        ("context", "business"),
        ("part", "groups"),
        ("scope", "filter_center_focus"),
        ("govern", "account_tree"),
        ("roles", "groups"),
        ("objective", "flag"),
        ("engagement", "work"),
        ("treatment", "assignment"),
        ("residual", "analytics"),
        ("accept", "verified"),
        ("monitor", "monitoring"),
        ("method", "tune"),
        ("risk", "shield"),
        ("register", "list_alt"),
    ):
        if term in value:
            return icon
    return "view_list"


def module_tabs(labels: Sequence[str], *, container=None, **kwargs: Any):
    """Use native tabs with one icon convention and native overflow behavior.

    Args:
        labels: Visible destination labels, optionally including Material icons.
        container: Existing Streamlit container, when provided by the caller.
        **kwargs: Native tab options forwarded unchanged.
    Returns:
        Native Streamlit tab containers.
    Raises:
        StreamlitAPIException: If native tab options are invalid.
    """
    display = [
        label if label.startswith(":material/") else f":material/{_icon(label)}: {label}"
        for label in labels
    ]
    return (container if container is not None else st).tabs(display, **kwargs)
