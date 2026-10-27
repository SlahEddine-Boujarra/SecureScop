"""Integrated SecureScope sidebar with deterministic compact navigation."""

import os
from collections.abc import Callable, Mapping
from typing import Any

import streamlit as st

from securescope.core.presentation import safe_text

NavigationItem = tuple[str, str, str, str]
NavigationGroup = tuple[str, tuple[NavigationItem, ...]]


NAVIGATION_GROUPS: tuple[NavigationGroup, ...] = (
    (
        "Overview",
        (
            (
                "ISO Command Center",
                "ISO Command Center",
                "Command Center",
                ":material/dashboard:",
            ),
            ("Overview", "Overview", "Exposure Overview", ":material/visibility:"),
        ),
    ),
    (
        "ISO 27001",
        (
            (
                "Programme Setup",
                "Programme Setup",
                "Programme Foundation",
                ":material/account_tree:",
            ),
            (
                "Gap Assessment",
                "Gap Assessment",
                "Control Assurance",
                ":material/verified_user:",
            ),
            ("Risk", "Risk", "Risk Management", ":material/policy:"),
            ("Policies", "Policies", "Policies", ":material/description:"),
        ),
    ),
    (
        "Security",
        (
            (
                "2 · Asset Management",
                "Asset Management",
                "Asset Management",
                ":material/inventory_2:",
            ),
            (
                "1 · Asset Discovery",
                "Asset Discovery",
                "Discover assets (Nmap)",
                ":material/travel_explore:",
            ),
            (
                "3 · Scan Center",
                "Scan Center",
                "Scan Center",
                ":material/radar:",
            ),
            (
                "4 · Reports & Findings",
                "Findings Dashboard",
                "Vulnerabilities",
                ":material/bug_report:",
            ),
            (
                "5 · SIEM & Wazuh",
                "SIEM / Wazuh",
                "SIEM",
                ":material/shield:",
            ),
            (
                "ISO Evidence Hub",
                "ISO Evidence Hub",
                "Evidence Register",
                ":material/folder_open:",
            ),
        ),
    ),
    (
        "Operations",
        (
            ("Calendar", "Calendar", "Calendar", ":material/calendar_month:"),
            (
                "Remediation",
                "Remediation",
                "Remediation",
                ":material/build:",
            ),
            (
                "Client History",
                "Client History",
                "Reports & Audit",
                ":material/assessment:",
            ),
        ),
    ),
)


# Internal routes preserved for contextual drill-downs. They are intentionally
# absent from the sidebar so Control Assurance remains the single ISO workspace.
HIDDEN_NAVIGATION_PAGES: dict[str, str] = {
    # Compatibility aliases retain the legacy route contract for deep links and
    # tests while the visible rail uses the consolidated information architecture.
    "1 · Asset Discovery": "Asset Discovery",
    "6 · ISO 27001 Assessment": "ISO 27001 Mapping",
}


def _toggle_sidebar() -> None:
    """Toggle the custom expanded or compact sidebar state.

    Returns:
        None.
    """
    st.session_state["sidebar_compact"] = not bool(st.session_state.get("sidebar_compact", False))
    st.session_state.pop("sidebar_transition_pending", None)


def _select_navigation(navigation_key: str) -> None:
    """Store the selected sidebar navigation key.

    Args:
        navigation_key: Stable internal identifier for the selected page.

    Returns:
        None.
    """
    st.session_state["app_navigation"] = navigation_key


def _navigation_widget_key(page: str) -> str:
    """Build the stable Streamlit widget key for a navigation page.

    Args:
        page: Internal page name associated with the navigation button.

    Returns:
        CSS-safe Streamlit widget key used by the menu button.
    """
    return "sidebar_navigation_" + page.lower().replace(" ", "_").replace("/", "_")


def render_sidebar_menu(
    active_client: str = "Default Client",
    asset_count: int = 0,
    report_count: int = 0,
    open_workspace_dialog: Callable[[], None] | None = None,
    open_connection_dialog: Callable[[], None] | None = None,
    *,
    page_objects: Mapping[str, Any] | None = None,
    active_navigation_key: str | None = None,
) -> str:
    """Render only the SecureScope sidebar menu.

    Args:
        active_client: Name of the currently selected client workspace.
        asset_count: Number of assets in the current workspace.
        report_count: Number of reports in the current workspace.
        open_workspace_dialog: Optional callback for workspace management.
        open_connection_dialog: Optional callback for connection diagnostics.
        page_objects: Optional modern ``st.Page`` registry. When supplied, the
            custom sidebar switches Streamlit routes instead of mutating the
            legacy session-state router.
        active_navigation_key: Stable key for the selected ``st.Page``.

    Returns:
        Internal page name selected by the user.
    """
    flat_items = [item for _group_name, group_items in NAVIGATION_GROUPS for item in group_items]
    navigation_pages = {navigation_key: page for navigation_key, page, _label, _icon in flat_items}
    navigation_pages.update(HIDDEN_NAVIGATION_PAGES)

    if page_objects is None:
        if st.session_state.get("app_navigation") not in navigation_pages:
            st.session_state["app_navigation"] = "ISO Command Center"
        current_navigation = str(st.session_state["app_navigation"])
    else:
        current_navigation = str(active_navigation_key or "ISO Command Center")
        if current_navigation not in navigation_pages and current_navigation != "Client Workspace":
            current_navigation = "ISO Command Center"
        # Keep the legacy key synchronized for existing contextual callbacks that
        # have not yet been migrated to ``st.switch_page``. It is no longer the
        # source of truth for top-level routing.
        st.session_state["app_navigation"] = current_navigation

    st.session_state.setdefault("sidebar_compact", False)
    compact = bool(st.session_state["sidebar_compact"])
    st.session_state.pop("sidebar_transition_pending", None)

    with st.sidebar:
        st.markdown(
            f'<span class="ss-sidebar-mode-{"compact" if compact else "expanded"}"></span>',
            unsafe_allow_html=True,
        )
        if compact:
            st.button(
                "",
                type="secondary",
                width="stretch",
                key="sidebar_compact_toggle",
                icon=":material/menu:",
                help="Expand navigation",
                on_click=_toggle_sidebar,
            )
            st.markdown(
                '<div class="ss-brand">' '<span class="ss-brand-mark">SS</span>' "</div>",
                unsafe_allow_html=True,
            )
        else:
            brand_column, toggle_column = st.columns(
                [5, 1],
                vertical_alignment="center",
                gap="small",
            )
            with brand_column:
                st.markdown(
                    """
                    <div class="ss-brand">
                        <span class="ss-brand-mark">SS</span>
                        <div class="ss-brand-copy">
                            <strong>SecureScope</strong>
                            <span>ISO 27001 Assurance</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with toggle_column:
                st.button(
                    "",
                    type="secondary",
                    width="content",
                    key="sidebar_compact_toggle",
                    icon=":material/menu_open:",
                    help="Collapse navigation",
                    on_click=_toggle_sidebar,
                )

        if compact:
            if (
                st.button(
                    "Client workspace",
                    icon=":material/business:",
                    type="secondary",
                    width="stretch",
                    key="open_client_dialog_compact",
                )
                and open_workspace_dialog is not None
            ):
                open_workspace_dialog()
        else:
            st.markdown(
                '<div class="ss-nav-label">Client workspace</div>',
                unsafe_allow_html=True,
            )
            if (
                st.button(
                    f"Switch workspace: {active_client}",
                    icon=":material/business:",
                    type="secondary",
                    width="stretch",
                    key="open_client_dialog_expanded",
                )
                and open_workspace_dialog is not None
            ):
                open_workspace_dialog()
            st.markdown(
                f'<div class="ss-workspace-meta">{safe_text(asset_count)} assets · '
                f"{safe_text(report_count)} reports</div>",
                unsafe_allow_html=True,
            )

        with st.container(key="sidebar_navigation_list"):
            for group_name, group_items in NAVIGATION_GROUPS:
                if not compact:
                    st.markdown(
                        f'<div class="ss-nav-label">{safe_text(group_name)}</div>',
                        unsafe_allow_html=True,
                    )

                for (
                    navigation_key,
                    page,
                    label,
                    _material_symbol,
                ) in group_items:
                    active = navigation_key == current_navigation
                    if page_objects is not None:
                        target_page = page_objects.get(navigation_key)
                        if target_page is not None:
                            container_key = (
                                "sidebar_current_route" if active else _navigation_widget_key(page)
                            )
                            with st.container(key=container_key):
                                st.page_link(
                                    target_page,
                                    label=label,
                                    icon=_material_symbol,
                                    width="stretch",
                                    help=label if compact else None,
                                )
                    else:
                        st.button(
                            "" if compact else label,
                            type="primary" if active else "secondary",
                            width="stretch",
                            icon=_material_symbol,
                            key=_navigation_widget_key(page),
                            help=label if compact else None,
                            on_click=_select_navigation,
                            args=(navigation_key,),
                        )

        if not compact:
            st.markdown(
                '<div class="ss-nav-label">Workspace</div>',
                unsafe_allow_html=True,
            )
        if page_objects is not None:
            workspace_page = page_objects.get("Client Workspace")
            if workspace_page is not None:
                with st.container(
                    key=(
                        "sidebar_current_route"
                        if current_navigation == "Client Workspace"
                        else "open_client_workspace_navigation"
                    )
                ):
                    st.page_link(
                        workspace_page,
                        label="Client Workspace",
                        icon=":material/domain:",
                        width="stretch",
                        help="Client Workspace" if compact else None,
                    )
        else:
            st.button(
                "" if compact else "Client Workspace",
                icon=":material/domain:",
                width="stretch",
                key="open_client_workspace_navigation",
                on_click=open_workspace_dialog,
            )

        if compact:
            if (
                st.button(
                    "",
                    icon=":material/lan:",
                    type="secondary",
                    width="stretch",
                    key="open_connection_dialog_compact",
                    help="Connection status",
                )
                and open_connection_dialog is not None
            ):
                open_connection_dialog()
        else:
            st.markdown(
                '<div class="ss-nav-label">System</div>',
                unsafe_allow_html=True,
            )
            if (
                st.button(
                    "Connection status",
                    icon=":material/lan:",
                    type="secondary",
                    width="stretch",
                    key="open_connection_dialog_expanded",
                )
                and open_connection_dialog is not None
            ):
                open_connection_dialog()

    if not compact and os.getenv("SECURESCOPE_INTERNAL_DIAGNOSTICS", "").lower() == "true":
        from securescope.ui.feature_availability import render_availability

        with st.sidebar:
            render_availability(compact=True)
    return navigation_pages.get(current_navigation, current_navigation)
