"""Administrator-only, two-step Wazuh configuration without secret readback."""

import logging
import os

import streamlit as st

from securescope.integrations.credential_store import (
    CredentialStoreError,
    open_configuration,
    seal_configuration,
)
from securescope.integrations.wazuh_service import (
    WazuhError,
    env_bool,
    require_connector_admin,
    save_wazuh_config,
)
from securescope.ui.components.primitives import empty_state

LOGGER = logging.getLogger(__name__)


def render_wazuh_settings(client_name: str) -> None:
    """Render role-gated credential replacement with a separate confirmation.

    Args:
        client_name: Active workspace; bound into the pending change key.
    Returns:
        None.
    Raises:
        Unexpected Streamlit rendering errors propagate.
    """
    from securescope.ui.grc_workspace.context import current_actor

    actor = current_actor()
    tls_enabled = env_bool("WAZUH_VERIFY_TLS", True)
    indexer_tls_enabled = env_bool("WAZUH_INDEXER_VERIFY_TLS", tls_enabled)
    if not tls_enabled:
        st.warning(
            (
                "TLS certificate verification is OFF. The server identity is not "
                "checked; credentials and evidence may be intercepted. Install a "
                "trusted certificate and enable verification."
            )
        )
    if not indexer_tls_enabled:
        st.warning(
            "Indexer TLS certificate verification is OFF. The evidence server's "
            "identity is not checked; credentials and evidence may be intercepted."
        )
    try:
        require_connector_admin(client_name, actor)
    except WazuhError:
        st.caption(
            "Connector settings are restricted to a workspace Administrator authorized by the host."
        )
        return
    prefix = f"wazuh_settings::{client_name}::{actor}"
    pending_key = prefix + "::pending"
    api_key, indexer_key = prefix + "::api_secret", prefix + "::indexer_secret"
    if st.session_state.pop(prefix + "::clear", False):
        for key in (api_key, indexer_key, prefix + "::confirm"):
            st.session_state.pop(key, None)
    if st.session_state.pop(prefix + "::saved", False):
        st.success(
            "Connection settings saved securely. Use Test Connection to verify connectivity."
        )
    if st.button(
        "Configure Connection",
        key=prefix + "::configure",
        type="primary" if not os.getenv("WAZUH_API_PASSWORD") else "secondary",
    ):
        st.session_state[prefix + "::editing"] = True
    if not st.session_state.get(prefix + "::editing"):
        return
    with st.container(border=True):
        st.caption(
            (
                "These host connector settings affect all workspaces. Existing "
                "passwords are never displayed. Leave a password blank to keep it;"
                " new credentials are stored encrypted."
            )
        )
        with st.form(prefix + "::form"):
            api_url = st.text_input(
                "Wazuh API URL",
                value=os.getenv("WAZUH_API_URL", ""),
                placeholder="https://wazuh.example:55000",
            )
            api_user = st.text_input("API Username", value=os.getenv("WAZUH_API_USER", "wazuh"))
            api_password = st.text_input("New API password", type="password", key=api_key)
            with st.expander("Advanced settings · Indexer"):
                indexer_url = st.text_input("Indexer URL", value=os.getenv("WAZUH_INDEXER_URL", ""))
                indexer_user = st.text_input(
                    "Indexer Username", value=os.getenv("WAZUH_INDEXER_USER", "")
                )
                indexer_password = st.text_input(
                    "New Indexer password", type="password", key=indexer_key
                )
            prepare = st.form_submit_button("Review connection changes")
        with st.expander("Advanced settings · Connection security"):
            verify_tls = st.checkbox(
                "Verify TLS Certificate", value=tls_enabled, key=prefix + "::tls"
            )
            verify_indexer_tls = st.checkbox(
                "Verify Indexer TLS Certificate",
                value=indexer_tls_enabled,
                key=prefix + "::indexer_tls",
            )
            if not verify_tls and tls_enabled:
                st.warning(
                    (
                        "Verification will be disabled if you confirm this change. An "
                        "untrusted server could intercept credentials and evidence."
                    )
                )
            if not verify_indexer_tls and indexer_tls_enabled:
                st.warning("The pending Indexer setting disables server identity checks.")
        if prepare:
            st.session_state[prefix + "::confirm"] = False
            try:
                st.session_state[pending_key] = seal_configuration(
                    {
                        "api_url": api_url,
                        "api_user": api_user,
                        "api_password": api_password,
                        "verify_tls": verify_tls,
                        "indexer_url": indexer_url,
                        "verify_indexer_tls": verify_indexer_tls,
                        "indexer_user": indexer_user,
                        "indexer_password": indexer_password,
                    }
                )
            except CredentialStoreError as exc:
                st.error(str(exc))
        if pending_key not in st.session_state:
            return
        try:
            pending = open_configuration(st.session_state[pending_key])
        except CredentialStoreError as exc:
            st.session_state.pop(pending_key, None)
            st.error(str(exc))
            return
        st.markdown("**Confirm host connection changes**")
        st.table(
            [
                {"Setting": label, "Value": value}
                for label, value in {
                    "API URL": pending["api_url"],
                    "API user": pending["api_user"],
                    "Indexer URL": pending["indexer_url"],
                    "TLS verification": "On" if pending["verify_tls"] else "OFF",
                    "Indexer TLS verification": (
                        "On" if pending.get("verify_indexer_tls", True) else "OFF"
                    ),
                    "API password": "Replace" if pending["api_password"] else "Keep existing",
                    "Indexer password": (
                        "Replace" if pending["indexer_password"] else "Keep existing"
                    ),
                }.items()
            ]
        )
        if not pending["verify_tls"] or not pending.get("verify_indexer_tls", True):
            st.warning("This pending change disables certificate verification for all workspaces.")
        confirmed = st.checkbox(
            "I authorize these connection changes for all workspaces", key=prefix + "::confirm"
        )
        if st.button("Confirm and save connection", disabled=not confirmed, key=prefix + "::save"):
            try:
                save_wazuh_config(**pending, client_name=client_name, actor=actor)
            except (WazuhError, CredentialStoreError) as exc:
                LOGGER.warning("Wazuh configuration update rejected (%s)", type(exc).__name__)
                empty_state("Settings were not saved", str(exc), kind="error")
            else:
                st.session_state.pop(pending_key, None)
                st.session_state[prefix + "::clear"] = True
                st.session_state[prefix + "::saved"] = True
                st.rerun()
        if st.button("Discard pending change", key=prefix + "::cancel"):
            st.session_state.pop(pending_key, None)
            st.session_state[prefix + "::clear"] = True
            st.rerun()
