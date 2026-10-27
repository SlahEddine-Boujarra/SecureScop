"""Two-confirmation client workspace deletion controls."""

import streamlit as st

from securescope.persistence.db_service import DatabaseError, get_client_id
from securescope.persistence.workspace_deletion import delete_workspace
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role


def render_workspace_deletion(client: str) -> bool:
    """Render deletion for the selected client only.

    Args:
        client: Exact target workspace.
    Returns:
        True after successful deletion, otherwise False.
    Raises:
        Expected permission/database errors display safe messages.
    """
    with st.expander(f"Delete workspace: {client}", expanded=True):
        actor = current_actor()
        try:
            role = get_workspace_role(client, actor)
            client_id = get_client_id(client)
        except (*ERRORS, DatabaseError) as exc:
            st.error(str(exc))
            return False
        if role != "Administrator":
            st.info(
                (
                    "Sign in as an Administrator of this workspace in Client "
                    "Workspace to delete it."
                )
            )
            return False
        st.warning(
            (
                "Delete “"
                f"{client}"
                "” and its SecureScope assets, findings, policies, risk "
                "records, evidence and history. External scanner systems and "
                "host integration settings are not "
                "deleted."
            )
        )
        with st.form(f"delete_workspace::{client_id}"):
            first = st.checkbox(
                f"1. I confirm that {client} is the client workspace I want to delete."
            )
            second = st.checkbox(
                "2. I understand deletion is permanent and have exported any records I need."
            )
            submit = st.form_submit_button("Permanently delete workspace", type="primary")
        if submit:
            try:
                result = delete_workspace(
                    client,
                    actor=actor,
                    expected_id=client_id,
                    confirm_data=first,
                    confirm_permanent=second,
                )
            except (*ERRORS, DatabaseError) as exc:
                st.error(str(exc))
            else:
                # Clear cached tenant data, drafts and selections, including the deleted identity.
                for key in list(st.session_state):
                    del st.session_state[key]
                st.session_state["workspace_deletion_notice"] = (
                    result.cleanup_warning or "Client workspace deleted."
                )
                return True
    return False
