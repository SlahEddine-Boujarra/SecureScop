"""Policy-linked discussion and audit references scoped to the saved document."""

from __future__ import annotations

import streamlit as st
from securescope.ui.components.navigation import module_tabs
from securescope.ui.components.primitives import identity_context

from securescope.persistence.foundation_repository import workspace_cursor
from securescope.persistence.workspace_planning import list_records, put_record
from securescope.ui.grc_workspace.formal import ERRORS


def render_policy_collaboration(
    client: str, engagement: int, scope: int, policy_id: str, actor: str, can_edit: bool
) -> None:
    """Persist threaded comments and links to real client audit records."""
    key = f"policy_links::{client}::{scope}::{policy_id}"
    identity = {"engagement": engagement, "scope": scope, "policy_id": policy_id}
    try:
        comments = [
            r
            for r in list_records(client, "policy_comment")
            if all(r["payload"].get(k) == v for k, v in identity.items())
        ]
        links = [
            r
            for r in list_records(client, "policy_audit")
            if all(r["payload"].get(k) == v for k, v in identity.items())
        ]
        with workspace_cursor(client) as (cursor, client_id):
            cursor.execute(
                (
                    "SELECT id,audit_no,status FROM securescope_audit_scopes WHERE "
                    "client_id=%s ORDER BY id DESC"
                ),
                (client_id,),
            )
            audits = [dict(r) for r in cursor.fetchall()]
    except ERRORS as exc:
        st.error(f"Policy discussion unavailable: {exc}")
        return
    audit_tab, comment_tab = module_tabs(["Audits", "Comments"])
    with audit_tab:
        catalog = {r["id"]: r for r in audits}
        for row in links:
            audit = catalog.get(row["payload"]["audit_id"])
            if audit:
                st.write(f"{audit['audit_no']} · {audit['status']}")
        if not links:
            st.info("No audits linked to this policy yet.")
        if audits:
            selected = st.selectbox(
                "Link an existing audit",
                list(catalog),
                format_func=lambda i: str(catalog[i]["audit_no"]),
                key=key + "audit",
            )
            if st.button("Link audit", disabled=not can_edit, key=key + "link"):
                try:
                    if not any(r["payload"]["audit_id"] == selected for r in links):
                        put_record(
                            client,
                            "policy_audit",
                            "",
                            dict(identity, audit_id=selected),
                            actor=actor,
                        )
                except ERRORS as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
        else:
            st.caption("Create an audit scope in Control Assurance to link it here.")
    with comment_tab:
        by_id = {r["record_key"]: r for r in comments}
        for row in comments:
            with st.container(border=True):
                identity_context(row["updated_by"], "Comment author")
                st.caption(str(row["created_at"]))
                parent = by_id.get(row["payload"].get("parent"))
                if parent:
                    identity_context(parent["updated_by"], "Reply to")
                    st.text(parent["payload"]["body"][:120])
                st.text(row["payload"]["body"])
        if not comments:
            st.info("No comments yet. Record review questions and decisions here.")
        with st.form(key + "comment"):
            parent = st.selectbox(
                "Reply to",
                [""] + list(by_id),
                format_func=lambda i: "New thread" if not i else by_id[i]["payload"]["body"][:70],
            )
            body = st.text_area("Comment", max_chars=10000)
            submit = st.form_submit_button("Post comment", disabled=not can_edit)
        if submit:
            try:
                put_record(
                    client,
                    "policy_comment",
                    "",
                    dict(identity, parent=parent, body=body),
                    actor=actor,
                )
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.rerun()
