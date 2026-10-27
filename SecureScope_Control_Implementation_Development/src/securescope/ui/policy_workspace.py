"""Policy library, structured editing, control links and human review."""

from __future__ import annotations

import base64
import difflib
import logging
import uuid
from datetime import date

import pandas as pd
import streamlit as st
from securescope.ui.components.navigation import module_tabs
from securescope.ui.components.primitives import identity_context

from securescope.core.presentation import safe_text
from securescope.integrations.credential_store import CredentialStoreError
from securescope.persistence.grc_repository import list_control_overview
from securescope.policies.documents import plain_text, render_document
from securescope.policies.repository import (
    PolicyError,
    document_payload,
    load_policies,
    policy_rows,
    save_policy,
    upload_policy,
)
from securescope.ui.components.primitives import metric_card, status_pill
from securescope.ui.components_v2.policy_editor import policy_editor
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role
from securescope.ui.workflow_sections import back_link, workflow_section

LOGGER = logging.getLogger(__name__)
POLICY_ERRORS = (*ERRORS, PolicyError, CredentialStoreError, ValueError)


def _export_html(row: dict, blocks: list[dict]) -> bytes:
    """Build a portable escaped policy document with governance metadata.

    Args:
        row: Saved policy metadata.
        blocks: Decrypted saved document.
    Returns:
        UTF-8 standalone HTML document bytes.
    Raises:
        ValueError: If blocks are invalid.
    """
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>"
        + safe_text(row["title"])
        + (
            "</title><style>body{font:16px/1.7 "
            "system-ui;max-width:850px;margin:48px "
            "auto;padding:24px;color:#172336}header{border-bottom:2px solid "
            "#087e78;padding-bottom:20px}small{color:#596579}@media "
            "print{body{margin:0}}</style></head><body><header><h1>"
        )
        + safe_text(row["title"])
        + "</h1><small>Version "
        + safe_text(row["policy_version"])
        + " · "
        + safe_text(row["status"])
        + " · Owner: "
        + safe_text(row.get("owner", ""))
        + " · Review: "
        + safe_text(row.get("review_date", ""))
        + "<br>Approved by: "
        + safe_text(row.get("approved_by", "Not approved"))
        + "</small></header>"
        + render_document(blocks)
        + "</body></html>"
    ).encode()


def _table(rows: list[dict], key: str) -> str | None:
    """Show a searchable, sortable policy table with selection and pagination.

    Args:
        rows: Saved policy metadata.
        key: Workspace/context-specific key.
    Returns:
        Selected policy UUID, if any.
    Raises:
        StreamlitAPIException: For invalid widget state.
    """
    view = st.segmented_control(
        "Policy view",
        ["All", "Needs my approval", "Needs approval", "Needs reassignment"],
        default="All",
        key=key + "::view",
    )
    actor = current_actor()
    rows = [
        r
        for r in rows
        if view == "All"
        or (
            view == "Needs my approval"
            and r["status"] == "In review"
            and r.get("reviewer") == actor
        )
        or (view == "Needs approval" and r["status"] == "In review")
        or (view == "Needs reassignment" and (not r.get("owner") or not r.get("reviewer")))
    ]
    search, status_filter, owner_filter = st.columns([2, 1, 1])
    query = search.text_input("Search policies", key=key + "::search").strip().casefold()
    statuses = status_filter.multiselect(
        "Status",
        ["Draft", "Suggested", "In review", "Approved", "Archived"],
        key=key + "::statuses",
    )
    owners = owner_filter.multiselect(
        "Owner", sorted({row.get("owner", "") for row in rows}), key=key + "::owners"
    )
    with st.expander("More filters"):
        approvers = st.multiselect(
            "Approvers",
            sorted({r.get("reviewer") or "Unassigned" for r in rows}),
            key=key + "::approvers",
        )
        sources = st.multiselect(
            "Source", ["Uploaded", "Created in SecureScope"], key=key + "::source_filter"
        )
        mapped_only = st.checkbox("Mapped to ISO/IEC 27001", key=key + "::mapped_only")
    rows = [
        r
        for r in rows
        if (not approvers or (r.get("reviewer") or "Unassigned") in approvers)
        and (
            not sources
            or ("Uploaded" if r.get("source_name") else "Created in SecureScope") in sources
        )
        and (not mapped_only or r.get("controls"))
    ]
    visible = [
        row
        for row in rows
        if (not statuses or row["status"] in statuses)
        and (not owners or row.get("owner") in owners)
        and (not query or query in str(row.get("title", "")).casefold())
    ]
    data = [
        {
            "Policy": row["title"],
            "Overall status": (
                "Expired"
                if row.get("review_date") and row["review_date"] < date.today().isoformat()
                else (
                    "OK"
                    if row["status"] == "Approved"
                    else "Pending approval" if row["status"] == "In review" else row["status"]
                )
            ),
            "Latest version state": row["status"],
            "Approver": row.get("reviewer") or "Unassigned",
            "Approval status": "1/1" if row.get("approved_by") else "0/1",
            "Source": row.get("source_name") or "Created in SecureScope",
            "Version": row["policy_version"],
            "Owner": row.get("owner", ""),
            "Controls": len(row.get("controls", [])),
            "Renew by": row.get("review_date", ""),
            "Updated": row.get("updated_at", ""),
        }
        for row in visible
    ]
    if not data:
        st.info("No policies match these filters. Adjust the filters or upload a policy.")
        return None
    with st.popover("Table options"):
        columns = st.multiselect(
            "Visible columns", list(data[0]), default=list(data[0]), key=key + "::columns"
        )
        sort = st.selectbox("Sort by", list(data[0]), key=key + "::sort")
        descending = st.checkbox("Descending", key=key + "::descending")
    ordering = sorted(
        range(len(data)), key=lambda index: data[index].get(sort) or "", reverse=descending
    )
    pages = max(1, (len(ordering) + 14) // 15)
    page = st.number_input(
        "Page", min_value=1, max_value=pages, value=1, key=key + f"::page::{pages}"
    )
    indices = ordering[(int(page) - 1) * 15 : int(page) * 15]
    event = st.dataframe(
        pd.DataFrame([data[index] for index in indices])[columns or ["Policy"]],
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key=key
        + "::grid::"
        + str(st.session_state.get(key + "::grid_generation", 0))
        + "::"
        + str(hash(tuple(visible[index]["policy_id"] for index in indices))),
        height="content",
    )
    if event.selection.rows:
        chosen = visible[indices[event.selection.rows[0]]]["policy_id"]
        if st.session_state.get(key + "::last_grid_selection") != chosen:
            st.session_state[key + "::last_grid_selection"] = chosen
            return chosen
    else:
        st.session_state.pop(key + "::last_grid_selection", None)
    return None


def render_policy_workspace_legacy(client: str, context: dict) -> None:
    """Render the policy workflow for the selected engagement and scope.

    Args:
        client: Workspace name.
        context: Current scope and engagement.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected failures are displayed.
    """
    st.subheader("Policies")
    st.caption("Controlled documents · Upload → Extract → Edit → Review → Approve")
    scope = context.get("selected_scope_id")
    if not scope:
        st.info("Create or select an ISMS scope before managing policies.")
        return
    engagement = int(context["selected_engagement_id"])
    actor = current_actor()
    key = f"policies::{client}::{engagement}::{scope}"
    try:
        rows, history = load_policies(client, engagement, int(scope))
        role = get_workspace_role(client, actor)
        controls = list_control_overview(client)
    except POLICY_ERRORS as exc:
        st.error(f"Policy workspace unavailable: {exc}")
        return
    can_edit = role in {"Administrator", "Consultant", "Client contributor"}
    if not can_edit:
        st.info(
            (
                "An active contributor membership is required to upload or edit "
                "policies. Sign in or complete Administrator setup in Client "
                "Workspace."
            )
        )
    revision = int(history[0]["version"]) if history else 0
    active = [row for row in rows if row["status"] != "Archived"]
    overdue = sum(
        bool(row.get("review_date")) and row["review_date"] < date.today().isoformat()
        for row in active
    )
    for column, title, count in zip(
        st.columns(4),
        ["Policies", "Approved", "In review", "Review due"],
        [
            len(active),
            sum(row["status"] == "Approved" for row in active),
            sum(row["status"] == "In review" for row in active),
            overdue,
        ],
    ):
        with column:
            metric_card(title, count)
    if not st.session_state.get(key + "::selected"):
        with st.expander("Starter policy catalog"):
            st.caption(
                (
                    "25 optional draft policies with suggested control mappings. "
                    "Tailoring and approval are required; this is not a prescribed ISO"
                    " document list."
                )
            )
            if st.button(
                "Add missing starter policies", disabled=not can_edit, key=key + "::starters"
            ):
                from securescope.policies.catalog import add_starter_policies

                try:
                    add_starter_policies(
                        client,
                        engagement,
                        int(scope),
                        actor=actor,
                        known_controls={str(c["control_id"]) for c in controls},
                    )
                except POLICY_ERRORS as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
    with st.expander("Bulk import policy documents"):
        bulk = st.file_uploader(
            "Select DOCX, TXT or Markdown documents",
            type=["docx", "txt", "md"],
            accept_multiple_files=True,
            disabled=not can_edit,
            key=key + "::bulk",
        )
        if bulk:
            st.write([file.name for file in bulk])
            st.caption(
                (
                    "Each file becomes a new draft. Existing documents are not "
                    "overwritten. Files are saved individually; a later failure does "
                    "not undo earlier successful uploads."
                )
            )
            if st.button(
                "Import listed documents as drafts", disabled=not can_edit, key=key + "::bulk_save"
            ):
                saved_count = 0
                for file in bulk:
                    try:
                        upload_policy(
                            client,
                            engagement,
                            int(scope),
                            actor=actor,
                            expected_version=revision + saved_count,
                            filename=file.name,
                            content=file.getvalue(),
                        )
                    except POLICY_ERRORS as exc:
                        st.error(f"{file.name}: {exc}")
                        break
                    saved_count += 1
                st.success(
                    f"Saved {saved_count} draft documents. Reload the policy list to review them."
                )
                st.session_state[key + "::bulk_result"] = saved_count
            if key + "::bulk_result" in st.session_state and st.button(
                "Reload policy list", key=key + "::reload_bulk"
            ):
                st.session_state.pop(key + "::bulk_result", None)
                st.rerun()
    with workflow_section(
        "Upload policy / create document",
        "Create a draft for review; existing documents remain in the register.",
    ):
        st.caption("DOCX, UTF-8 TXT or Markdown · maximum 2 MiB · extracted text requires review")
        upload = st.file_uploader(
            "Policy document",
            type=["docx", "txt", "md"],
            key=key + "::upload",
            disabled=not can_edit,
        )
        if st.button(
            "Upload and save draft",
            type="primary",
            disabled=not can_edit or upload is None,
            key=key + "::extract",
        ):
            try:
                with st.spinner("Saving encrypted draft…"):
                    saved_id = upload_policy(
                        client,
                        engagement,
                        int(scope),
                        actor=actor,
                        expected_version=revision,
                        filename=upload.name,
                        content=upload.getvalue(),
                    )
                st.session_state[key + "::selected"] = saved_id
                st.session_state.pop(key + "::new", None)
                st.rerun()
            except POLICY_ERRORS as exc:
                LOGGER.warning("Policy extraction rejected: %s", type(exc).__name__)
                st.error(str(exc))
        if st.button("Start blank policy", disabled=not can_edit, key=key + "::blank"):
            st.session_state[key + "::new"] = {
                "title": "New policy",
                "blocks": [
                    {"kind": "h1", "runs": [{"text": "Purpose"}]},
                    {"kind": "p", "runs": [{"text": "Describe the policy's purpose and scope."}]},
                ],
                "policy_id": str(uuid.uuid4()),
            }
            st.session_state[key + "::selected"] = "new"
    if st.session_state.get(key + "::selected") and back_link("Policies", key=key + "::back"):
        st.session_state.pop(key + "::selected", None)
        st.session_state.pop(key + "::last_grid_selection", None)
        st.session_state[key + "::grid_generation"] = (
            st.session_state.get(key + "::grid_generation", 0) + 1
        )
        st.rerun()
    selected_id = (
        _table(rows, key) if rows and not st.session_state.get(key + "::selected") else None
    )
    if selected_id:
        st.session_state[key + "::selected"] = selected_id
        st.rerun()
    selected_id = st.session_state.get(key + "::selected")
    new = st.session_state.get(key + "::new") if selected_id == "new" else None
    row = next((item for item in rows if item["policy_id"] == selected_id), None)
    if row is None and new is None:
        st.info("Select a policy row to open its document, review, history and controls.")
        return
    row = row or {
        "policy_id": new["policy_id"],
        "policy_version": 0,
        "status": "Draft",
        "title": new["title"],
        "owner": actor,
    }
    try:
        payload = {"blocks": new["blocks"]} if new else document_payload(row)
    except POLICY_ERRORS as exc:
        st.error(str(exc))
        return
    blocks = payload["blocks"]
    version_key = key + f"::{row['policy_id']}::{row['policy_version']}"
    st.divider()
    st.markdown(status_pill(row["status"]), unsafe_allow_html=True)
    st.caption(f"Policy ID: {row['policy_id']}")
    st.caption(
        row.get("purpose") or "Add organization-specific purpose and requirements before approval."
    )
    st.caption(f"Renewal cadence: {row.get('renewal_cadence') or 'Not set'}")
    st.caption(f"Document version {row['policy_version']}")
    identity_context(row.get("updated_by", actor), "Updated by")
    document_tab, review_tab, control_tab, history_tab, builder_tab, discussion_tab = module_tabs(
        [
            "Policy versions",
            "Review",
            "Mapped elements",
            "Version history",
            "Guided builder",
            "Audits and comments",
        ]
    )
    with discussion_tab:
        if not new:
            from securescope.ui.policy_collaboration import render_policy_collaboration

            render_policy_collaboration(
                client, engagement, int(scope), row["policy_id"], actor, can_edit
            )
        else:
            st.info("Save the draft before linking audits or starting a discussion.")
    with builder_tab:
        from securescope.policies.builder import apply_section_edits, document_sections

        sections = document_sections(blocks)
        section_map = {section["id"]: section for section in sections}
        SECTIONS = list(section_map)

        st.caption(
            (
                "These prompts guide drafting. Completion means you reviewed a "
                "section; it does not establish compliance."
            )
        )
        draft_key = version_key + "::builder_draft"
        draft = st.session_state.setdefault(draft_key, {})
        completed_key = version_key + "::builder_checked"
        completed = st.session_state.setdefault(completed_key, [])
        guide, preview = st.columns([1, 1])
        with guide:
            section = st.selectbox(
                "Section",
                SECTIONS,
                format_func=lambda sid: section_map[sid]["title"],
                key=version_key + "::section",
            )
            text = st.text_area(
                "Organization-specific wording",
                value=draft.get(section, section_map[section]["text"]),
                height=220,
                key=version_key + "::section_text::" + section,
                disabled=not can_edit,
            )
            checked = st.checkbox(
                "I have tailored and reviewed this section",
                value=section in completed,
                key=version_key + "::checked::" + section,
                disabled=not can_edit,
            )
            draft[section] = text
            if checked and text.strip() and section not in completed:
                completed.append(section)
            elif (not checked or not text.strip()) and section in completed:
                completed.remove(section)
            st.progress(
                len(completed) / len(SECTIONS),
                text=f"{len(completed)}/{len(SECTIONS)} sections reviewed by you",
            )
        try:
            built = apply_section_edits(blocks, draft)
        except ValueError as exc:
            st.error(str(exc))
            built = []
        with preview:
            st.markdown("**Live section preview**")
            if built:
                st.markdown(render_document(built), unsafe_allow_html=True)
            else:
                st.info("Add wording to preview your new sections.")
        if st.button(
            "Save guided policy draft",
            disabled=not can_edit or not built,
            key=version_key + "::save_builder",
        ):
            try:
                save_policy(
                    client,
                    engagement,
                    int(scope),
                    actor=actor,
                    policy_id=row["policy_id"],
                    expected_version=revision,
                    status="Draft",
                    note="Updated policy sections through guided drafting; review required.",
                    metadata={
                        field: row.get(field, [] if field == "controls" else "")
                        for field in ("title", "owner", "reviewer", "review_date", "controls")
                    },
                    blocks=built,
                )
            except POLICY_ERRORS as exc:
                st.error(str(exc))
            else:
                st.session_state[key + "::selected"] = row["policy_id"]
                st.session_state.pop(key + "::new", None)
                st.rerun()
    metadata = {}
    with document_tab:
        with st.container(border=True):
            st.markdown("**Current version**")
            st.write(
                f"{row['status']} · Version {row['policy_version']}"
                f" · Edited by {row.get('updated_by', actor)}"
            )
            st.caption(
                (
                    "Edit the saved document below. Assign a reviewer and renewal date"
                    " before submitting on the Review tab."
                )
            )
        approved = next(
            (
                item
                for snapshot in history
                for item in policy_rows(snapshot, int(scope))
                if item["policy_id"] == row["policy_id"] and item.get("status") == "Approved"
            ),
            None,
        )
        if approved:
            with st.expander(
                f"Approved version {approved['policy_version']} · {approved.get('approved_at', '')}"
            ):
                identity_context(approved.get("approved_by", "Not recorded"), "Approved by")
                try:
                    st.markdown(
                        render_document(document_payload(approved)["blocks"]),
                        unsafe_allow_html=True,
                    )
                except POLICY_ERRORS as exc:
                    st.error(str(exc))
        outline, document, info = st.columns([1, 3, 1.3])
        with outline:
            st.markdown("**Document outline**")
            for block in blocks:
                if block["kind"].startswith("h"):
                    st.caption("".join(run["text"] for run in block["runs"]))
            if new:
                st.info("Extracted draft — not saved")
                st.caption(new.get("notes", "Blank document"))
            if row.get("source_name"):
                st.caption(f"Source: {row['source_name']} · {row.get('source_size', 0):,} bytes")
                st.caption(
                    f"Uploaded by {row.get('uploaded_by', '—')} · {row.get('uploaded_at', '—')}"
                )
        with info:
            st.markdown("**Policy information**")
            for field, label in [
                ("title", "Policy title"),
                ("owner", "Owner"),
                ("reviewer", "Reviewer"),
                ("review_date", "Review date (YYYY-MM-DD)"),
                ("purpose", "Purpose"),
                ("renewal_cadence", "Renewal cadence"),
            ]:
                metadata[field] = st.text_input(
                    label,
                    value=str(row.get(field, "")),
                    key=version_key + "::" + field,
                    disabled=not can_edit,
                )
            catalog = {
                str(control["control_id"]): str(control["control_name"]) for control in controls
            }
            metadata["controls"] = st.multiselect(
                "ISO controls",
                list(catalog),
                default=[cid for cid in row.get("controls", []) if cid in catalog],
                format_func=lambda cid: f"{cid} · {catalog[cid]}",
                key=version_key + "::controls",
                disabled=not can_edit,
            )
            note = st.text_area(
                "Change summary", key=version_key + "::summary", disabled=not can_edit
            )
            st.caption(
                "Saving an edit creates a draft. Previous approved versions remain available."
            )
        with document:
            editor = policy_editor(
                blocks, key=version_key + "::editor", read_only=not can_edit, saved=new is None
            )
            save_event = getattr(editor, "save", None)
            if save_event:
                try:
                    if new:
                        metadata["source_name"] = new.get("filename", "")
                    save_policy(
                        client,
                        engagement,
                        int(scope),
                        actor=actor,
                        policy_id=row["policy_id"],
                        expected_version=revision,
                        status="Draft",
                        note=note,
                        metadata=metadata,
                        blocks=save_event["blocks"],
                        source=new.get("source") if new else None,
                    )
                except POLICY_ERRORS as exc:
                    st.error(str(exc))
                else:
                    st.session_state[key + "::selected"] = row["policy_id"]
                    st.session_state.pop(key + "::new", None)
                    st.rerun()
            if not new:
                st.download_button(
                    "Download saved policy",
                    _export_html(row, blocks),
                    file_name=f"policy_{row['policy_id']}_v{row['policy_version']}.html",
                    mime="text/html",
                    key=version_key + "::download",
                )
                from reportlab.platypus.doctemplate import LayoutError

                from securescope.reporting.policy_export import policy_pdf

                try:
                    pdf = policy_pdf(row, blocks)
                except (ValueError, LayoutError) as exc:
                    LOGGER.warning("Policy PDF generation failed: %s", type(exc).__name__)
                    st.error(
                        "PDF layout could not be generated. The HTML download remains available."
                    )
                else:
                    st.download_button(
                        "Download PDF",
                        pdf,
                        file_name=f"policy_{row['policy_id']}_v{row['policy_version']}.pdf",
                        mime="application/pdf",
                        key=version_key + "::pdf",
                    )
                if payload.get("source_base64"):
                    st.download_button(
                        "Download original source",
                        base64.b64decode(payload["source_base64"]),
                        file_name=row.get("source_name", "original.docx"),
                        key=version_key + "::original",
                    )
    with review_tab:
        st.write(f"Reviewer: {row.get('reviewer') or 'Unassigned'}")
        st.caption(
            f"Review date: {row.get('review_date') or 'Not set'}"
            f" · Approved by: {row.get('approved_by') or 'Not approved'}"
        )
        st.info(
            (
                "Review actions apply to the saved document version. Save all "
                "editor and metadata changes first."
            )
        )
        rationale = st.text_area("Review / approval comments", key=version_key + "::rationale")
        confirmed = st.checkbox(
            "I reviewed the saved document and its mapped controls.",
            key=version_key + "::confirmed",
        )
        request = None
        for column, label, status, allowed in zip(
            st.columns(3),
            ["Submit for review", "Approve policy", "Archive policy"],
            ["In review", "Approved", "Archived"],
            [
                can_edit
                and row["status"] in {"Draft", "Suggested"}
                and bool(row.get("reviewer"))
                and bool(row.get("review_date")),
                role == "Administrator" and row["status"] == "In review",
                role == "Administrator" and row["status"] != "Archived",
            ],
        ):
            if column.button(
                label,
                key=version_key + "::" + status,
                type="primary" if status != "Archived" else "secondary",
                disabled=new is not None or not allowed or not confirmed or not rationale.strip(),
            ):
                request = status
        if request:
            try:
                save_policy(
                    client,
                    engagement,
                    int(scope),
                    actor=actor,
                    policy_id=row["policy_id"],
                    expected_version=revision,
                    status=request,
                    note=rationale,
                    metadata={},
                )
            except POLICY_ERRORS as exc:
                st.error(str(exc))
            else:
                st.rerun()
    with control_tab:
        st.caption(
            f"This saved policy supports {len(row.get('controls', []))}"
            f" controls. A mapping does not establish implementation."
        )
        for cid in row.get("controls", []):
            if st.button(
                f"{cid} · {catalog.get(cid, 'Control')}", key=version_key + "::open::" + cid
            ):
                from securescope.ui.exposure_management_ui import open_control_assessment
                from securescope.ui.navigation_runtime import navigate_to

                st.session_state[f"manual_control_pending::{client}"] = cid
                open_control_assessment(client)
                navigate_to("Gap Assessment")
    with history_tab:
        previous = []
        seen = set()
        for snapshot in history:
            for item in policy_rows(snapshot, int(scope)):
                marker = item["policy_version"]
                if item["policy_id"] == row["policy_id"] and marker not in seen:
                    previous.append(item)
                    seen.add(marker)
        if previous:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            k: item.get(k, "")
                            for k in (
                                "policy_version",
                                "status",
                                "updated_by",
                                "updated_at",
                                "change_summary",
                            )
                        }
                        for item in previous
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            selected_version = st.selectbox(
                "View saved version",
                range(len(previous)),
                format_func=lambda index: f"Version {previous[index]['policy_version']}"
                f" · {previous[index]['status']}",
                key=version_key + "::history",
            )
            try:
                historic = document_payload(previous[selected_version])["blocks"]
                st.markdown(render_document(historic), unsafe_allow_html=True)
                st.code(
                    "\n".join(
                        difflib.unified_diff(
                            plain_text(historic).splitlines(),
                            plain_text(blocks).splitlines(),
                            fromfile="Selected version",
                            tofile="Current saved version",
                        )
                    )
                    or "No text changes.",
                    language="diff",
                )
            except POLICY_ERRORS as exc:
                st.error(str(exc))


def render_related_policies(client: str, control_id: str) -> None:
    """Show reverse policy references for the selected ISMS context.

    Args:
        client: Workspace name.
        control_id: Selected control reference.
    Returns:
        None.
    Raises:
        Expected read failures display an explicit unavailable state.
    """
    from securescope.ui.grc_workspace.context import workspace_state_keys

    engagement_key, scope_key = workspace_state_keys(client)
    engagement = st.session_state.get(engagement_key)
    scope = st.session_state.get(scope_key)
    with st.expander("Related policies"):
        if not engagement or not scope:
            st.info(
                (
                    "Select an engagement and ISMS scope in Programme Foundation to "
                    "view linked policies."
                )
            )
            return
        try:
            rows, _ = load_policies(client, int(engagement), int(scope))
        except POLICY_ERRORS as exc:
            st.error(f"Policy links unavailable: {exc}")
            return
        linked = [
            row
            for row in rows
            if control_id in row.get("controls", []) and row["status"] != "Archived"
        ]
        if not linked:
            st.info("No policies mapped to this control in the selected scope.")
        for row in linked:
            st.write(f"{row['title']} · {row['status']} · v{row['policy_version']}")
            if st.button("Open policy", key=f"policy_backlink::{control_id}::{row['policy_id']}"):
                from securescope.ui.navigation_runtime import navigate_to

                st.session_state[f"policies::{client}::{engagement}::{scope}::selected"] = row[
                    "policy_id"
                ]
                navigate_to("Policies")


def render_policies_page(client: str) -> None:
    """Open the directly navigable policy library in the current context.

    Args:
        client: Active workspace name.
    Returns:
        None.
    Raises:
        Expected context errors are shown in the UI.
    """
    from securescope.ui.grc_workspace.context import open_selected_context

    try:
        context = open_selected_context(client)
    except POLICY_ERRORS as exc:
        st.error(f"Policy context unavailable: {exc}")
        return
    render_policy_workspace(client, context)


def render_policy_workspace(client: str, context: dict) -> None:
    """Open the custom workbench over the existing authorized repositories."""
    from securescope.ui.assurance_workbench import render_policy_workbench

    render_policy_workbench(client, context)
