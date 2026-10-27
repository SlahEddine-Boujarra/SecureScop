"""Risk workspace over the existing canonical asset/scenario register."""

from __future__ import annotations

import json
from datetime import date

import pandas as pd
import streamlit as st
from securescope.ui.components.primitives import identity_context

from securescope.ui.components.navigation import section_navigation

from securescope.ui.workflow_sections import back_link

from securescope.grc.risk_register import ASSET_GROUPS, starter_risks
from securescope.persistence.foundation_repository import FoundationError, member_role
from securescope.persistence.risk_register_repository import list_risk_register, save_risk_record
from securescope.persistence.workspace_planning import (
    EDITORS,
    delete_group,
    list_records,
    put_record,
)
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role
from securescope.ui.workflow_sections import workflow_section


def _save(client: str, row: dict, actor: str, revision: int) -> None:
    """Authorize on the locked tenant row before the canonical write."""

    def authorize(cursor, client_id):
        if member_role(cursor, client_id, actor) not in EDITORS:
            raise FoundationError("An active contributor membership is required.")
        references = row.get("control_references") or []
        if isinstance(references, str):
            references = [x.strip() for x in references.split(",") if x.strip()]
        cursor.execute(
            "SELECT control_id FROM securescope_control_assessment_profiles WHERE client_id=%s",
            (client_id,),
        )
        known = {item["control_id"] for item in cursor.fetchall()}
        if not set(references).issubset(known):
            raise FoundationError("Use control references from this workspace's catalog.")

    row = dict(row, residual_verified=False, residual_evidence="", residual_verified_by="")
    save_risk_record(client, row, actor=actor, expected_revision=revision, authorize=authorize)


def _detail(client: str, row: dict, details: dict, groups: list[dict], role: str) -> None:
    """Edit assessment inputs and submit the current saved revision for human review."""
    ref = row["risk_ref"]
    key = f"risk::{client}::{ref}"
    actor = current_actor()
    if back_link("Risks", key=key + "back"):
        st.session_state.pop(f"risk::{client}::selected", None)
        st.rerun()
    st.subheader(f"Risk {ref} · {row.get('threat') or row.get('asset') or 'New scenario'}")
    st.caption(
        (
            "Discover → Suggest → Review → Approve. Suggestions are drafts. "
            "Assessment changes invalidate a previous review."
        )
    )
    saved = details.get(str(ref), {})
    meta = saved.get("payload", {})
    state = meta.get("review_state", "Draft")
    if meta.get("reviewed_revision") != row.get("revision"):
        state = "Draft"
    st.write(f'Review: {state} · Inherent score: {row.get("pre_risk_score", "Not assessed")}')
    from securescope.ui.components.risk_score import score_card

    for column, title, field in zip(
        st.columns(2), ["Inherent risk", "Residual risk"], ["pre_risk_score", "post_risk_score"]
    ):
        with column:
            score_card(
                title,
                row.get(field),
                verified=field == "pre_risk_score" or bool(row.get("residual_verified")),
            )
    with st.expander("View scoring rubrics"):
        st.write(
            (
                "Likelihood × impact; both inputs are 1–5. Current thresholds: 1–4"
                " Low, 5–9 Medium, 10–16 High, 17–25 Critical. Missing ratings are"
                " not assessed."
            )
        )
        st.caption(
            (
                "Document organization-specific likelihood and financial/business "
                "impact definitions in your risk methodology; these labels are not"
                " prescribed ISO scoring rules."
            )
        )
    with st.expander("Risk details and related records"):
        st.write(
            {
                "Risk ID": ref,
                "Updated": str(row.get("updated_at", "")),
                "Category": meta.get("category", ""),
                "Impacted asset / activity": row.get("asset", ""),
                "Source": "Canonical risk register",
            }
        )
        st.caption("Linked control IDs and treatment actions appear in the assessment below.")
    st.caption(
        (
            "Ratings use the existing 1–5 scale. Record your organization’s "
            "likelihood and impact rationale. Proposed residual scores remain "
            "unverified until evidence is reviewed."
        )
    )
    with st.form(key + "assessment"):
        edit = dict(row)
        left, right = st.columns(2)
        with left:
            for field, label in [
                ("asset", "Asset / business activity"),
                ("threat", "Scenario / threat"),
                ("vulnerability", "Vulnerability"),
                ("risk_owner", "Risk owner"),
                ("existing_controls", "Existing controls"),
            ]:
                edit[field] = st.text_area(label, value=str(row.get(field) or ""))
            edit["asset_group"] = st.selectbox(
                "Asset group",
                ASSET_GROUPS,
                index=(
                    list(ASSET_GROUPS).index(row.get("asset_group"))
                    if row.get("asset_group") in ASSET_GROUPS
                    else 0
                ),
            )
            for prefix, label in [("pre", "Inherent"), ("post", "Proposed residual")]:
                for measure in ("likelihood", "impact"):
                    field = f"{prefix}_{measure}"
                    options = [None, 1, 2, 3, 4, 5]
                    edit[field] = st.selectbox(
                        f"{label} {measure}",
                        options,
                        index=options.index(row.get(field)) if row.get(field) in options else 0,
                        format_func=lambda value: "Not assessed" if value is None else str(value),
                    )
                    rationale = field + "_rationale"
                    edit[rationale] = st.text_input(
                        f"{label} {measure} rationale", value=str(row.get(rationale) or "")
                    )
        with right:
            choices = ["Modify", "Accept", "Avoid", "Transfer / Share"]
            edit["treatment_option"] = st.selectbox(
                "Treatment option",
                choices,
                index=(
                    choices.index(row.get("treatment_option"))
                    if row.get("treatment_option") in choices
                    else 0
                ),
            )
            for field, label in [
                ("treatment_action", "Treatment action"),
                ("treatment_action_owner", "Action owner"),
                ("treatment_action_timescale", "Timescale"),
                ("treatment_action_progress", "Progress"),
                ("comments", "Assessment notes"),
            ]:
                edit[field] = st.text_area(label, value=str(row.get(field) or ""))
            refs = row.get("control_references") or []
            edit["control_references"] = st.text_input(
                "Control references (comma separated)",
                value=", ".join(refs) if isinstance(refs, list) else str(refs),
            )
            states = ["Not Started", "In Progress", "Completed", "Rejected", "Accepted risk"]
            edit["treatment_action_status"] = st.selectbox(
                "Treatment status",
                states,
                index=(
                    states.index(row.get("treatment_action_status"))
                    if row.get("treatment_action_status") in states
                    else 0
                ),
            )
        submit = st.form_submit_button("Save assessment draft", disabled=role not in EDITORS)
    if submit:
        try:
            _save(client, edit, actor, int(row.get("revision", 0)))
        except (*ERRORS, ValueError) as exc:
            st.error(str(exc))
        else:
            st.rerun()
    if not row.get("revision"):
        st.info("Save the assessment before assigning review details and actions.")
        return
    group_names = {
        "default": "Default scenario register",
        **{g["record_key"]: g["payload"]["name"] for g in groups},
    }
    with st.form(key + "review"):
        group = st.selectbox(
            "Scenario register",
            list(group_names),
            index=(
                list(group_names).index(meta.get("group"))
                if meta.get("group") in group_names
                else 0
            ),
            format_func=group_names.get,
        )
        category = st.text_input("Risk category", value=meta.get("category", ""))
        approver = st.text_input("Approver", value=meta.get("approver", ""))
        due = st.text_input("Next review (YYYY-MM-DD)", value=meta.get("review_due", ""))
        decision = st.selectbox(
            "Review action", ["Save draft", "Submit for review", "Approve submitted revision"]
        )
        confirmed = st.checkbox("I reviewed this saved risk assessment and its treatment decision.")
        submit_review = st.form_submit_button("Save review details", disabled=role not in EDITORS)
    if submit_review:
        try:
            if decision != "Save draft" and not confirmed:
                raise FoundationError("Confirm review of the saved assessment.")
            payload = {
                "risk_ref": ref,
                "group": group,
                "category": category,
                "approver": approver,
                "review_due": due,
                "review_state": {
                    "Save draft": "Draft",
                    "Submit for review": "In review",
                    "Approve submitted revision": "Approved",
                }[decision],
            }
            put_record(
                client,
                "risk_detail",
                str(ref),
                payload,
                actor=actor,
                expected=saved.get("revision", 0),
            )
        except (*ERRORS, ValueError) as exc:
            st.error(str(exc))
        else:
            st.rerun()
    with workflow_section("Add treatment action", "Assign the next treatment task and save it."):
        with st.form(key + "task"):
            title = st.text_input("Action title")
            owner = st.text_input("Assigned owner", value=row.get("risk_owner") or "")
            due = st.date_input("Due date")
            task_submit = st.form_submit_button("Add action", disabled=role not in EDITORS)
        if task_submit:
            try:
                put_record(
                    client,
                    "risk_task",
                    "",
                    {
                        "risk_ref": ref,
                        "title": title,
                        "owner": owner,
                        "due": due.isoformat(),
                        "status": "Not started",
                    },
                    actor=actor,
                )
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.rerun()


def render_risk_page_legacy(client: str) -> None:
    """Render overview, canonical risks, suggestion library and action tracking."""
    st.title("Risk")
    actor = current_actor()
    key = f"risk::{client}"
    try:
        rows = list_risk_register(client)
        groups = list_records(client, "risk_group")
        details = {r["record_key"]: r for r in list_records(client, "risk_detail")}
        tasks = list_records(client, "risk_task")
        role = get_workspace_role(client, actor)
    except ERRORS as exc:
        st.error(f"Risk workspace unavailable: {exc}")
        return
    if not role:
        st.info(
            (
                "Sign in or complete workspace Administrator setup in Client "
                "Workspace to access Risk."
            )
        )
        return
    signature = tuple((r["risk_ref"], r.get("revision")) for r in rows)
    if st.session_state.get(key + "report_revision") != signature:
        st.session_state.pop(key + "report", None)
        st.session_state[key + "report_revision"] = signature
    selected = st.session_state.get(key + "::selected")
    if selected is not None:
        row = next((r for r in rows if r["risk_ref"] == selected), {"risk_ref": selected})
        _detail(client, row, details, groups, role)
        return
    if pending := st.session_state.pop(key + "pending_page", None):
        st.session_state[key + "page"] = pending
    page = section_navigation(
        "Risk workspace",
        ["Overview", "Risks", "Risk library", "Action tracker"],
        default="Overview",
        key=key + "page",
    )
    with page.panel:
        if page == "Overview":
            a, b, c = st.columns(3)
            a.metric("Registered risks", len(rows))
            b.metric(
                "Pending review",
                sum(r["payload"].get("review_state") == "In review" for r in details.values()),
            )
            c.metric("Open actions", sum(r["payload"].get("status") != "Complete" for r in tasks))
            from securescope.ui.security_visuals import risk_matrix

            risk_matrix(rows, key=key + "matrix")
            st.subheader("Enterprise risk register")
            if st.button("Add your own risk", disabled=role not in EDITORS):
                st.session_state[key + "::selected"] = max([r["risk_ref"] for r in rows] or [0]) + 1
                st.rerun()
            snapshot = json.dumps(rows, default=str, indent=2).encode()
            st.download_button(
                "Download risk report (JSON)",
                snapshot,
                file_name="risk_register.json",
                mime="application/json",
            )
            if st.button("Save dated snapshot", disabled=role not in EDITORS):
                try:
                    put_record(
                        client,
                        "risk_snapshot",
                        "",
                        {"date": date.today().isoformat(), "risks": json.loads(snapshot)},
                        actor=actor,
                    )
                except ERRORS as exc:
                    st.error(str(exc))
                else:
                    st.success("Snapshot saved.")
            with st.expander("Generate assessment workbook"):
                if st.button("Prepare Excel report"):
                    from securescope.reporting.iso_assurance_export import (
                        build_iso_assurance_workbook,
                    )

                    st.session_state[key + "report"] = build_iso_assurance_workbook(
                        client_name=client, gap_rows=[], soa_rows=[], risks=rows
                    )
                if st.session_state.get(key + "report"):
                    st.download_button(
                        "Download assessment workbook",
                        st.session_state[key + "report"],
                        file_name="risk_assessment.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
            st.subheader("Scenario registers")
            if st.button("Manage register access"):
                render_register_access(client)
            default_count = sum(
                details.get(str(row["risk_ref"]), {}).get("payload", {}).get("group", "default")
                == "default"
                for row in rows
            )
            if st.button(f"Open Default · {default_count} scenarios"):
                st.session_state[key + "group_filter"] = "default"
                st.session_state[key + "pending_page"] = "Risks"
                st.rerun()
            st.caption(
                (
                    "Workspace Administrators manage registers. Contributors edit "
                    "assessments; read-only members view them."
                )
            )
            for group in groups:
                with st.container(border=True):
                    if st.button(
                        "Open " + group["payload"]["name"], key=key + "open" + group["record_key"]
                    ):
                        st.session_state[key + "group_filter"] = group["record_key"]
                        st.session_state[key + "pending_page"] = "Risks"
                        st.rerun()
                    with st.expander("Edit register details"):
                        name_edit = st.text_input(
                            "Register name",
                            value=group["payload"]["name"],
                            key=key + "name" + group["record_key"],
                        )
                        if st.button(
                            "Save register details",
                            key=key + "edit" + group["record_key"],
                            disabled=role != "Administrator",
                        ):
                            try:
                                put_record(
                                    client,
                                    "risk_group",
                                    group["record_key"],
                                    dict(group["payload"], name=name_edit.strip()),
                                    actor=actor,
                                    expected=group["revision"],
                                )
                            except ERRORS as exc:
                                st.error(str(exc))
                            else:
                                st.rerun()
                    st.caption(group["payload"].get("description", ""))
                    confirm = st.checkbox(
                        "Confirm deletion of this empty register",
                        key=key + group["record_key"] + "confirm",
                    )
                    if st.button(
                        "Delete register",
                        key=key + group["record_key"],
                        disabled=role != "Administrator" or not confirm,
                    ):
                        try:
                            delete_group(
                                client,
                                group["record_key"],
                                actor=actor,
                                expected=group["revision"],
                                confirmed=confirm,
                            )
                        except ERRORS as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()
            with st.form(key + "group"):
                name = st.text_input("New scenario register name")
                description = st.text_area("Register description")
                create = st.form_submit_button(
                    "Create scenario register", disabled=role != "Administrator"
                )
            if create:
                try:
                    put_record(
                        client,
                        "risk_group",
                        "",
                        {"name": name.strip(), "description": description},
                        actor=actor,
                    )
                except ERRORS as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
        elif page == "Risks":
            query = st.text_input("Search scenarios, assets or owners").casefold()
            group_names = {
                "all": "All registers",
                "default": "Default",
                **{g["record_key"]: g["payload"]["name"] for g in groups},
            }
            chosen_group = st.selectbox(
                "Register",
                list(group_names),
                index=(
                    list(group_names).index(st.session_state.get(key + "group_filter", "all"))
                    if st.session_state.get(key + "group_filter", "all") in group_names
                    else 0
                ),
                format_func=group_names.get,
            )
            owners = st.multiselect(
                "Owners", sorted({r.get("risk_owner") or "Unassigned" for r in rows})
            )
            states = st.multiselect("Review status", ["Draft", "In review", "Approved"])
            levels = st.multiselect(
                "Inherent risk level", ["Low", "Medium", "High", "Critical", "Not assessed"]
            )
            category_filter = st.text_input("Category contains").casefold()
            approver_filter = st.text_input("Approver contains").casefold()
            visible = []
            for original in rows:
                r = dict(original)
                meta = details.get(str(r["risk_ref"]), {}).get("payload", {})
                r["review_status"] = (
                    meta.get("review_state", "Draft")
                    if meta.get("reviewed_revision") == r.get("revision")
                    else "Draft"
                )
                r["category"] = meta.get("category", "")
                if (
                    query
                    not in " ".join(
                        str(r.get(k) or "") for k in ("threat", "asset", "risk_owner")
                    ).casefold()
                    or (chosen_group != "all" and meta.get("group", "default") != chosen_group)
                    or (owners and (r.get("risk_owner") or "Unassigned") not in owners)
                    or (states and r["review_status"] not in states)
                    or (levels and r.get("pre_risk_level") not in levels)
                    or category_filter not in r["category"].casefold()
                    or approver_filter not in meta.get("approver", "").casefold()
                ):
                    continue
                visible.append(r)
            if st.button("Add scenario", disabled=role not in EDITORS):
                st.session_state[key + "::selected"] = max([r["risk_ref"] for r in rows] or [0]) + 1
                st.rerun()
            if visible:
                from securescope.ui.components.risk_score import score_style

                event = st.dataframe(
                    pd.DataFrame(visible)[
                        [
                            "risk_ref",
                            "asset",
                            "threat",
                            "risk_owner",
                            "pre_risk_score",
                            "treatment_option",
                            "treatment_action_status",
                            "post_risk_score",
                            "review_status",
                            "category",
                        ]
                    ].style.map(score_style, subset=["pre_risk_score", "post_risk_score"]),
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                )
                if event.selection.rows:
                    st.session_state[key + "::selected"] = visible[event.selection.rows[0]][
                        "risk_ref"
                    ]
                    st.rerun()
            else:
                st.info(
                    "No matching risks. Add a scenario from Overview or tailor a library suggestion."
                )
        elif page == "Risk library":
            st.info("Examples are guidance. Tailor a suggestion before saving it as client data.")
            examples = starter_risks()
            index = st.selectbox(
                "Suggested scenario",
                range(len(examples)),
                format_func=lambda i: examples[i].get("threat", str(i)),
            )
            st.write(examples[index])
            if st.button("Use suggestion as a draft", disabled=role not in EDITORS):
                suggestion = dict(
                    examples[index], risk_ref=max([r["risk_ref"] for r in rows] or [0]) + 1
                )
                # Example measurements and ownership are not client assertions.
                for field in ("pre_likelihood", "pre_impact", "post_likelihood", "post_impact"):
                    suggestion[field] = None
                suggestion.update(risk_owner=actor, treatment_action_status="Not Started")
                try:
                    _save(client, suggestion, actor, 0)
                except (*ERRORS, ValueError) as exc:
                    st.error(str(exc))
                else:
                    st.session_state[key + "::selected"] = suggestion["risk_ref"]
                    st.rerun()
        else:
            if not tasks:
                st.info(
                    "No actions yet. Open a risk and add a treatment action with an owner and due date."
                )
            for task in tasks:
                payload = task["payload"]
                with st.container(border=True):
                    st.write(f"Risk {payload['risk_ref']} · {payload['title']}")
                    identity_context(payload["owner"], "Owner")
                    st.caption(f"Due {payload['due']}")
                    status = st.selectbox(
                        "Action status",
                        ["Not started", "In progress", "Complete"],
                        index=["Not started", "In progress", "Complete"].index(payload["status"]),
                        key=task["record_key"],
                    )
                    if st.button(
                        "Save action status",
                        key=task["record_key"] + "save",
                        disabled=role not in EDITORS,
                    ):
                        try:
                            put_record(
                                client,
                                "risk_task",
                                task["record_key"],
                                dict(payload, status=status),
                                actor=actor,
                                expected=task["revision"],
                            )
                        except ERRORS as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()


@st.dialog("Register access")
def render_register_access(client: str) -> None:
    """Show effective workspace grants and reuse controlled membership administration."""
    from securescope.persistence.foundation_repository import workspace_cursor
    from securescope.ui.grc_workspace.formal import render_membership_manager

    st.caption(
        (
            "These scenario registers inherit client workspace permissions. "
            "Changing a membership affects every register in this workspace."
        )
    )
    try:
        with workspace_cursor(client) as (cursor, client_id):
            cursor.execute(
                (
                    "SELECT u.email,m.role FROM securescope_workspace_memberships m "
                    "JOIN securescope_users u ON u.id=m.user_id WHERE m.client_id=%s "
                    "AND m.active AND u.active ORDER BY u.email"
                ),
                (client_id,),
            )
            grants = [dict(row) for row in cursor.fetchall()]
        st.dataframe(grants, hide_index=True)
        render_membership_manager(client, current_actor())
    except ERRORS as exc:
        st.error(str(exc))


def render_risk_page(client: str) -> None:
    """Open the custom workbench over the existing authorized repositories."""
    from securescope.ui.risk_management import render_risk_management

    render_risk_management(client)
