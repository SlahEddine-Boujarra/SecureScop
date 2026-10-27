"""Trusted adapters for the isolated policy and risk browser workbenches."""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from datetime import date

import streamlit as st

from securescope.integrations.credential_store import CredentialStoreError
from securescope.persistence.foundation_repository import (
    FoundationError,
    member_role,
    workspace_cursor,
)
from securescope.persistence.grc_repository import list_control_overview
from securescope.persistence.grc_workspace_repository import list_workspace_members
from securescope.persistence.workspace_planning import (
    EDITORS,
    delete_group,
    list_records,
    put_record,
)
from securescope.policies.repository import (
    PolicyError,
    document_payload,
    load_policies,
    policy_rows,
    save_policy,
    upload_policy,
)
from securescope.policies.suggestions import TOPICS, policy_template, section_choices
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role

EXPECTED_ERRORS = (*ERRORS, PolicyError, CredentialStoreError, ValueError, TypeError, KeyError)


def _members(client):
    return [
        dict(email=r["email"], role=r["workspace_role"]) for r in list_workspace_members(client)
    ]


def _public_policy(row, *, content=False):
    result = {
        k: v
        for k, v in row.items()
        if k not in {"document_ciphertext", "policy_text", "source_base64"}
    }
    result.setdefault("controls", [])
    result["approvers"] = result.get("approvers") or (
        [result["reviewer"]] if result.get("reviewer") else []
    )
    approved = len(result.get("approvals", {}))
    count = len(result["approvers"])
    result["approval_label"] = f"{approved}/{count} approved" if count else "Not assigned"
    result["overall"] = (
        (
            "Expired"
            if result.get("review_date") and result["review_date"] < date.today().isoformat()
            else "OK"
        )
        if result.get("status") == "Approved"
        else "Needs remediation"
    )
    if content:
        payload = document_payload(row)
        result["blocks"] = payload["blocks"]
        result["reviewed_sections"] = payload.get("reviewed_sections", {})
    return result


def _event(result, key):
    event = getattr(result, "action", None)
    if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
        return None
    nonce = event.get("nonce")
    if (
        not isinstance(nonce, str)
        or len(nonce) > 100
        or nonce == st.session_state.get(key + ":handled")
    ):
        return None
    st.session_state[key + ":handled"] = nonce
    return event


def _show_download(key):
    if artifact := st.session_state.get(key + ":download"):
        st.download_button(
            "Download generated document",
            artifact["content"],
            file_name=artifact["name"],
            mime=artifact["mime"],
            key=key + ":download_button",
        )


def render_policy_workbench(client, context):
    scope = context.get("selected_scope_id")
    if not scope:
        st.info("Create or select an ISMS scope before managing policies.")
        return
    engagement, scope = int(context["selected_engagement_id"]), int(scope)
    key = f"policies::{client}::{engagement}::{scope}"
    actor = current_actor()
    try:
        role = get_workspace_role(client, actor)
        if not role:
            st.info(
                (
                    "Sign in or complete Administrator setup in Client Workspace "
                    "to access Policies."
                )
            )
            return
        rows, history = load_policies(client, engagement, scope)
        pending_key = f"policy_requirement_create::{client}::{engagement}::{scope}"
        pending = st.session_state.get(pending_key)
        if pending and role in EDITORS:
            from securescope.persistence.assurance_workspace_repository import load_workspace
            from securescope.ui.control_workspace import _policy_draft

            view = load_workspace(client, pending["control_id"], actor, engagement, scope)
            criterion = next(
                (r for r in view["result"]["requirements"] if r["id"] == pending["requirement_id"]),
                None,
            )
            if criterion:
                st.caption("Create a canonical policy draft for the selected control requirement.")
                if st.button("Cancel policy draft", key=pending_key + "::cancel"):
                    st.session_state.pop(pending_key, None)
                    st.rerun()
                _policy_draft(client, pending["control_id"], view, pending_key, criterion)
                return
            st.session_state.pop(pending_key, None)
        revision = int(history[0]["version"]) if history else 0
        controls = list_control_overview(client)
        selected = st.session_state.get(key + "::selected")
        stored = next((r for r in rows if r["policy_id"] == selected), None)
        detail = _public_policy(stored, content=True) if stored else None
        mode = (
            "policy_" + ("builder" if st.session_state.get(key + ":builder") else "detail")
            if detail
            else "policy_list"
        )
        data = dict(
            mode=mode,
            selected=selected,
            revision=revision,
            detail=detail,
            rows=[_public_policy(r) for r in rows if r.get("status") != "Archived"],
            actor=actor,
            is_admin=role == "Administrator",
            can_edit=role in EDITORS,
            members=_members(client),
            controls=controls,
            templates=list(TOPICS),
            response=st.session_state.get(key + ":response"),
            approved=None,
            audits=[],
            links=[],
            comments=[],
            guidance={},
            default_guidance=section_choices(""),
        )
        if detail:
            from securescope.persistence.assurance_workspace_repository import (
                policy_control_references,
            )

            detail["controls"] = list(
                dict.fromkeys(
                    [
                        *detail.get("controls", []),
                        *policy_control_references(client, actor, engagement, scope, selected),
                    ]
                )
            )
            identity = dict(policy_id=selected, engagement=engagement, scope=scope)
            for kind, target in [("policy_comment", "comments"), ("policy_audit", "links")]:
                data[target] = [
                    r
                    for r in list_records(client, kind)
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
                data["audits"] = [dict(r) for r in cursor.fetchall()]
            approved = next(
                (
                    r
                    for h in history
                    for r in policy_rows(h, scope)
                    if r["policy_id"] == selected and r.get("status") == "Approved"
                ),
                None,
            )
            data["approved"] = _public_policy(approved, content=True) if approved else None
            data["guidance"] = {
                "".join(r["text"] for r in b["runs"]): section_choices(
                    "".join(r["text"] for r in b["runs"])
                )
                for b in detail["blocks"]
                if b["kind"].startswith("h")
            }
        event = _event(
            assurance_workbench(json.loads(json.dumps(data, default=str)), key=key + ":workbench"),
            key,
        )
        if not event:
            return
        response = {"nonce": event["nonce"]}
        try:
            download = dispatch_policy(client, engagement, scope, actor, rows, revision, key, event)
            if download:
                response["download"] = download
            response["message"] = {
                "policy_save": "Policy draft saved.",
                "policy_metadata": "Policy details saved.",
                "policy_submit": "Policy submitted for review.",
                "policy_approve": "Policy approval recorded.",
                "template": "Policy draft created.",
                "upload": "Policy uploaded.",
                "comment": "Comment saved.",
                "link_audit": "Audit link saved.",
                "delete": "Policy removed.",
            }.get(event["action"], "")
        except EXPECTED_ERRORS as exc:
            response["error"] = "Policy operation failed: " + str(exc)
        st.session_state[key + ":response"] = response
    except EXPECTED_ERRORS as exc:
        st.error(f"Policies unavailable: {exc}")
        return
    st.rerun()


def dispatch_policy(client, engagement, scope, actor, rows, revision, key, event):
    action, p = event["action"], event["payload"]
    selected = st.session_state.get(key + "::selected")
    if event.get("selected") != selected:
        raise PolicyError("The selected policy changed. Reload before acting.")
    stored = next((r for r in rows if r["policy_id"] == selected), None)
    if action == "open_control":
        policy = next(
            (r for r in rows if r["policy_id"] == st.session_state.get(key + "::selected")), {}
        )
        from securescope.persistence.assurance_workspace_repository import policy_control_references

        linked = set(policy.get("controls", [])) | set(
            policy_control_references(client, actor, engagement, scope, policy.get("policy_id", ""))
        )
        if p.get("control_id") not in linked:
            raise PolicyError("Control is not linked to this policy.")
        from securescope.ui.control_workspace import open_control_workspace

        open_control_workspace(client, p["control_id"])
        return
    if action == "open":
        if not any(r["policy_id"] == p.get("id") for r in rows):
            raise PolicyError("Policy not found in this scope.")
        st.session_state[key + "::selected"] = p["id"]
        st.session_state[key + ":builder"] = False
        st.session_state.pop(key + ":download", None)
        return
    if action in {"back", "detail", "edit"}:
        if action == "back":
            st.session_state.pop(key + "::selected", None)
        st.session_state[key + ":builder"] = action == "edit"
        return
    if event.get("expected") != revision:
        raise PolicyError("Policies changed in another session. Reload before saving.")
    if action == "template":
        draft = policy_template(str(p.get("name", "")), client)
        known = {c["control_id"] for c in list_control_overview(client)}
        policy_id = str(uuid.uuid4())
        save_policy(
            client,
            engagement,
            scope,
            actor=actor,
            policy_id=policy_id,
            expected_version=revision,
            status="Draft",
            note="Created a tailored starter draft for human review.",
            metadata=dict(
                draft, owner=actor, controls=[c for c in draft["controls"] if c in known]
            ),
            blocks=draft["blocks"],
        )
        st.session_state[key + "::selected"] = policy_id
        return
    if action == "upload":
        content = decode_upload(p)
        st.session_state[key + "::selected"] = upload_policy(
            client,
            engagement,
            scope,
            actor=actor,
            expected_version=revision,
            filename=p["filename"],
            content=content,
        )
        return
    if not stored:
        raise PolicyError("Select a saved policy.")
    identity = dict(policy_id=selected, engagement=engagement, scope=scope)
    if action == "comment":
        put_record(
            client,
            "policy_comment",
            "",
            dict(identity, body=str(p.get("body", "")), parent=p.get("parent", "")),
            actor=actor,
        )
    elif action == "link_audit":
        put_record(
            client, "policy_audit", "", dict(identity, audit_id=int(p["audit_id"])), actor=actor
        )
    elif action == "export":
        from securescope.reporting.policy_docx import policy_docx
        from securescope.reporting.policy_export import policy_pdf

        kind = p.get("format")
        if kind not in {"pdf", "docx"}:
            raise PolicyError("Unsupported export format.")
        from reportlab.platypus.doctemplate import LayoutError

        try:
            content = (policy_docx if kind == "docx" else policy_pdf)(
                stored, document_payload(stored)["blocks"]
            )
        except (OSError, ValueError, LayoutError) as exc:
            logging.getLogger(__name__).exception("Policy %s export failed", kind)
            label = "Word" if kind == "docx" else "PDF"
            raise PolicyError(f"{label} export could not be generated.") from exc
        name = (
            re.sub(r"[^A-Za-z0-9_-]+", "_", str(stored.get("title") or "Policy")).strip("_")[:120]
            or "Policy"
        )
        return dict(
            content_base64=base64.b64encode(content).decode("ascii"),
            filename=f'{name}_v{stored["policy_version"]}.{kind}',
            mime=(
                "application/pdf"
                if kind == "pdf"
                else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
        )
    elif action in {
        "policy_save",
        "policy_metadata",
        "policy_submit",
        "policy_approve",
        "policy_archive",
    }:
        statuses = dict(
            policy_save="Draft",
            policy_metadata="Draft",
            policy_submit="In review",
            policy_approve="Approved",
            policy_archive="Archived",
        )
        metadata = p if action == "policy_submit" else p.get("metadata", {})
        blocks = (
            p.get("blocks")
            if action == "policy_save"
            else document_payload(stored)["blocks"] if action == "policy_metadata" else None
        )
        save_policy(
            client,
            engagement,
            scope,
            actor=actor,
            policy_id=selected,
            expected_version=event["expected"],
            status=statuses[action],
            note=str(p.get("note") or "Policy " + action.removeprefix("policy_")),
            metadata=metadata,
            blocks=blocks,
        )
        st.session_state.pop(key + ":download", None)
    else:
        raise PolicyError("Unsupported policy action.")


def decode_upload(payload):
    value = payload.get("content", "")
    if not isinstance(value, str) or len(value) > 2_800_000:
        raise ValueError("Upload exceeds 2 MiB.")
    content = base64.b64decode(value, validate=True)
    if len(content) > 2 * 1024 * 1024:
        raise ValueError("Upload exceeds 2 MiB.")
    return content


def render_risk_workbench(
    client, *, lifecycle="Registers & assessment", scope_filter="All client risks", scope_id=None
):
    from securescope.grc.risk_lifecycle import EXTRA_FIELDS, scoring_view
    from securescope.grc.risk_register import ASSET_GROUPS, starter_risks
    from securescope.persistence.risk_register_repository import list_risk_register
    from securescope.ui.design_system.tokens import DESIGN_TOKENS

    actor, key = current_actor(), f"risk::{client}"
    try:
        role = get_workspace_role(client, actor)
        if not role:
            st.info("Sign in or complete Administrator setup in Client Workspace to access Risk.")
            return
        rows = list_risk_register(client)
        details = {r["record_key"]: r for r in list_records(client, "risk_detail")}
        groups = [
            dict(
                record_key="default",
                revision=0,
                payload=dict(name="Default", description="Default risk register"),
            )
        ] + list_records(client, "risk_group")
        merged = []
        for r in rows:
            meta = details.get(str(r["risk_ref"]), {}).get("payload", {})
            merged.append(
                dict(
                    r,
                    **{
                        name: meta[name]
                        for name in EXTRA_FIELDS
                        if name in meta and name != "category"
                    },
                    completion_state=(
                        meta.get("completion_state", "Draft")
                        if meta.get("completed_revision") == r.get("revision")
                        else "Draft"
                    ),
                    meta_revision=details.get(str(r["risk_ref"]), {}).get("revision", 0),
                    group=meta.get("group", "default"),
                    asset_ids=meta.get("asset_ids", []),
                    asset_ips=meta.get("asset_ips", None),
                    category=meta.get("category", ""),
                    approver=meta.get("approver", ""),
                    review_due=meta.get("review_due", ""),
                    review_state=(
                        meta.get("review_state", "Draft")
                        if meta.get("reviewed_revision") == r.get("revision")
                        else "Draft"
                    ),
                )
            )
        selected = st.session_state.get(key + "::selected")
        detail = next((r for r in merged if r["risk_ref"] == selected), None)
        if not detail and selected is not None:
            detail = st.session_state.get(key + ":new")
        mode = (
            "risk_detail"
            if detail
            else "risk_table" if st.session_state.get(key + ":group") else "risk_overview"
        )
        revision = detail.get("revision", 0) if detail else 0
        if not detail and lifecycle != "Registers & assessment":
            mode = "risk_table"
        from securescope.grc.scope_workflow import filter_scope_risks
        from securescope.persistence.risk_links import risk_scope_options

        if (
            mode == "risk_overview"
            and scope_filter == "Current ISMS Scope"
            and not filter_scope_risks(merged, scope_filter, scope_id)
        ):
            unassigned = filter_scope_risks(merged, "Unassigned scope", scope_id)
            st.info(f"No risks are currently assigned to ISMS Scope #{scope_id}.")
            if unassigned:
                st.caption(f"{len(unassigned)} unassigned client risks exist.")
                if st.button("View Unassigned Risks", key=key + "::unassigned"):
                    st.session_state[f"risk_scope_filter::{client}::pending"] = "Unassigned scope"
                    st.rerun()
        data = dict(
            lifecycle=lifecycle,
            scopes=risk_scope_options(client, actor),
            scoring=scoring_view(),
            risk_colors={
                "Low": DESIGN_TOKENS.success,
                "Medium": DESIGN_TOKENS.warning,
                "High": DESIGN_TOKENS.danger,
                "Critical": DESIGN_TOKENS.danger,
            },
            show_register_creation=lifecycle == "Registers & assessment",
            mode=mode,
            selected=selected,
            revision=revision,
            detail=detail,
            rows=filter_scope_risks(merged, scope_filter, scope_id),
            groups=groups,
            group=(
                st.session_state.get(key + ":group", "all")
                if lifecycle == "Registers & assessment"
                else "all"
            ),
            owned=st.session_state.get(key + ":owned", False),
            actor=actor,
            members=_members(client),
            can_edit=role in EDITORS,
            is_admin=role == "Administrator",
            controls=list_control_overview(client),
            asset_groups=list(ASSET_GROUPS),
            templates=starter_risks(),
            response=st.session_state.get(key + ":response"),
            comments=[],
            reviews=[],
            tasks=[],
        )
        from securescope.persistence.risk_links import discovered_assets

        data["assets"] = discovered_assets(client, actor) if detail else []
        if detail and detail.get("asset_ips") is not None:
            detail["asset_ids"] = [
                a["id"] for a in data["assets"] if a["ip"] in detail["asset_ips"]
            ]
            detail["missing_asset_ips"] = [
                ip for ip in detail["asset_ips"] if ip not in {a["ip"] for a in data["assets"]}
            ]
        data["inventory_signature"] = [(a["id"], a["ip"]) for a in data["assets"]]
        if detail and revision:
            for kind, target in [
                ("risk_comment", "comments"),
                ("risk_review", "reviews"),
                ("risk_task", "tasks"),
            ]:
                data[target] = [
                    r
                    for r in list_records(client, kind)
                    if r["payload"].get("risk_ref") == selected
                ]
        event = _event(
            assurance_workbench(json.loads(json.dumps(data, default=str)), key=key + ":workbench"),
            key,
        )
        _show_download(key)
        if preview := st.session_state.get(key + ":import"):
            st.info(
                (
                    "Preview: new rows only, in the register selected when you "
                    "uploaded. Existing references are rejected. No rows have been "
                    "written."
                )
            )
            st.dataframe(preview, hide_index=True)
            if st.button(
                "Confirm import of these rows",
                key=key + ":confirm_import",
                disabled=role not in EDITORS,
            ):
                commit_risk_import(
                    client,
                    actor,
                    preview,
                    group=st.session_state.get(key + ":import_group", "default"),
                )
                st.session_state.pop(key + ":import", None)
                st.rerun()
        if not event:
            return
        response = {"nonce": event["nonce"]}
        try:
            if lifecycle != "Registers & assessment" and event["action"] in {
                "risk_new",
                "risk_template",
                "import_preview",
                "group_save",
                "group_delete",
            }:
                raise FoundationError("Create and manage registers in Registers & assessment.")
            dispatch_risk(
                client,
                actor,
                key,
                event,
                rows,
                details,
                groups,
                detail,
                current_scope_id=scope_id if scope_filter == "Current ISMS Scope" else None,
            )
            response["message"] = (
                "Assessment completed. Approval and formal acceptance remain separate."
                if event["action"] == "risk_complete"
                else risk_action_message(event["action"], lifecycle)
            )
        except EXPECTED_ERRORS as exc:
            response["error"] = f"Risk operation {event['action'].replace('_', ' ')} failed: {exc}"
        st.session_state[key + ":response"] = response
    except EXPECTED_ERRORS as exc:
        st.error(f"Risk workspace unavailable: {exc}")
        return
    st.rerun()


def dispatch_risk(
    client, actor, key, event, rows, details, groups, detail, *, current_scope_id=None
):
    from securescope.grc.risk_register import starter_risks

    action, p = event["action"], event["payload"]
    selected = st.session_state.get(key + "::selected")
    if event.get("selected") != selected:
        raise FoundationError("The selected risk changed. Reload before acting.")
    if action == "open_control":
        if p.get("control_id") not in (detail or {}).get("control_references", []):
            raise FoundationError("Control is not linked to this saved risk.")
        from securescope.ui.control_workspace import open_control_workspace

        open_control_workspace(client, p["control_id"])
        return
    if action == "open":
        if not any(r["risk_ref"] == p.get("id") for r in rows):
            raise FoundationError("Select a risk in this workspace.")
        st.session_state[key + "::selected"] = p["id"]
        return
    if action in {"back", "register"}:
        st.session_state.pop(key + "::selected", None)
        if action == "back":
            st.session_state.pop(key + ":group", None)
            st.session_state[f"risk_management::{client}::pending"] = "Registers & assessment"
        else:
            group = p.get("group", st.session_state.get(key + ":group", "default"))
            if group not in {"all", *(g["record_key"] for g in groups)}:
                raise FoundationError("Select an existing register.")
            st.session_state[key + ":group"] = group
            st.session_state[key + ":owned"] = bool(p.get("owned", False))
        return
    if action in {"risk_new", "risk_template"}:
        ref = max([r["risk_ref"] for r in rows] or [0]) + 1
        draft = starter_risks()[int(p["index"])] if action == "risk_template" else {}
        draft = dict(
            draft,
            risk_ref=ref,
            revision=0,
            risk_owner=actor,
            primary_scope_id=current_scope_id,
            group=(
                st.session_state.get(key + ":group", "default")
                if st.session_state.get(key + ":group") != "all"
                else "default"
            ),
            asset_ids=[],
            review_state="Draft",
            control_references=draft.get("control_references", []),
        )
        st.session_state[key + ":new"] = draft
        st.session_state[key + "::selected"] = ref
        return
    if action == "group_save":
        saved_group = put_record(
            client,
            "risk_group",
            str(p.get("key", "")),
            dict(name=str(p["name"]), description=str(p.get("description", ""))),
            actor=actor,
            expected=int(p.get("revision", 0)),
        )
        st.session_state[key + ":group"] = saved_group
        st.session_state.pop(key + "::selected", None)
        return
    if action == "group_delete":
        delete_group(
            client,
            str(p["key"]),
            actor=actor,
            expected=int(p["revision"]),
            confirmed=p.get("confirmed") is True,
        )
        return
    if action == "snapshot":
        put_record(
            client, "risk_snapshot", "", dict(notes=str(p.get("note", "")), risks=rows), actor=actor
        )
        return
    if action == "risk_export":
        st.session_state[key + ":download"] = dict(
            content=json.dumps(rows, default=str, indent=2).encode(),
            name="Risk_assessment_data.json",
            mime="application/json",
        )
        return
    if action == "import_preview":
        from securescope.grc.document_registers import normalize_register_rows

        content = json.loads(decode_upload(p))
        if not isinstance(content, list) or len(content) > 500:
            raise ValueError("Import requires a JSON array of up to 500 rows.")
        content = [
            dict(r, residual_verified=False, residual_evidence="", residual_verified_by="")
            for r in content
        ]
        clean = normalize_register_rows("asset_risks", content)
        existing = {r["risk_ref"] for r in rows}
        if any(r["risk_ref"] in existing for r in clean):
            raise ValueError(
                "An imported reference already exists. This import only creates new records."
            )
        st.session_state[key + ":import"] = clean
        selected_group = st.session_state.get(key + ":group", "default")
        st.session_state[key + ":import_group"] = (
            "default" if selected_group == "all" else selected_group
        )
        return
    if not detail or event.get("expected") != detail.get("revision", 0):
        raise FoundationError("The assessment changed. Reload before acting.")
    if action in {"risk_save", "risk_complete"}:
        record = dict(p["record"], risk_ref=selected)
        from securescope.persistence.risk_links import save_assessment

        group = str(p["record"].get("group") or detail.get("group") or "default")
        save_assessment(
            client,
            record,
            actor=actor,
            revision=event["expected"],
            group=group,
            metadata_revision=event.get("meta_expected", 0),
            asset_ids=p["record"].get("asset_ids", detail.get("asset_ids", [])),
            complete=action == "risk_complete",
        )
        st.session_state.pop(key + ":new", None)
        st.session_state.pop(key + ":download", None)
        return
    if not detail.get("revision"):
        raise FoundationError(
            "Save the scenario before adding related records or requesting approval."
        )
    if action == "comment":
        put_record(
            client,
            "risk_comment",
            "",
            dict(risk_ref=selected, body=str(p.get("body", "")), parent=p.get("parent", "")),
            actor=actor,
        )
    elif action == "task_save":
        task_key = str(p.get("key", ""))
        if task_key and not any(
            r["record_key"] == task_key and r["payload"].get("risk_ref") == selected
            for r in list_records(client, "risk_task")
        ):
            raise FoundationError("Select a task from this scenario.")
        put_record(
            client,
            "risk_task",
            task_key,
            {k: p.get(k, "") for k in ["title", "owner", "status", "due"]}
            | dict(risk_ref=selected),
            actor=actor,
            expected=int(p.get("revision", 0)),
        )
    elif action in {"risk_metadata", "risk_submit", "risk_approve"}:
        saved = details.get(str(selected), {})
        if event.get("meta_expected", 0) != int(saved.get("revision", 0)):
            raise FoundationError("Risk review metadata changed. Reload before acting.")
        meta = dict(
            saved.get("payload", {}), risk_ref=selected, expected_risk_revision=event["expected"]
        )
        if action == "risk_metadata":
            meta.update(group=p["group"], category=str(p.get("category", "")), review_state="Draft")
        elif action == "risk_submit":
            meta.update(
                approver=p["approver"], review_due=p.get("review_due", ""), review_state="In review"
            )
        else:
            meta.update(review_state="Approved", notes=str(p.get("note", "")))
        put_record(
            client,
            "risk_detail",
            str(selected),
            meta,
            actor=actor,
            expected=int(saved.get("revision", 0)),
        )
    else:
        raise FoundationError("Unsupported risk action.")


def commit_risk_import(client, actor, rows, *, group="default"):
    """Commit new risks and selected-register placement atomically; reject stale refs."""
    from securescope.persistence.risk_register_repository import save_risk_records

    def authorize(cursor, client_id):
        if member_role(cursor, client_id, actor) not in EDITORS:
            raise FoundationError("Contributor membership is required.")
        if group != "default":
            cursor.execute(
                (
                    "SELECT 1 FROM securescope_workspace_records WHERE client_id=%s "
                    "AND kind='risk_group' AND record_key=%s"
                ),
                (client_id, group),
            )
            if not cursor.fetchone():
                raise FoundationError("The selected register no longer exists.")
        cursor.execute(
            "SELECT control_id FROM securescope_control_assessment_profiles WHERE client_id=%s",
            (client_id,),
        )
        known = {r["control_id"] for r in cursor.fetchall()}
        if any(not set(r.get("control_references") or []).issubset(known) for r in rows):
            raise FoundationError("Imported controls must belong to the workspace catalog.")

    def after_save(cursor, client_id, revisions):
        """Place every imported scenario before the transaction is committed."""
        from psycopg2.extras import Json

        for ref, revision in revisions.items():
            cursor.execute(
                (
                    "INSERT INTO securescope_workspace_records "
                    "(client_id,kind,record_key,payload,updated_by) VALUES "
                    "(%s,'risk_detail',%s,%s,%s)"
                ),
                (
                    client_id,
                    str(ref),
                    Json(
                        dict(
                            risk_ref=ref,
                            group=group,
                            review_state="Draft",
                            reviewed_revision=revision,
                        )
                    ),
                    actor,
                ),
            )

    save_risk_records(
        client,
        rows,
        actor=actor,
        expected_revisions={r["risk_ref"]: 0 for r in rows},
        authorize=authorize,
        after_save=after_save,
    )


def risk_action_message(action: str, lifecycle: str) -> str:
    """Describe a completed risk operation without implying formal acceptance.

    Args:
        action: Existing component event name.
        lifecycle: Active risk workflow stage.
    Returns:
        str: Context-specific feedback, empty for navigation-only events.
    Raises:
        No exceptions are raised.
    """
    if action == "risk_save":
        return {
            "Treatment plan": "Risk treatment updated.",
            "Residual assessment": "Residual assessment saved.",
        }.get(lifecycle, "Risk scenario saved.")
    return {
        "group_save": "Risk register saved.",
        "group_delete": "Risk register removed.",
        "task_save": "Treatment task saved.",
        "comment": "Risk comment saved.",
        "risk_submit": "Risk assessment submitted for review.",
        "risk_approve": "Risk assessment approved; formal acceptance remains separate.",
    }.get(action, "")
