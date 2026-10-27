"""Stitch-inspired formal-register presentation using existing record workflows."""

from __future__ import annotations

import json
import logging
from datetime import date

import streamlit as st

from securescope.ui.workflow_sections import back_link

from securescope.grc.formal_registers import FIELDS
from securescope.persistence.foundation_repository import FoundationError, save_version, versions
from securescope.persistence.workspace_planning import EDITORS
from securescope.ui.assurance_workbench import _event
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role

LOGGER = logging.getLogger(__name__)
CONFIG = {
    "context": (
        "Context of the Organization (Clause 4.1)",
        "Internal and external factors influencing ISMS objectives.",
        "context_issues",
        "Add issue",
        {
            "title": "Issue",
            "issue_type": "Type",
            "relevance": "Relevance",
            "owner": "Owner",
            "status": "Status",
        },
        "issue_type",
    ),
    "parties": (
        "Interested Parties (Clause 4.2)",
        "Stakeholders, their needs and the requirements relevant to your ISMS.",
        "interested_parties",
        "Add interested party",
        {
            "name": "Interested party",
            "party_type": "Type",
            "needs_and_expectations": "Needs and expectations",
            "applicable_requirement_count": "Requirements",
            "owner": "Owner",
            "status": "Status",
        },
        "party_type",
    ),
    "roles": (
        "Roles & RACI",
        "Accountable people and their information security responsibilities.",
        "role_assignments",
        "Assign responsibility",
        {
            "role_name": "ISMS role",
            "raci_type": "RACI",
            "display_name": "Person",
            "responsibility": "Responsibility",
            "status": "Status",
        },
        "raci_type",
    ),
    "scope": (
        "ISMS Scope",
        "Boundaries, applicability and the formal scope statement.",
        "organizational_units",
        "Add boundary",
        {
            "name": "Boundary / unit",
            "unit_type": "Category",
            "description": "Description",
            "location": "Location",
            "owner": "Owner",
        },
        "unit_type",
    ),
    "objectives": (
        "Information Security Objectives (Clause 6.2)",
        "Measurable targets, accountable owners and delivery plans.",
        "objectives",
        "Add objective",
        {
            "title": "Objective",
            "measure": "Measure",
            "baseline": "Baseline",
            "target": "Target",
            "due_date": "Due date",
            "owner": "Owner",
        },
        "",
    ),
}


def render_stitch_records(client: str, context: dict, section: str, registers: dict) -> bool:
    """Render a compact table and detail drawer for a formal register.

    Args:
        client: Active client workspace.
        context: Selected engagement and scope.
        section: Configured formal-register key.
        registers: Existing service data for this section.
    Returns:
        False; navigation and dialogs are handled through explicit session state.
    Raises:
        Unexpected errors propagate; known persistence failures are displayed.
    """
    from securescope.ui.grc_workspace import dialogs

    actor = current_actor()
    engagement = int(context["selected_engagement_id"])
    scope = context.get("selected_scope_id")
    key = f"stitch::{client}::{engagement}::{scope}::{section}"
    title, description, collection, add_label, columns, filter_key = CONFIG[section]
    try:
        role = get_workspace_role(client, actor)
        if not role:
            st.info("Sign in or complete Administrator setup to access formal records.")
            return False
        history = (
            versions(client, engagement, int(scope), "objectives")
            if section == "objectives" and scope
            else []
        )
        latest = history[0] if history else {}
        revision = int(latest.get("version", 0))
        rows = (
            list(latest.get("records", []))
            if section == "objectives"
            else list(registers.get(collection, []))
        )
        prepared = [dict(r, _row_key=str(r.get("id", i)), _index=i) for i, r in enumerate(rows)]
        selected_scope = next((r for r in context.get("scopes", []) if r["id"] == scope), None)
        tool_state = st.session_state.get(key + ":tool")
        if tool_state:
            from securescope.ui.grc_workspace.record_tools import render_record_tools

            if back_link("Register", key=key + ":back"):
                st.session_state.pop(key + ":tool", None)
                st.rerun()
            render_record_tools(
                client, context, section, registers, tool_state["tool"], tool_state.get("id")
            )
            return False
        data = dict(
            mode="foundation",
            today=date.today().isoformat(),
            selected=section,
            revision=revision,
            actor=actor,
            title=title,
            description=description,
            rows=prepared,
            columns=columns,
            filter_key=filter_key,
            add_label=add_label,
            can_edit=role in EDITORS,
            section=section,
            scope=selected_scope if section == "scope" else None,
            fields=list(FIELDS["objectives"]) if section == "objectives" else [],
            register_status=latest.get("status", "Not started"),
            climate_status=(
                "Climate determination: "
                + str(registers["climate_determinations"][0].get("determination") or "Needs review")
                if registers.get("climate_determinations")
                else "Climate determination: Not recorded"
            ),
            response=st.session_state.get(key + ":response"),
        )
        action = _event(
            assurance_workbench(json.loads(json.dumps(data, default=str)), key=key), key
        )
        queued = st.session_state.pop(key + ":dialog", False)
        if queued:
            if section == "context":
                dialogs.render_context_issue_dialog(client, engagement, scope, actor)
            elif section == "parties":
                dialogs.render_interested_party_dialog(client, engagement, scope, actor)
            elif section == "roles":
                dialogs.render_raci_dialog(
                    client, engagement, scope, registers.get("workspace_members", []), actor
                )
            elif section == "scope":
                dialogs.render_organizational_unit_dialog(
                    client,
                    engagement,
                    scope,
                    rows,
                    actor,
                    default_type=(
                        "Site"
                        if isinstance(queued, dict)
                        and queued.get("boundary_type") == "Site / location"
                        else None
                    ),
                )
        if not action:
            return False
        response = {"nonce": action["nonce"]}
        st.session_state[key + ":response"] = response
        if action["action"] in {
            "foundation_tools",
            "foundation_review",
            "foundation_history",
            "foundation_edit",
        }:
            st.session_state[key + ":tool"] = {
                "tool": {"foundation_history": "history", "foundation_edit": "edit"}.get(
                    action["action"], "review"
                ),
                "id": action.get("payload", {}).get("id"),
            }
            st.rerun()
        if action["action"] == "foundation_scope_edit":
            if section != "scope" or role not in EDITORS:
                raise FoundationError("Open an editable Scope record first.")
            from securescope.ui.grc_workspace.scope_editor import start_scope_editor

            boundary_type = action.get("payload", {}).get("boundary_type")
            step = {"Technology": 2, "Product / service": 2, "Other boundary": 3}.get(boundary_type)
            if step is not None and selected_scope:
                start_scope_editor(client, engagement, selected_scope, initial_step=step)
            else:
                start_scope_editor(client, engagement, selected_scope)
            st.rerun()
        if role not in EDITORS:
            raise FoundationError("Contributor membership is required.")
        if action["action"] == "foundation_objective_save":
            if section != "objectives":
                raise FoundationError("Open the Objectives register before editing objectives.")
            if not scope:
                raise FoundationError("Select an ISMS scope first.")
            payload = action["payload"]
            index = payload.get("index")
            record = {f: str(payload.get("record", {}).get(f, "")) for f in FIELDS["objectives"]}
            due = record.get("due_date")
            historical = payload.get("historical") is True
            if due:
                try:
                    past = date.fromisoformat(due) < date.today()
                except ValueError as exc:
                    raise FoundationError("Use a valid objective due date.") from exc
                if past and not historical and payload.get("date_intent") != "current":
                    raise FoundationError(
                        "This due date is in the past. Choose current overdue or historical."
                    )
            record["historical"] = historical
            record["archived"] = payload.get("archived") is True
            if index is None:
                rows.append(record)
            elif type(index) is int and 0 <= index < len(rows):
                rows[index] = record
            else:
                raise FoundationError("Objective changed. Reload before editing.")
            save_version(
                client,
                engagement,
                int(scope),
                "objectives",
                rows,
                actor=actor,
                owner=latest.get("owner") or actor,
                status="Draft",
                expected_version=action["expected"],
                note="Updated objective through the formal register editor.",
            )
            response["message"] = "Objective saved in a new draft version."
            st.session_state[key + ":response"] = response
            st.rerun()
        if action["action"] != "foundation_add":
            raise FoundationError("Unsupported register action.")
        st.session_state[key + ":dialog"] = {
            "boundary_type": action.get("payload", {}).get("boundary_type")
        }
        st.rerun()
    except (*ERRORS, ValueError, TypeError) as exc:
        LOGGER.warning("Formal register action failed: %s", type(exc).__name__)
        if "action" in locals() and action:
            st.session_state[key + ":response"] = {"nonce": action["nonce"], "error": str(exc)}
            st.rerun()
        st.error(str(exc))
    return False
