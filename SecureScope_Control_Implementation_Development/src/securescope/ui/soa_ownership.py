"""Explicit scope assignment for preserved historical SoA versions."""

import streamlit as st

from securescope.persistence.grc_repository import (
    GrcRepositoryError,
    assign_legacy_soa_scope,
    latest_statement_of_applicability,
    list_statement_of_applicability_versions,
)
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role


def render_legacy_soa(client, engagement, scope):
    """Expose unassigned SoA history without copying or guessing its scope.

    Args:
        client: Active client.
        engagement: Selected engagement ID.
        scope: Selected scope ID.
    Returns:
        None.
    Raises:
        Unexpected errors propagate; known persistence errors are displayed.
    """
    try:
        legacy = list_statement_of_applicability_versions(client)
        if not legacy:
            return
        with st.expander(f"Legacy / unassigned SoA versions ({len(legacy)})"):
            st.caption(
                "Historical migration associations are preserved, but do not estab"
                "lish a confirmed scope. Assignment does not copy or modify SoA it"
                "ems."
            )
            st.dataframe(
                [
                    {
                        k.replace("_", " ").title(): r.get(k)
                        for k in (
                            "version_number",
                            "status",
                            "prepared_by",
                            "approved_by",
                            "approval_date",
                            "notes",
                            "control_count",
                        )
                    }
                    for r in legacy
                ],
                hide_index=True,
                width="stretch",
            )
            by_id = {int(r["id"]): r for r in legacy}
            inspected = st.selectbox(
                "View historical SoA",
                list(by_id),
                format_func=lambda value: f"Version {by_id[value]['version_number']}",
                key=f"legacy_soa_view::{client}",
            )
            document = latest_statement_of_applicability(client, version_id=inspected)
            if document:
                st.dataframe(
                    [
                        {
                            k.replace("_", " ").title(): r.get(k)
                            for k in (
                                "control_id",
                                "control_name",
                                "applicability",
                                "inclusion_justification",
                                "exclusion_justification",
                                "implementation_status",
                                "control_owner",
                                "reviewer",
                                "review_date",
                            )
                        }
                        for r in document["items"]
                    ],
                    hide_index=True,
                    width="stretch",
                )
            if (
                scope
                and engagement
                and get_workspace_role(client, current_actor()) == "Administrator"
            ):
                by_id = {int(r["id"]): r for r in legacy}
                with st.form(f"legacy_soa::{client}::{engagement}::{scope}"):
                    selected = st.selectbox(
                        "Legacy version",
                        list(by_id),
                        format_func=lambda value: f"Version {by_id[value]['version_number']}",
                    )
                    rationale = st.text_area("Scope assignment rationale")
                    confirmed = st.checkbox(
                        "I confirm this historical SoA belongs to the selected ISMS scope."
                    )
                    save = st.form_submit_button("Assign to current scope")
                if save:
                    if not confirmed:
                        st.error("Confirm the historical SoA scope before assigning it.")
                    else:
                        assign_legacy_soa_scope(
                            client,
                            selected,
                            engagement_id=engagement,
                            scope_id=scope,
                            actor=current_actor(),
                            rationale=rationale,
                        )
                        st.toast("Historical SoA assigned to the current scope.")
                        st.rerun()
    except (*ERRORS, GrcRepositoryError) as exc:
        st.error(f"Legacy SoA could not be loaded or assigned: {exc}")


def render_soa_working_editor(client_name, soa_engagement, soa_scope, soa_rows):
    """Render the complete working register without filtering out saved records.

    Args:
        client_name: Active client name.
        soa_engagement: Selected engagement identifier, or None.
        soa_scope: Selected scope identifier, or None.
        soa_rows: Canonical rows resolved for the selected scope/version.
    Returns:
        DataFrame of all edited rows, including unchanged records.
    Raises:
        StreamlitAPIException: If the supplied editor configuration is invalid.
    """
    import hashlib
    import json

    import pandas as pd

    from securescope.ui.components_v2.assurance_pages import assurance_page

    key = f"soa_working_editor::{client_name}::{soa_engagement}::{soa_scope}"
    signature = hashlib.sha256(
        json.dumps(soa_rows, sort_keys=True, default=str).encode()
    ).hexdigest()
    if st.session_state.get(key + "::source") != signature:
        st.session_state[key] = [dict(row) for row in soa_rows]
        st.session_state[key + "::source"] = signature
        st.session_state[key + "::baseline"] = [dict(row) for row in soa_rows]
    working = st.session_state[key]
    st.caption(
        "Working applicability is a proposal. Control Assurance metrics use the latest approved SoA for this scope."
    )
    if working != st.session_state.get(key + "::baseline", working):
        st.warning(
            "Unsaved SoA changes. Create a versioned snapshot below, then approve it to update formal applicability and assurance metrics."
        )
    message = st.session_state.pop(key + "::feedback", None)
    if message:
        st.success(message)
    view_rows = []
    for record in working:
        row = dict(record)
        row["family"] = ".".join(str(row["control_id"]).split(".")[:2])
        rationale = (
            row.get("inclusion_justification")
            if row.get("applicability") == "Applicable"
            else row.get("exclusion_justification")
        )
        row["rationale"] = rationale or "Not recorded"
        row["justification_status"] = (
            "Recorded" if str(rationale or "").strip() else "Missing justification"
        )
        row["necessary"] = "Yes" if row.get("necessary_control") else "No"
        view_rows.append(row)

    def edit_row(event):
        """Select an existing canonical row for editing; return None."""
        if event.get("action") == "edit" and event.get("id") in {
            row["control_id"] for row in working
        }:
            st.session_state[key + "::edit"] = event["id"]

    assurance_page(
        dict(
            mode="soa",
            title="Statement of Applicability",
            subtitle=f"ISMS Scope #{soa_scope} · Clause 6.1.3 · Controlled applicability decisions",
            rows=view_rows,
            metrics=[
                {"label": "Total controls", "value": len(working)},
                {
                    "label": "Applicable",
                    "value": sum(r.get("applicability") == "Applicable" for r in working),
                },
                {
                    "label": "Excluded",
                    "value": sum(r.get("applicability") == "Not applicable" for r in working),
                },
                {
                    "label": "Pending rationale",
                    "value": sum(r["justification_status"] != "Recorded" for r in view_rows),
                },
            ],
            filters=[
                {"key": field, "label": label}
                for field, label in [
                    ("family", "All families"),
                    ("applicability", "All applicability"),
                    ("implementation_status", "All implementation"),
                    ("justification_status", "All rationales"),
                ]
            ],
            columns=[
                {
                    "key": field,
                    "label": label,
                    "kind": (
                        "status"
                        if field
                        in {"applicability", "implementation_status", "justification_status"}
                        else "text"
                    ),
                }
                for field, label in [
                    ("control_id", "Control"),
                    ("control_name", "Control name"),
                    ("family", "Family"),
                    ("necessary", "Necessary"),
                    ("applicability", "Applicability"),
                    ("rationale", "Rationale"),
                    ("implementation_status", "Implementation"),
                    ("justification_status", "Justification"),
                ]
            ],
        ),
        key=key + "::view",
        on_action=edit_row,
    )
    selected = st.session_state.pop(key + "::edit", None)
    if selected:
        _edit_soa_row(key, selected)
    return pd.DataFrame(st.session_state[key])


@st.dialog("Edit applicability", width="large")
def _edit_soa_row(key: str, control_id: str) -> None:
    """Edit a working row without changing a historical SoA version.

    Args:
        key: Scope-specific working register session key.
        control_id: Canonical control identifier in that register.
    Returns:
        None. The existing snapshot action persists all working rows.
    Raises:
        ValueError: If the selected row no longer belongs to the register.
    """
    rows = st.session_state[key]
    original = next((r for r in rows if r["control_id"] == control_id), None)
    if original is None:
        raise ValueError("The control is no longer in the selected SoA register.")
    st.caption(f"{control_id} · {original.get('control_name', '')}")
    st.caption("Changes update the working register. Save a versioned snapshot to persist them.")
    with st.form(key + "::row_form::" + control_id):
        left, right = st.columns(2)
        necessary = left.checkbox(
            "Necessary control", value=bool(original.get("necessary_control"))
        )
        options = ["Applicable", "Not applicable"]
        applicability = right.selectbox(
            "Applicability",
            options,
            index=(
                options.index(original.get("applicability"))
                if original.get("applicability") in options
                else 0
            ),
        )
        values = {}
        for field, label in [
            ("inclusion_justification", "Inclusion justification"),
            ("exclusion_justification", "Exclusion justification"),
            ("control_owner", "Control owner"),
            ("related_risks", "Related risks"),
            ("related_treatment_plans", "Related treatment plans"),
            ("evidence", "Evidence references"),
            ("effectiveness_review", "Effectiveness review"),
        ]:
            if field in original:
                values[field] = (
                    st.text_area(label, value=str(original.get(field) or ""))
                    if "justification" in field or field == "effectiveness_review"
                    else st.text_input(label, value=str(original.get(field) or ""))
                )
        approved = (
            st.checkbox("Approved", value=bool(original.get("approved")))
            if "approved" in original
            else None
        )
        save = st.form_submit_button("Apply Changes", type="primary")
    if save:
        updated = dict(original, **values, necessary_control=necessary, applicability=applicability)
        if approved is not None:
            updated["approved"] = approved
        st.session_state[key] = [updated if r["control_id"] == control_id else r for r in rows]
        st.session_state[key + "::feedback"] = (
            "Applicability updated in the working register. Save a versioned snapshot below."
        )
        st.rerun(scope="app")
    if st.button("Cancel", key=key + "::cancel"):
        st.rerun(scope="app")


def pending_soa_applicability(client: str, engagement: int | None, scope: int | None) -> dict:
    """Read unsaved applicability edits for exactly one selected context.

    Args:
        client: Active client name.
        engagement: Selected engagement identifier.
        scope: Selected ISMS Scope identifier.
    Returns:
        Control IDs mapped to proposed applicability labels, never approved decisions.
    Raises:
        No exceptions are raised for an absent working register.
    """
    if engagement is None or scope is None:
        return {}
    key = f"soa_working_editor::{client}::{engagement}::{scope}"
    baseline = {row["control_id"]: row for row in st.session_state.get(key + "::baseline", [])}
    return {
        row["control_id"]: row.get("applicability")
        for row in st.session_state.get(key, [])
        if row["control_id"] in baseline and row != baseline[row["control_id"]]
    }
