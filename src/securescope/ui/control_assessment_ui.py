"""A focused, draft-aware control assessment using existing approval services."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from securescope.core.gap_assessment_domain import (
    ASSESSMENT_MODELS,
    ASSESSMENT_STATUSES,
    ASSURANCE_DIMENSIONS,
    CRITERION_RESULTS,
    TEST_RESULTS,
    GapAssessmentError,
)
from securescope.evidence.automated_checks import usable_evidence
from securescope.evidence.models import role_can
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    list_evidence_records,
)
from securescope.persistence.grc_repository import (
    GrcRepositoryError,
    control_detail_history,
    create_control_target,
    create_profile_version,
    save_manual_control_assessment,
)
from securescope.persistence.migration_service import MigrationError
from securescope.persistence.risk_register_repository import list_risk_register
from securescope.persistence.working_register_repository import load_register, save_register
from securescope.ui.assurance_interactions import open_control_assessment
from securescope.ui.components.primitives import identity_context
from securescope.ui.evidence_hub_ui import _identity
from securescope.ui.workflow_sections import workflow_section
from securescope.ui.workspace_inputs import remembered_scope, working_actor

ERRORS = (
    GrcRepositoryError,
    EvidenceRepositoryError,
    DatabaseConfigurationError,
    MigrationError,
    GapAssessmentError,
    ValueError,
)
STATUS_OPTIONS = [
    status
    for status in ASSESSMENT_STATUSES
    if status not in {"Not applicable", "Accepted residual risk"}
]
GAP_STATUSES = {
    "Not implemented",
    "Gap identified",
    "Partially implemented",
    "Insufficient evidence",
}


def render_profile_editor(client_name: str, rows: list[dict[str, Any]]) -> None:
    """Expose persistent owner and scope editing from the control register.

    Args:
        client_name: Active workspace.
        rows: Current control profile versions.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected validation or storage errors.
    """
    with workflow_section(
        "Edit control owners and assessment scope",
        "Set accountable owners and the boundaries of this assessment.",
    ):
        st.caption(
            (
                "Edit several controls together. Saving creates profile versions; "
                "their targets must be reviewed before the next assessment."
            )
        )
        actor = working_actor(client_name, "profiles")

        def multiline(value: Any) -> str:
            if isinstance(value, str):
                return value
            return "\n".join(str(item) for item in value or [])

        original = [
            {
                "control_id": row["control_id"],
                "control_name": row["control_name"],
                "control_owner": row.get("control_owner") or "",
                "assessment_owner": row.get("assessment_owner") or "",
                "scope": (row.get("assessment_scope") or {}).get("description", ""),
                "measurement_model": row.get("measurement_model") or "checklist",
                "automation_level": row.get("automation_level") or "Manual",
                "assessment_methods": multiline(row.get("assessment_methods")),
                "evidence_requirements": multiline(row.get("evidence_requirements")),
            }
            for row in rows
        ]
        edited = st.data_editor(
            original,
            disabled=["control_id", "control_name"],
            hide_index=True,
            width="stretch",
            height=390,
            key=f"profile_metadata::{client_name}",
            column_config={
                "measurement_model": st.column_config.SelectboxColumn(
                    "Measurement model",
                    options=list(ASSESSMENT_MODELS),
                    required=True,
                ),
                "automation_level": st.column_config.SelectboxColumn(
                    "Automation",
                    options=["Manual", "Partial", "Automated"],
                    required=True,
                ),
                "assessment_methods": st.column_config.TextColumn(
                    "Assessment methods (one per line)",
                    width="large",
                ),
                "evidence_requirements": st.column_config.TextColumn(
                    "Evidence requirements (one per line)",
                    width="large",
                ),
            },
        )
        if st.button("Save profile changes", type="primary", key=f"save_profiles::{client_name}"):
            changed = 0
            # ``st.data_editor`` returns a DataFrame for a list-of-dicts input;
            # iterate its records rather than its column names.
            edited_rows = (
                edited.to_dict(orient="records") if hasattr(edited, "to_dict") else list(edited)
            )
            for before, after, profile in zip(original, edited_rows, rows):
                cleaned_after = {
                    **after,
                    "control_owner": str(after.get("control_owner") or "").strip(),
                    "assessment_owner": str(after.get("assessment_owner") or "").strip(),
                    "scope": str(after.get("scope") or "").strip(),
                    "measurement_model": str(after.get("measurement_model") or "checklist").strip(),
                    "automation_level": str(after.get("automation_level") or "Manual").strip(),
                }
                if before == cleaned_after:
                    continue
                try:
                    create_profile_version(
                        client_name,
                        profile["control_id"],
                        measurement_model=cleaned_after["measurement_model"],
                        control_owner=cleaned_after["control_owner"],
                        assessment_owner=cleaned_after["assessment_owner"],
                        assessment_scope={"description": cleaned_after["scope"]},
                        assessment_methods=[
                            item.strip()
                            for item in str(
                                cleaned_after.get("assessment_methods") or ""
                            ).splitlines()
                            if item.strip()
                        ],
                        evidence_requirements=[
                            item.strip()
                            for item in str(
                                cleaned_after.get("evidence_requirements") or ""
                            ).splitlines()
                            if item.strip()
                        ],
                        automation_level=cleaned_after["automation_level"],
                        supported_data_sources=profile.get("supported_data_sources") or [],
                        actor=actor,
                    )
                except ERRORS as exc:
                    st.error(
                        f"{profile['control_id']}: {exc}. {changed} earlier changes were saved."
                    )
                    return
                changed += 1
            if changed:
                st.session_state[f"profile_saved::{client_name}"] = (
                    f"{changed} profile versions saved."
                )
                st.rerun()
            st.info("No profile fields changed.")
    if message := st.session_state.pop(f"profile_saved::{client_name}", None):
        st.success(message)


def _target_editor(client_name: str, selected: dict[str, Any], prefix: str) -> None:
    """Show a prefilled target proposal with an explicit approval action.

    Args:
        client_name: Active workspace.
        selected: Current control profile.
        prefix: Unique widget prefix.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected validation or storage errors.
    """
    try:
        from securescope.grc.scope_workflow import filter_scope_risks
        from securescope.ui.grc_workspace.context import selected_context_ids

        engagement_id, scope_id = selected_context_ids(client_name)
        risk_view = (
            st.segmented_control(
                "Risks addressed — scope",
                ["Current ISMS Scope", "All client risks"],
                default="Current ISMS Scope",
                key=f"{prefix}::risk_scope::{engagement_id}::{scope_id}",
            )
            or "Current ISMS Scope"
        )
        risk_options = {
            int(r["risk_ref"]): r
            for r in filter_scope_risks(list_risk_register(client_name), risk_view, scope_id)
        }
    except ERRORS as exc:
        st.error(f"Risk references are unavailable: {exc}")
        return
    with workflow_section(
        "Agree the target",
        "Review the expected outcome before recording an assessment.",
        status="Completed" if selected.get("target_id") else "Not started",
        step=1,
    ):
        if selected.get("target_id"):
            st.success(f"Target version {selected['target_version']} is available.")
            st.write(selected.get("target_description") or "")
        with st.form(prefix + "::target"):
            description = st.text_area(
                "Expected result",
                value=selected.get("target_description")
                or selected.get("expected_security_outcome")
                or "",
            )
            rationale = st.text_input(
                "Business rationale", placeholder="Why does the business need this result?"
            )
            risk_refs = st.multiselect(
                "Risks addressed",
                list(risk_options),
                format_func=lambda ref: (
                    f"R-{ref} — "
                    + str(
                        risk_options[ref].get("risk_summary")
                        or risk_options[ref].get("threat")
                        or "Untitled"
                    )
                ),
            )
            if not risk_options:
                st.info("Create a risk in Risk Management before approving a risk-based target.")
            left, right = st.columns(2)
            approver = left.text_input("Target approved by")
            due = right.date_input("Target due", value=date.today() + timedelta(days=90))
            with st.expander("Measurement and acceptance details"):
                numeric = st.number_input("Numeric target (optional)", value=None, min_value=0.0)
                unit = st.text_input("Unit", value="%")
                remaining = st.text_input("Treatment of scope below the target")
                evidence = st.text_area(
                    "Evidence needed", value="\n".join(selected.get("evidence_requirements") or [])
                )
                test = st.text_input("Effectiveness test to perform")
            approved = st.form_submit_button("Approve target version", type="primary")
        if approved:
            try:
                create_control_target(
                    client_name,
                    int(selected["profile_id"]),
                    target_description=description,
                    target_value=numeric,
                    unit=unit if numeric is not None else "",
                    target_date=due,
                    rationale=rationale,
                    risk_basis=", ".join(f"R-{ref}" for ref in risk_refs),
                    risk_refs=risk_refs,
                    remaining_scope_justification=remaining,
                    required_evidence=[
                        line.strip() for line in evidence.splitlines() if line.strip()
                    ],
                    required_effectiveness_test=test,
                    approver=approver,
                    approval_date=date.today(),
                )
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.rerun()


def render_assessment(client_name: str, rows: list[dict[str, Any]]) -> None:
    """Assess a selected control with reused scope, evidence and durable drafts.

    Args:
        client_name: Active workspace.
        rows: Current control overview.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected validation or persistence errors.
    """
    if not rows:
        st.info("No controls are available in this workspace.")
        return
    options = {str(row["control_id"]): row for row in rows}
    selection_key = f"guided_control::{client_name}"
    pending = st.session_state.pop(f"manual_control_pending::{client_name}", "")
    if pending in options:
        st.session_state[selection_key] = pending
    selected_id = st.selectbox(
        "Control to assess",
        list(options),
        format_func=lambda value: f"{value} · {options[value]['control_name']}",
        key=selection_key,
        on_change=open_control_assessment,
        args=(client_name,),
    )
    selected = dict(options[selected_id])
    requirement_view = None
    from securescope.persistence.assurance_workspace_repository import (
        load_workspace,
        seed_control_baseline,
    )
    from securescope.persistence.foundation_repository import FoundationError
    from securescope.ui.grc_workspace.context import current_actor, selected_context_ids

    engagement, scope_id = selected_context_ids(client_name)
    if engagement and scope_id:
        try:
            requirement_view = load_workspace(
                client_name, selected_id, current_actor(), engagement, scope_id
            )
            if seed_control_baseline(
                client_name, selected_id, current_actor(), engagement, scope_id, requirement_view
            ):
                st.rerun()
        except (*ERRORS, FoundationError) as exc:
            st.error(f"Scoped requirements could not be loaded: {exc}")
            return
    configured = (
        (selected.get("assessment_scope") or {}).get("implementation_requirements") or {}
    ).get("requirements", [])
    requirement_results = requirement_view["result"]["requirements"] if requirement_view else []
    prefix = f"assessment::{client_name}::{selected['profile_id']}"
    register_key = f"assessment:{selected['profile_id']}"
    try:
        saved = load_register(client_name, register_key)
        evidence_pool = list_evidence_records(
            client_name, validation_status="Validated", engagement_id=engagement, scope_id=scope_id
        )
    except ERRORS as exc:
        st.error(str(exc))
        return
    st.session_state.setdefault(prefix + "::snapshot", saved)
    snapshot = st.session_state[prefix + "::snapshot"]
    draft = st.session_state.get(prefix + "::working") or (
        snapshot["rows"][0] if snapshot["rows"] else {}
    )
    actor = working_actor(client_name, prefix)
    from securescope.ui.components.stitch import apply_assurance_design

    apply_assurance_design()
    st.html(
        "<style>"
        + (Path(__file__).parent / "styles" / "assessment_workspace.css").read_text(
            encoding="utf-8"
        )
        + "</style>"
    )
    with st.container(key="assessment_header"):
        st.subheader(
            f"{selected_id} — "
            + (
                (selected.get("assessment_scope") or {}).get("organization_name")
                or selected["control_name"]
            )
        )
        identity_context(selected.get("control_owner") or "Unassigned", "Control owner")
        st.caption(f"Profile version {selected.get('profile_version', 1)}")
        st.caption(
            f"ISMS Scope: {scope_id or 'Not selected'} · Target: "
            f"{'Approved' if selected.get('target_id') else 'Required before submission'}"
        )
        save_requested = submit_requested = False
        save_feedback = st.container()
    guidance = requirement_results or configured
    with st.container(key="assessment_guidance"):
        st.markdown("#### SecureScope assessment")
        resolved = (requirement_view or {}).get("result", {})
        supported = sum(item.get("result") == "PASS" for item in guidance)
        missing = [item for item in guidance if item.get("result") != "PASS"]
        st.html(
            '<div class="assessment-status-strip"><span>'
            + escape(str(resolved.get("implementation", "Not assessed")))
            + "</span><span>"
            + str(supported)
            + " / "
            + str(len(guidance))
            + " requirements supported</span><span>"
            + str(len(missing))
            + " requiring review</span></div>"
        )
        st.caption(f"{len(missing)} requirements require evidence or review.")
    your_tab = st.container(key="assessment_judgment")
    with your_tab:
        st.markdown("#### Your assessment")
    conclusion_tab = st.container(key="assessment_conclusion")
    review_tab = conclusion_tab
    evidence_tab = st.container(key="assessment_evidence_details")
    effectiveness_tab = st.container(key="assessment_advanced")
    with effectiveness_tab:
        st.markdown("#### Advanced Details & Dimensions")
        target_tab = st.container(border=True)
    with target_tab:
        st.markdown("#### Scope, owner & approved target")
        st.caption("Confirm the assessment boundaries and controlled target.")
        with workflow_section("Requirements & approved target"):
            if configured:
                st.caption(
                    f"Current ISMS Scope #{scope_id} · {len(configured)} configured criteria"
                )
                st.table(
                    [
                        {
                            "Requirement": r["title"],
                            "Expected result": r["expected_result"],
                            "Mandatory": r["mandatory"],
                        }
                        for r in configured
                    ]
                )
                if not selected.get("target_id"):
                    st.info(
                        (
                            "Confirm this requirement set as the controlled assessment target."
                            " You do not need to rewrite its outcomes."
                        )
                    )
                    rationale = st.text_input(
                        "Requirement review rationale", key=prefix + "::baseline_rationale"
                    )
                    requirement_due = st.date_input(
                        "Requirement target date",
                        value=date.today() + timedelta(days=90),
                        key=prefix + "::requirement_due",
                    )
                    confirmed = st.checkbox(
                        "I reviewed these criteria for the current scope.",
                        key=prefix + "::baseline_confirm",
                    )
                    if st.button(
                        "Confirm requirements for assessment",
                        disabled=not confirmed,
                        key=prefix + "::baseline_target",
                    ):
                        try:
                            create_control_target(
                                client_name,
                                int(selected["profile_id"]),
                                target_description="\n".join(
                                    f"{r['title']}: {r['expected_result']}" for r in configured
                                ),
                                target_value=None,
                                unit="",
                                target_date=requirement_due,
                                rationale=rationale,
                                risk_basis=(
                                    "Current scoped implementation requirements; related canonical "
                                    "risks remain linked in the profile."
                                ),
                                remaining_scope_justification="",
                                required_evidence=[
                                    r["expected_result"]
                                    for r in configured
                                    if r.get("evidence_required", True)
                                ],
                                required_effectiveness_test=(
                                    "Assess configured requirements against their scoped evidence."
                                ),
                                approver=current_actor(),
                                approval_date=date.today(),
                            )
                        except ERRORS as exc:
                            st.error(f"Requirement confirmation failed: {exc}")
                        else:
                            st.rerun()
                else:
                    st.caption("The current profile has a controlled assessment target.")
            else:
                _target_editor(client_name, selected, prefix)
        scope_default = (
            selected.get("scope_definition")
            or (selected.get("assessment_scope") or {}).get("description")
            or remembered_scope(client_name)
        )
        scope_column, owner_column = st.columns([2, 1])
        scope = scope_column.text_area(
            "Scope being assessed",
            value=draft.get("scope", scope_default or ""),
            key=prefix + "::scope",
        )
        owner = owner_column.text_input(
            "Control owner",
            value=draft.get("owner", selected.get("control_owner") or ""),
            key=prefix + "::owner",
        )
        if scope.strip():
            st.session_state[f"working_scope::{client_name}"] = scope.strip()
    with target_tab:
        current = st.text_area(
            "Operational Narrative",
            value=draft.get("current_state", selected.get("current_state") or ""),
            key=prefix + "::current",
        )
    with evidence_tab:
        proof_heading, proof_action = st.columns([2, 1])
        proof_heading.markdown("#### Requirements & Evidence Details")
        if proof_action.button("Link Proof from Workspace", key=prefix + "::open_evidence"):
            from securescope.ui.control_workspace import open_control_workspace

            open_control_workspace(client_name, selected_id)
        scoped_evidence_ids = (
            {e["id"] for e in requirement_view["bundle"]["requirement_evidence"]}
            if requirement_view
            else None
        )
        now = datetime.now(timezone.utc)
        available = {}
        for item in evidence_pool:
            expiry = item.get("expires_at")
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            mapped = any(
                mapping.get("control_id") == selected_id
                and usable_evidence(
                    {
                        **item,
                        "mapping_approved": mapping.get("approved"),
                        "mapping_origin": mapping.get("mapping_origin"),
                    },
                    {str(item.get("tool_id") or "").lower()},
                )
                for mapping in item.get("controls") or []
            )
            if (
                mapped
                and (scoped_evidence_ids is None or int(item["id"]) in scoped_evidence_ids)
                and (not expiry or expiry > now)
                and item.get("freshness_status") in {"Current", "Expiring Soon"}
            ):
                available[int(item["id"])] = item
        if available:
            st.html(
                '<div class="assessment-proofs">'
                + "".join(
                    "<article><div><strong>"
                    + escape(str(item["title"]))
                    + "</strong><p>EV-"
                    + escape(str(item["id"]))
                    + " · "
                    + escape(
                        str(
                            item.get("source") or item.get("evidence_type") or "Documented evidence"
                        )
                    )
                    + " · "
                    + escape(str(item.get("freshness_status", "Unknown")))
                    + "</p></div><span>Validated</span></article>"
                    for item in available.values()
                )
                + "</div>"
            )
        linked = st.multiselect(
            "Reuse validated evidence",
            list(available),
            default=[item for item in draft.get("evidence_ids", []) if item in available],
            format_func=lambda value: f"#{value} · {available[value]['title']}",
            key=prefix + "::evidence",
        )
        if not available:
            st.caption(
                (
                    "No current, validated evidence is mapped to this control yet. "
                    "Submit or review it in the Evidence workspace."
                )
            )
        with st.expander("Use an additional evidence reference"):
            reference = st.text_input(
                "Document / test reference",
                value=draft.get("reference", ""),
                key=prefix + "::reference",
            )
            freshness = st.selectbox(
                "Reference freshness",
                ["Unknown", "Current", "Approaching expiration", "Expired"],
                index=["Unknown", "Current", "Approaching expiration", "Expired"].index(
                    draft.get("freshness", "Unknown")
                ),
                key=prefix + "::freshness",
            )
    with conclusion_tab:
        st.markdown("#### Conclusion")
        st.caption("Review the evidence-supported conclusion before completing the assessment.")
        result_column, confidence_column = st.columns(2)
        status = result_column.selectbox(
            "Assessment result",
            STATUS_OPTIONS,
            index=STATUS_OPTIONS.index(draft.get("status", "Not assessed")),
            key=prefix + "::status",
        )
        confidence = confidence_column.selectbox(
            "Assessment confidence",
            ["Low", "Medium", "High"],
            index=["Low", "Medium", "High"].index(
                draft.get("confidence", "Medium" if linked else "Low")
            ),
            key=prefix + "::confidence",
            help=(
                "Confidence describes the supporting evidence; "
                "it does not validate the assessment."
            ),
        )
        gap = risk = action = verify = effort = ""
        priority = "Medium"
        if status in GAP_STATUSES:
            gap = st.text_area("What is missing?", value=draft.get("gap", ""), key=prefix + "::gap")
            left, right = st.columns(2)
            action = left.text_area(
                "Action needed", value=draft.get("action", ""), key=prefix + "::action"
            )
            verify = right.text_area(
                "How will the fix be verified?",
                value=draft.get("verify", ""),
                key=prefix + "::verify",
            )
            risk = left.text_input(
                "Related business risk", value=draft.get("risk", ""), key=prefix + "::risk"
            )
            effort = right.text_input(
                "Remaining work / effort", value=draft.get("effort", ""), key=prefix + "::effort"
            )
            priority = st.selectbox(
                "Priority",
                ["Critical", "High", "Medium", "Low"],
                index=["Critical", "High", "Medium", "Low"].index(draft.get("priority", "Medium")),
                key=prefix + "::priority",
            )
        test_data = None
        with effectiveness_tab:
            dimensions = []
            dimension_columns = st.columns(2)
            for index, dimension in enumerate(ASSURANCE_DIMENSIONS):
                initial = st.session_state.get(
                    prefix + "::dimension::" + dimension,
                    draft.get("dimensions", {}).get(dimension, "Not assessed"),
                )
                if dimension in {"Implementation", "Operating effectiveness"}:
                    labels = (
                        {
                            "Implemented but not verified": "Implemented",
                            "Partially implemented": "Partial",
                            "Not implemented": "Not Implemented",
                            "Insufficient evidence": "Insufficient Evidence",
                        }
                        if dimension == "Implementation"
                        else {
                            "Implemented and effective": "Effective",
                            "Partially implemented": "Partial",
                            "Not implemented": "Ineffective",
                            "Insufficient evidence": "Not Enough Evidence",
                        }
                    )
                    initial = initial or "Not assessed"
                    choices = list(labels)
                    if initial not in choices and initial != "Not assessed":
                        choices.append(initial)
                    with your_tab:
                        dimension_value = (
                            st.radio(
                                (
                                    "Implementation"
                                    if dimension == "Implementation"
                                    else "Effectiveness"
                                ),
                                choices,
                                index=choices.index(initial) if initial in choices else None,
                                format_func=lambda value, labels=labels: labels.get(value, value),
                                horizontal=True,
                                key=prefix + "::dimension::" + dimension,
                            )
                            or "Not assessed"
                        )
                else:
                    with dimension_columns[index % 2]:
                        dimension_value = st.selectbox(
                            dimension,
                            STATUS_OPTIONS,
                            index=STATUS_OPTIONS.index(initial),
                            key=prefix + "::dimension::" + dimension,
                        )
                dimensions.append({"Dimension": dimension, "Result": dimension_value})
            criteria_grid = st.data_editor(
                pd.DataFrame(
                    (
                        requirement_assessment_rows(configured, requirement_results, draft)
                        if configured
                        else draft.get("criteria")
                    )
                    or [
                        {"description": text, "result": "Not assessed", "evidence_reference": ""}
                        for text in (
                            (selected.get("assessment_scope") or {}).get(
                                "implementation_requirements"
                            )
                            or {}
                        ).get("criteria", [])
                    ],
                    columns=(["criterion_identifier"] if configured else [])
                    + ["description", "result", "evidence_reference"],
                ),
                num_rows="fixed" if configured else "dynamic",
                disabled=["criterion_identifier", "description"] if configured else [],
                hide_index=True,
                width="stretch",
                column_config={
                    "criterion_identifier": None,
                    "description": st.column_config.TextColumn(
                        "Criterion", width="large", required=True
                    ),
                    "result": st.column_config.SelectboxColumn(
                        "Result", options=list(CRITERION_RESULTS), required=True
                    ),
                    "evidence_reference": st.column_config.TextColumn(
                        "Evidence reference", width="large"
                    ),
                },
                key=prefix + "::criteria",
            )
            if st.checkbox(
                "Record an effectiveness test",
                value=bool(draft.get("test_data")),
                key=prefix + "::test_enabled",
            ):
                test_data = {}
                for field, label in (
                    ("test_scenario", "Test scenario"),
                    ("test_objective", "Test objective"),
                    ("expected_outcome", "Expected result"),
                    ("observed_outcome", "Observed result"),
                    ("tested_sample", "Sample tested"),
                    ("evidence_reference", "Test evidence"),
                    ("tester", "Tester"),
                ):
                    test_data[field] = st.text_input(
                        label,
                        value=(draft.get("test_data") or {}).get(field, ""),
                        key=prefix + "::" + field,
                    )
                test_data.update(
                    result=st.selectbox(
                        "Test outcome",
                        list(TEST_RESULTS),
                        index=list(TEST_RESULTS).index(
                            (draft.get("test_data") or {}).get("result", list(TEST_RESULTS)[0])
                        ),
                        key=prefix + "::test_result",
                    ),
                    test_date=st.date_input(
                        "Test date",
                        value=date.fromisoformat(
                            (draft.get("test_data") or {}).get(
                                "test_date", date.today().isoformat()
                            )
                        ),
                        key=prefix + "::test_date",
                    ),
                    retest_required=st.checkbox(
                        "Re-test required",
                        value=bool((draft.get("test_data") or {}).get("retest_required")),
                        key=prefix + "::retest",
                    ),
                    corrective_action=st.text_area(
                        "Test corrective action",
                        value=(draft.get("test_data") or {}).get("corrective_action", ""),
                        key=prefix + "::corrective",
                    ),
                )
                test_data["retest_due_date"] = (
                    st.date_input(
                        "Re-test due date",
                        value=date.fromisoformat(
                            (draft.get("test_data") or {}).get("retest_due_date")
                            or (date.today() + timedelta(days=30)).isoformat()
                        ),
                        disabled=not test_data["retest_required"],
                        key=prefix + "::retest_due",
                    )
                    if test_data["retest_required"]
                    else None
                )
    with effectiveness_tab:
        summary = st.text_area(
            "Evaluator Rationale",
            value=draft.get("evidence_summary", ""),
            key=prefix + "::evidence_summary",
            help="Explain what the reviewed evidence demonstrates about control operation.",
        )
    dimension_rows = dimensions.to_dict("records") if hasattr(dimensions, "to_dict") else dimensions
    dimension_results = {row["Dimension"]: row["Result"] for row in dimension_rows}
    criteria = criteria_grid.fillna("").to_dict("records")
    with your_tab:
        override_rationale = st.text_area(
            "Note / assessment rationale (optional unless overriding a positive result)",
            value=draft.get("override_rationale", ""),
            key=prefix + "::override",
        )
    identity, role = _identity(client_name)
    authorized = bool(role and role_can(role, "review"))
    with review_tab:
        st.caption(f"ISMS Scope #{scope_id or 'Not selected'}")
        st.write(f"**Result:** {status} · **Evidence linked:** {len(linked)}")
        if requirement_results:
            st.caption(
                f"Requirements passed: {sum(r['result'] == 'PASS' for r in requirement_results)}"
                f" / {len(requirement_results)} · Unresolved mandatory: "
                f"{sum(r['mandatory'] and r['result'] != 'PASS' for r in requirement_results)}"
            )
        validated = st.checkbox(
            "I confirm and validate this assessment",
            disabled=not authorized,
            key=prefix + "::validate",
        )
        if status in {"Target achieved", "Implemented and effective"} and not authorized:
            st.info(
                (
                    "This conclusion requires a Consultant or Administrator identity. "
                    "A draft can still be saved."
                )
            )
    contents = dict(
        override_rationale=override_rationale,
        confidence=confidence,
        scope=scope,
        owner=owner,
        evidence_ids=linked,
        reference=reference,
        evidence_summary=summary,
        freshness=freshness,
        current_state=current,
        status=status,
        gap=gap,
        action=action,
        verify=verify,
        risk=risk,
        effort=effort,
        priority=priority,
        dimensions=dimension_results,
        criteria=criteria,
        test_data=(
            {
                key: value.isoformat() if isinstance(value, date) else value
                for key, value in test_data.items()
            }
            if test_data
            else None
        ),
    )
    st.session_state[prefix + "::working"] = contents
    baseline = st.session_state.setdefault(prefix + "::initial_contents", dict(contents))
    has_changes = contents != baseline

    with review_tab:
        if has_changes:
            st.caption("Unsaved changes · retained in this session")
        if not selected.get("target_id"):
            st.info(
                "Confirm the requirements in Implementation & Evidence before finalizing. "
                "You can save a draft now."
            )
        identity_context(identity or actor or "Not identified", "Assessor")
        save_draft, finalize, next_column = st.columns(3)
        bottom_save = save_draft.button("Save Draft", key=prefix + "::save_draft")
        feedback = st.container()
        if save_requested or bottom_save:
            try:
                revision = save_register(
                    client_name,
                    register_key,
                    [contents],
                    actor=actor,
                    expected_revision=snapshot["revision"],
                )
            except ERRORS as exc:
                feedback.error(str(exc))
                if save_requested:
                    save_feedback.error(str(exc))
            else:
                st.session_state[prefix + "::snapshot"] = {"rows": [contents], "revision": revision}
                st.session_state[prefix + "::initial_contents"] = dict(contents)
                feedback.success(
                    "Draft saved. Assessment results and approval status have not changed."
                )
                if save_requested:
                    save_feedback.success("Draft saved.")
        finalize_requested = finalize.button(
            "Complete Assessment",
            type="primary",
            disabled=not selected.get("target_id"),
            key=prefix + "::finalize",
        )
        if finalize_requested or submit_requested:
            chosen = [available[item] for item in linked]
            evidence_reference = "; ".join(
                [
                    *(f"Evidence #{item['id']}" for item in chosen),
                    *([reference] if reference else []),
                ]
            )
            try:
                if configured and status in {"Target achieved", "Implemented and effective"}:
                    unresolved = [
                        c
                        for c in criteria
                        if c["result"] != "Pass"
                        and any(
                            r["id"] == c.get("criterion_identifier") and r["mandatory"]
                            for r in configured
                        )
                    ]
                    if unresolved:
                        raise ValueError(
                            (
                                "Complete the mandatory requirement results before recording a "
                                "positive conclusion."
                            )
                        )
                    if any(
                        r["mandatory"]
                        and not next(
                            (
                                c.get("evidence_reference", "").strip()
                                for c in criteria
                                if c.get("criterion_identifier") == r["id"]
                            ),
                            "",
                        )
                        for r in configured
                    ):
                        raise ValueError("Record supporting references for each mandatory result.")
                    if not override_rationale.strip():
                        raise ValueError(
                            "Record the assessment rationale and explain any overrides."
                        )
                save_manual_control_assessment(
                    client_name,
                    int(selected["profile_id"]),
                    assessment_status=status,
                    current_state=current,
                    target_state=selected.get("target_description") or "",
                    gap_statement=gap,
                    scope_definition=scope,
                    accountable_owner=owner,
                    evidence_source="Evidence workspace" if chosen else "Manual reference",
                    evidence_reference=evidence_reference,
                    evidence_summary="\n".join(
                        [
                            *(str(item.get("summary") or item["title"]) for item in chosen),
                            summary,
                            override_rationale,
                        ]
                    ),
                    evidence_freshness=(
                        freshness if reference else ("Current" if chosen else "Unknown")
                    ),
                    evidence_expiration=min(
                        [item["expires_at"] for item in chosen if item.get("expires_at")],
                        default=None,
                    ),
                    confidence=confidence,
                    dimension_results=dimension_results,
                    criteria=criteria,
                    effectiveness_test=test_data,
                    related_risk=risk,
                    remaining_effort=effort,
                    priority=priority,
                    recommended_treatment=action,
                    required_verification=verify,
                    actor=actor,
                    validator=identity if validated and authorized else "",
                )
            except ERRORS as exc:
                (save_feedback if submit_requested else st).error(str(exc))
            else:
                st.session_state[prefix + "::initial_contents"] = dict(contents)
                (save_feedback if submit_requested else st).success(
                    "Assessment saved. Any required gap has been added to the treatment queue."
                )
        index = list(options).index(selected_id)
        next_id = list(options)[(index + 1) % len(options)]
        next_column.button(
            "Next control",
            key=prefix + "::next",
            on_click=open_control_assessment,
            args=(client_name, next_id),
        )
        with st.expander("Previous assessments and decisions"):
            try:
                history = control_detail_history(client_name, selected_id)
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.dataframe(
                    pd.DataFrame(history.get("assessments", [])), hide_index=True, width="stretch"
                )


def requirement_assessment_rows(requirements, results, draft):
    """Reuse stable profile criteria and supporting references in the assessment.

    Args:
        requirements: Current scoped criteria.
        results: Current derived results from canonical proof.
        draft: Saved in-progress assessment answers.
    Returns:
        Editable result rows retaining criterion identities and saved overrides.
    Raises:
        KeyError: If an internal criterion has no stable identity.
    """
    conclusions = {row["id"]: row for row in results}
    saved = {row.get("criterion_identifier"): row for row in draft.get("criteria", [])}
    rows = []
    for requirement in requirements:
        identity = requirement["id"]
        result = conclusions.get(identity, {})
        previous = saved.get(identity, {})
        references = [f"Evidence #{value}" for value in result.get("evidence_ids", [])]
        references += [
            f"Policy {value['id']} v{value['version']}"
            for value in result.get("policy_versions", [])
        ]
        if result.get("assessment_id"):
            references.append(f"Assessment #{result['assessment_id']}")
        rows.append(
            dict(
                criterion_identifier=identity,
                description=requirement["title"],
                result=previous.get(
                    "result",
                    {"PASS": "Pass", "PARTIAL": "Partial", "FAIL": "Fail"}.get(
                        result.get("result"), "Not assessed"
                    ),
                ),
                evidence_reference=previous.get("evidence_reference", "; ".join(references)),
            )
        )
    return rows
