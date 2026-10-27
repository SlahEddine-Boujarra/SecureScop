"""Streamlit presentation for the workspace-scoped ISO Evidence Hub."""

from __future__ import annotations

import shutil
from datetime import date, timedelta
from typing import Any

import pandas as pd
import streamlit as st

from securescope.evidence.evidence_service import (
    EvidenceServiceError,
    consultant_review,
    ingest_report,
    request_manual_evidence,
    submit_manual_evidence,
)
from securescope.evidence.models import ReviewDecision, WorkspaceRole, role_can
from securescope.evidence.storage import EvidenceStorageError, read_artifact
from securescope.evidence.tool_catalog import TOOLS, IntegrationMode
from securescope.grc.control_catalog import (
    ISO_CONTROL_CATALOG,
)
from securescope.persistence.db_service import DatabaseError, get_client_id
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    enqueue_evidence_job,
    evidence_hub_summary,
    get_workspace_role,
    list_evidence_records,
    list_evidence_requests,
    update_evidence_request,
)
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.working_register_repository import load_register, save_register
from securescope.reporting.auditor_package_service import (
    AuditorPackageError,
    build_auditor_package,
    build_control_matrix_pdf,
)
from securescope.ui.components.navigation import section_navigation
from securescope.ui.grc_workspace.context import selected_context_ids
from securescope.ui.workflow_sections import workflow_section


def _identity(client_name: str) -> tuple[str, WorkspaceRole | None]:
    """Resolve local session or environment identity through workspace membership.

    Args:
        client_name: Current workspace name.
    Returns:
        Trusted principal and active role, or an unauthorized identity.
    Raises:
        Unexpected errors propagate; expected membership lookup failures deny access.
    """
    from securescope.ui.grc_workspace.context import current_actor

    email = current_actor()
    if not email or email == "local-consultant":
        return "", None
    try:
        role = get_workspace_role(client_name, email)
    except EvidenceRepositoryError:
        return email, None
    try:
        return email, WorkspaceRole(role) if role else None
    except ValueError:
        return email, None


def _status(tool: Any) -> str:
    """Return a local display status without running a source tool."""

    if tool.integration_mode is IntegrationMode.EXISTING:
        return "Configuration managed externally — not verified"
    if tool.integration_mode is IntegrationMode.IMPORT_ONLY:
        return "Import ready - execution disabled"
    if tool.executable_names and any(shutil.which(name) for name in tool.executable_names):
        return "Installed"
    if tool.integration_mode is IntegrationMode.API_OR_IMPORT:
        return "Report import ready / API optional"
    return "Not detected / report import available"


def _overview(client_name: str) -> None:
    """Render workspace evidence coverage and recent activity."""

    from datetime import datetime, timezone

    from securescope.grc.assurance_requirements import evidence_freshness
    from securescope.persistence.assurance_workspace_repository import assurance_overview
    from securescope.persistence.foundation_repository import FoundationError
    from securescope.persistence.grc_repository import list_control_overview
    from securescope.ui.grc_workspace.context import current_actor, selected_context_ids

    engagement, scope = selected_context_ids(client_name)
    missing = "Not Determined"
    try:
        evidence = list_evidence_records(
            client_name, limit=5000, scope_id=scope, engagement_id=engagement
        )
        summary = dict(
            validated=sum(r["validation_status"] == "Validated" for r in evidence),
            pending=sum(r["validation_status"] == "Pending" for r in evidence),
            expired=sum(
                evidence_freshness(r, 90, datetime.now(timezone.utc)) == "Stale" for r in evidence
            ),
        )
        if scope and engagement:
            entries = assurance_overview(
                client_name,
                current_actor(),
                engagement,
                scope,
                list_control_overview(client_name, scope_id=scope),
            )
            configured = [
                entry["result"] for entry in entries if not entry["result"].get("baseline_preview")
            ]
            if any(result["mandatory_count"] for result in configured):
                missing = sum(
                    r["mandatory"] and r["result"] == "NO EVIDENCE"
                    for result in configured
                    for r in result["requirements"]
                    if result["applicability"] != "Not Applicable"
                )
        else:
            summary = evidence_hub_summary(client_name)
    except (EvidenceRepositoryError, GrcRepositoryError, FoundationError) as exc:
        st.warning(f"Evidence metrics are unavailable: {exc}")
        return
    st.caption(f"Current ISMS Scope #{scope}" if scope else "All Client Evidence")
    with st.container(key="evidence_overview_metrics"):
        columns = st.columns(4)
        values = (
            ("Accepted", summary.get("validated", 0)),
            ("Unreviewed", summary.get("pending", 0)),
            ("Missing requirements", missing),
            ("Stale evidence", summary.get("expired", 0)),
        )
        for column, (label, value) in zip(columns, values):
            with column:
                st.metric(label, value)
    st.caption(
        "Missing counts mandatory requirements without usable proof. "
        "Evidence coverage is not a compliance conclusion."
    )
    if len(evidence) == 5000:
        st.caption("Showing the latest 5,000 evidence records; counts summarize this selection.")
    if st.button("Open Control Coverage", key=f"evidence_coverage::{client_name}"):
        from securescope.ui.gap_dashboard_ui import DASHBOARD_TAB
        from securescope.ui.navigation_runtime import navigate_to

        st.session_state[f"assurance_pending_tab::{client_name}"] = DASHBOARD_TAB
        navigate_to("Gap Assessment")
    evidence = evidence[:50]
    st.markdown("#### Recent evidence")
    if evidence:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "ID": item["id"],
                        "Title": item["title"],
                        "Source": item["tool_id"],
                        "Method": item["collection_method"],
                        "Collected": item["collected_at"],
                        "Freshness": item["freshness_status"],
                        "Review": (
                            "System verified"
                            if item.get("verification_origin") == "System collector"
                            else item["validation_status"]
                        ),
                    }
                    for item in evidence
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No evidence has been submitted in this workspace yet.")


def _tool_catalog(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Configure evidence owners and freshness for installed or imported sources.

    Args:
        client_name: Active workspace.
        actor: Configured identity.
        role: Verified workspace role.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected persistence failures.
    """
    try:
        saved = load_register(client_name, "tool_settings")
    except GrcRepositoryError as exc:
        st.error(str(exc))
        return
    preferences = {row["tool_id"]: row for row in saved["rows"]}
    records = [
        {
            "tool_id": tool.tool_id,
            "Source": tool.name,
            "Mode": tool.integration_mode.value,
            "Local availability": _status(tool),
            "Enabled for import": preferences.get(tool.tool_id, {}).get("Enabled for import", True),
            "Evidence owner": preferences.get(tool.tool_id, {}).get("Evidence owner", ""),
            "Freshness days": preferences.get(tool.tool_id, {}).get("Freshness days", 90),
            "Controls": ", ".join(tool.iso_control_ids),
        }
        for tool in TOOLS
    ]
    allowed = bool(role and role_can(role, "configure"))
    edited = st.data_editor(
        records,
        hide_index=True,
        width="stretch",
        height=510,
        disabled=(
            True if not allowed else ["tool_id", "Source", "Mode", "Local availability", "Controls"]
        ),
        column_config={
            "tool_id": None,
            "Controls": None,
            "Mode": None,
            "Freshness days": st.column_config.NumberColumn(min_value=1, max_value=3650, step=1),
            "Enabled for import": st.column_config.CheckboxColumn(),
        },
        key=f"tool_preferences::{client_name}::{saved['revision']}",
    )
    st.caption(
        (
            "Availability is detected locally. Enabling an import source does "
            "not install it or enable remote execution."
        )
    )
    if st.button(
        "Save source settings", disabled=not allowed, key=f"save_tool_preferences::{client_name}"
    ):
        try:
            save_register(
                client_name,
                "tool_settings",
                edited,
                actor=actor,
                expected_revision=saved["revision"],
            )
        except (GrcRepositoryError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.success("Source settings saved.")
    with st.expander("Technical details"):
        st.dataframe(
            [
                {
                    "Source": row["Source"],
                    "Provider ID": row["tool_id"],
                    "Mode": row["Mode"],
                    "Supported controls": row["Controls"],
                }
                for row in records
            ],
            hide_index=True,
            width="stretch",
        )
    if not allowed:
        st.info("An Administrator can change source settings.")


def _collect_tab(
    client_name: str,
    actor: str,
    role: WorkspaceRole | None,
) -> None:
    """Route automated collection to its dedicated, authorized workspace."""

    from securescope.ui.navigation_runtime import navigate_to

    st.markdown("#### Automated evidence sources")
    st.caption(
        "Use the dedicated source workspace to configure authorized collection, "
        "monitor job state and inspect the resulting evidence."
    )
    source_actions = st.columns(3)
    with source_actions[0]:
        if st.button(
            "Open Nmap discovery",
            icon=":material/travel_explore:",
            width="stretch",
            key=f"evidence_open_nmap::{client_name}",
        ):
            navigate_to("1 · Asset Discovery")
    with source_actions[1]:
        if st.button(
            "Open Nuclei scans",
            icon=":material/radar:",
            width="stretch",
            key=f"evidence_open_nuclei::{client_name}",
        ):
            navigate_to("3 · Scan Center")
    with source_actions[2]:
        if st.button(
            "Open Wazuh monitoring",
            icon=":material/shield:",
            width="stretch",
            key=f"evidence_open_wazuh::{client_name}",
        ):
            navigate_to("5 · SIEM & Wazuh")

    st.markdown("#### Other defensive collectors")
    executable = [tool for tool in TOOLS if tool.can_execute and tool.executable_names]
    rows = [
        {
            "Source": tool.name,
            "Mode": tool.integration_mode.value,
            "Local status": _status(tool),
            "Allowed": "Defensive collection" if tool.can_execute else "Import only",
            "Formats": ", ".join(tool.report_formats),
        }
        for tool in executable
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if role and role_can(role, "collect"):
        st.info(
            "Existing Nmap, OpenVAS and Nuclei campaigns continue through their independent "
            "workers. New defensive collectors are queued through the FastAPI control plane; "
            "until a connector is configured, use report import. Arbitrary command arguments "
            "are never accepted from this page."
        )
        defensive = [tool for tool in TOOLS if tool.integration_mode is IntegrationMode.LOCAL_CLI]
        from securescope.ui.evidence_collection_context import current_collection_context

        origin = current_collection_context(client_name)
        if origin.get("provider") in {tool.tool_id for tool in defensive}:
            defensive = [tool for tool in defensive if tool.tool_id == origin["provider"]]
        with st.form("iso_defensive_collection_job"):
            tool_id = st.selectbox(
                "Defensive collector",
                options=[tool.tool_id for tool in defensive],
                format_func=lambda value: next(
                    tool.name for tool in defensive if tool.tool_id == value
                ),
            )
            target = st.text_input(
                "Authorized target",
                help=(
                    "Domain, HTTP(S) URL, approved local path, container image or "
                    "cloud provider according to the selected collector."
                ),
            )
            profile = st.text_input(
                "Optional approved profile",
                help="Required for OpenSCAP; ignored by other collectors.",
            )
            submitted = st.form_submit_button("Queue defensive collection")
        if submitted:
            try:
                engagement_id, scope_id = selected_context_ids(client_name)
                job_uuid = enqueue_evidence_job(
                    client_name,
                    tool_id=tool_id,
                    target=target,
                    profile=profile,
                    requested_by=actor,
                    engagement_id=engagement_id,
                    scope_id=scope_id,
                )
            except (EvidenceRepositoryError, ValueError) as exc:
                st.error(str(exc))
            else:
                st.success(f"Collection job {job_uuid} queued for the independent evidence worker.")
    else:
        st.info("Your workspace role has read-only access to collection status.")


def _import_tab(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Import several reports using shared scope and ownership defaults.

    Args:
        client_name: Active workspace.
        actor: Configured identity.
        role: Verified membership role.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected import or persistence errors.
    """
    engagement_id, scope_id = selected_context_ids(client_name)
    allowed = bool(role and role_can(role, "import"))
    defaults = st.session_state.get(f"evidence_defaults::{client_name}", {})
    try:
        settings = load_register(client_name, "tool_settings")["rows"]
    except GrcRepositoryError as exc:
        st.error(str(exc))
        return
    preferences = {item["tool_id"]: item for item in settings}
    sources = [
        tool for tool in TOOLS if preferences.get(tool.tool_id, {}).get("Enabled for import", True)
    ]
    if not sources:
        st.info("Enable at least one source in Tool Catalog to import reports.")
        return
    tool_id = st.selectbox(
        "Evidence source",
        options=[tool.tool_id for tool in sources],
        format_func=lambda value: next(tool.name for tool in sources if tool.tool_id == value),
        key=f"import_source::{client_name}",
        disabled=not allowed,
    )
    preferred = preferences.get(tool_id, {})
    with st.form(f"iso_evidence_report_import::{client_name}"):
        uploads = st.file_uploader(
            "Original reports",
            type=["json", "jsonl", "sarif", "csv", "xml", "dat", "txt"],
            accept_multiple_files=True,
            disabled=not allowed,
        )
        summary = st.text_area("What these reports demonstrate", disabled=not allowed)
        with workflow_section(
            "Scope, ownership and freshness",
            "Identify who owns the evidence, what it covers and when it expires.",
        ):
            scope = st.text_area(
                "Assessment scope covered", value=defaults.get("scope", ""), disabled=not allowed
            )
            source = st.text_input("Asset or source system (optional)", disabled=not allowed)
            owner = st.text_input(
                "Evidence owner",
                value=preferred.get("Evidence owner") or defaults.get("owner") or actor,
                disabled=not allowed,
            )
            age = st.number_input(
                "Freshness period (days)",
                min_value=1,
                max_value=3650,
                value=int(preferred.get("Freshness days") or defaults.get("freshness_days", 90)),
                disabled=not allowed,
            )
        submitted = st.form_submit_button(
            "Import reports for review", disabled=not allowed, type="primary"
        )
    if submitted:
        if not uploads or len(uploads) > 20:
            st.error("Choose between 1 and 20 reports.")
            return
        completed = []
        errors = []
        for uploaded in uploads:
            try:
                evidence_id = ingest_report(
                    client_name,
                    role=role,
                    engagement_id=engagement_id if scope_id else None,
                    scope_id=scope_id,
                    tool_id=tool_id,
                    filename=uploaded.name,
                    content=uploaded.getvalue(),
                    title=uploaded.name,
                    summary=summary,
                    scope_description=scope,
                    source_asset_or_system=source,
                    owner=owner,
                    submitted_by=actor,
                    acceptable_age_days=int(age),
                )
            except (EvidenceServiceError, EvidenceRepositoryError, ValueError) as exc:
                errors.append(f"{uploaded.name}: {exc}")
            else:
                completed.append(f"{uploaded.name} (#{evidence_id})")
        if completed:
            st.success("Imported: " + ", ".join(completed))
        for error in errors:
            st.error(error)


def _manual_tab(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Render manual evidence submission for governance and non-automatable controls."""

    engagement_id, scope_id = selected_context_ids(client_name)
    st.caption(
        f"Evidence will be associated with the current ISMS Scope #{scope_id}."
        if scope_id
        else (
            "No ISMS Scope selected. Evidence will remain unassigned "
            "and visible in All Client Evidence."
        )
    )
    allowed = bool(role and role_can(role, "submit"))
    control_options = list(ISO_CONTROL_CATALOG)
    with st.form(f"iso_manual_evidence::{client_name}"):
        controls = st.multiselect(
            "Related clauses or controls",
            options=control_options,
            format_func=lambda value: f"{value} - {ISO_CONTROL_CATALOG[value]['name']}",
            disabled=not allowed,
        )
        evidence_type = st.selectbox(
            "Evidence type",
            [
                "Policy",
                "Procedure",
                "Record",
                "Interview",
                "Observation",
                "Contract",
                "Meeting minutes",
                "Test result",
            ],
            disabled=not allowed,
        )
        title = st.text_input("Evidence title", disabled=not allowed)
        summary = st.text_area("Evidence summary and conclusion supported", disabled=not allowed)
        scope = st.text_area(
            "Scope covered",
            value=st.session_state.get(f"evidence_defaults::{client_name}", {}).get("scope", ""),
            disabled=not allowed,
        )
        source = st.text_input("Document, process, site or system", disabled=not allowed)
        owner = st.text_input(
            "Evidence owner",
            value=st.session_state.get(f"evidence_defaults::{client_name}", {}).get("owner")
            or actor,
            disabled=not allowed,
        )
        attachment = st.file_uploader("Optional original attachment", disabled=not allowed)
        age = st.number_input(
            "Freshness period (days)",
            min_value=1,
            max_value=3650,
            value=365,
            disabled=not allowed,
        )
        submitted = st.form_submit_button("Submit manual evidence", disabled=not allowed)
    if submitted:
        try:
            evidence_id = submit_manual_evidence(
                client_name,
                role=role,
                engagement_id=engagement_id if scope_id else None,
                scope_id=scope_id,
                control_ids=controls,
                evidence_type=evidence_type,
                title=title,
                summary=summary,
                scope_description=scope,
                source_asset_or_system=source,
                owner=owner,
                submitted_by=actor,
                acceptable_age_days=int(age),
                attachment_filename=attachment.name if attachment else None,
                attachment_content=attachment.getvalue() if attachment else None,
            )
        except (EvidenceServiceError, EvidenceRepositoryError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state[f"evidence_notice::{client_name}"] = (
                f"Manual evidence #{evidence_id} submitted for review."
            )
            st.rerun()


def _review_tab(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Render the consultant-only validation queue."""

    try:
        pending = list_evidence_records(client_name, validation_status="Pending")
    except EvidenceRepositoryError as exc:
        st.warning(str(exc))
        return
    if not pending:
        st.info("No evidence is awaiting consultant review.")
        return
    allowed = bool(role and role_can(role, "review"))
    selected_id = st.selectbox(
        "Evidence awaiting review",
        [item["id"] for item in pending],
        format_func=lambda value: next(
            f"#{item['id']} · {item['title']} · {item['tool_id']}"
            for item in pending
            if item["id"] == value
        ),
    )
    selected = next(item for item in pending if item["id"] == selected_id)
    st.write("**Summary:** " + str(selected.get("summary") or "Not recorded"))
    st.write("**Scope:** " + str(selected.get("scope_description") or "Not recorded"))
    st.write("**Asset / System:** " + str(selected.get("source_asset_or_system") or "Not recorded"))
    st.caption(
        f"{selected.get('observation_count', 0)} observations · Source {selected.get('tool_id')}"
    )
    st.write(
        "Suggested Controls: "
        + ", ".join(str(c.get("control_id")) for c in selected.get("controls", []))
    )
    if role == WorkspaceRole.ADMINISTRATOR:
        with st.expander("Technical Audit Details"):
            st.write("SHA-256: " + str(selected.get("sha256") or "Not recorded"))
    if selected.get("storage_reference"):
        try:
            original = read_artifact(
                get_client_id(client_name, create=False),
                str(selected["storage_reference"]),
                expected_sha256=selected.get("sha256"),
            )
        except (DatabaseError, EvidenceStorageError, ValueError) as exc:
            st.warning(f"Original report preview is unavailable: {exc}")
        else:
            st.download_button(
                "Download original report for review",
                original,
                file_name=str(selected.get("original_filename") or "evidence.bin"),
                mime="application/octet-stream",
            )
    suggested = [
        item["control_id"]
        for item in selected.get("controls") or []
        if item["control_id"] in ISO_CONTROL_CATALOG
    ]
    with st.form(f"iso_evidence_consultant_review::{client_name}::{selected_id}"):
        decision = st.selectbox(
            "Decision", [item.value for item in ReviewDecision], disabled=not allowed
        )
        approved = st.multiselect(
            "Approved control mappings",
            options=list(ISO_CONTROL_CATALOG),
            default=suggested,
            format_func=lambda value: f"{value} - {ISO_CONTROL_CATALOG[value]['name']}",
            disabled=not allowed,
        )
        comment = st.text_area("Consultant rationale", disabled=not allowed)
        submitted = st.form_submit_button("Record consultant decision", disabled=not allowed)
    if not allowed:
        st.info("Only a Consultant or Administrator can validate evidence.")
    if submitted:
        try:
            consultant_review(
                client_name,
                int(selected_id),
                role=role,
                decision=decision,
                validator=actor,
                comment=comment,
                approved_controls=approved,
            )
        except (EvidenceServiceError, EvidenceRepositoryError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state[f"evidence_notice::{client_name}"] = (
                "Consultant decision recorded. No control status was changed automatically."
            )
            st.rerun()


def _requests_tab(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Render manual evidence requests and their deadlines."""

    try:
        requests = list_evidence_requests(client_name)
    except EvidenceRepositoryError as exc:
        st.warning(str(exc))
        requests = []
    if requests:
        st.dataframe(pd.DataFrame(requests), hide_index=True, width="stretch")
    allowed = bool(role and role_can(role, "review"))
    if requests:
        with workflow_section(
            "Update an existing request", "Select a request and record its current progress."
        ):
            selected_id = st.selectbox(
                "Request",
                [row["id"] for row in requests],
                format_func=lambda value: next(
                    f"#{row['id']} · {row['title']}" for row in requests if row["id"] == value
                ),
                key=f"request_selected::{client_name}",
            )
            selected = next(row for row in requests if row["id"] == selected_id)
            try:
                responses = list_evidence_records(client_name)
            except EvidenceRepositoryError as exc:
                st.error(str(exc))
                responses = []
            can_submit = bool(role and role_can(role, "submit"))
            with st.form(f"request_update::{client_name}::{selected_id}"):
                left, right = st.columns(2)
                assignee = left.text_input(
                    "Assigned to", value=selected["assigned_to"], disabled=not allowed
                )
                deadline = right.date_input(
                    "Delivery date", value=selected["due_date"], disabled=not allowed
                )
                statuses = (
                    ["Open", "Submitted", "Accepted", "Rejected", "Cancelled"]
                    if allowed
                    else ["Submitted"]
                )
                status = left.selectbox(
                    "Request status",
                    statuses,
                    index=(
                        statuses.index(selected["status"]) if selected["status"] in statuses else 0
                    ),
                )
                evidence_id = right.selectbox(
                    "Response evidence",
                    [None, *[row["id"] for row in responses]],
                    format_func=lambda value: (
                        "No response linked"
                        if value is None
                        else next(
                            f"#{row['id']} · {row['title']}"
                            for row in responses
                            if row["id"] == value
                        )
                    ),
                )
                update_clicked = st.form_submit_button(
                    "Save request changes", disabled=not can_submit
                )
            if update_clicked:
                try:
                    update_evidence_request(
                        client_name,
                        int(selected_id),
                        actor=actor,
                        expected_status=selected["status"],
                        status=status,
                        assigned_to=assignee,
                        due_date=deadline,
                        response_evidence_id=evidence_id,
                    )
                except EvidenceRepositoryError as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
    with st.form(f"iso_evidence_request::{client_name}"):
        control_id = st.selectbox(
            "Clause or control",
            options=list(ISO_CONTROL_CATALOG),
            format_func=lambda value: f"{value} - {ISO_CONTROL_CATALOG[value]['name']}",
            disabled=not allowed,
        )
        title = st.text_input("Request title", disabled=not allowed)
        requested = st.text_area("Required evidence and acceptance criteria", disabled=not allowed)
        assigned = st.text_input("Assigned client contributor", disabled=not allowed)
        due = st.date_input(
            "Due date", value=date.today() + timedelta(days=14), disabled=not allowed
        )
        submitted = st.form_submit_button("Create evidence request", disabled=not allowed)
    if submitted:
        try:
            request_id = request_manual_evidence(
                client_name,
                role=role,
                control_id=control_id,
                title=title,
                requested_evidence=requested,
                assigned_to=assigned,
                due_date=due,
                requested_by=actor,
            )
        except (EvidenceServiceError, EvidenceRepositoryError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.success(f"Evidence request #{request_id} created.")
            st.rerun()


def _auditor_tab(client_name: str, actor: str, role: WorkspaceRole | None) -> None:
    """Prepare persistent download controls for the chosen audit scope.

    Args:
        client_name: Active workspace.
        actor: Configured identity.
        role: Verified workspace role.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected report preparation errors.
    """
    allowed = bool(role and role_can(role, "export"))
    scope = st.text_area(
        "Assessment scope for the deliverable",
        value=st.session_state.get(f"evidence_defaults::{client_name}", {}).get("scope", ""),
        disabled=not allowed,
        key=f"auditor_scope::{client_name}",
    )
    include_raw = st.checkbox(
        "Include validated original evidence",
        value=True,
        disabled=not allowed,
        key=f"auditor_raw::{client_name}",
    )
    pdf_column, zip_column = st.columns(2)
    if pdf_column.button(
        "Prepare printable PDF", disabled=not allowed, key=f"auditor_prepare_pdf::{client_name}"
    ):
        try:
            st.session_state[f"auditor_pdf::{client_name}"] = build_control_matrix_pdf(
                client_name, prepared_by=actor, assessment_scope=scope
            )
        except (AuditorPackageError, EvidenceRepositoryError, ValueError) as exc:
            st.error(str(exc))
    if zip_column.button(
        "Prepare auditor ZIP",
        type="primary",
        disabled=not allowed,
        key=f"auditor_prepare_zip::{client_name}",
    ):
        try:
            st.session_state[f"auditor_zip::{client_name}"] = build_auditor_package(
                client_name,
                prepared_by=actor,
                assessment_scope=scope,
                include_raw_evidence=include_raw,
            )
        except (AuditorPackageError, EvidenceRepositoryError, ValueError) as exc:
            st.error(str(exc))
    for suffix, label, mime in (
        ("pdf", "Control matrix", "application/pdf"),
        ("zip", "Auditor package", "application/zip"),
    ):
        data = st.session_state.get(f"auditor_{suffix}::{client_name}")
        if data is not None and allowed:
            st.download_button(
                f"Download {label}",
                data,
                file_name=f"ISO-{suffix}-package.{suffix}",
                mime=mime,
                on_click="ignore",
                key=f"auditor_download_{suffix}::{client_name}",
            )
    if not allowed:
        st.info(
            "A Consultant, Administrator or Auditor membership is needed to prepare audit exports."
        )


def render_iso_evidence_hub(
    client_name: str,
    *,
    embedded: bool = False,
) -> None:
    """Render the workspace-scoped ISO evidence workflow.

    Args:
        client_name: Exact active workspace name.
        embedded: When ``True``, place the complete Evidence Hub workflow inside
            Control Assurance without removing any original tables or actions.

    Returns:
        None.

    Raises:
        ValueError: Never raised; known permission and repository failures are
            displayed as safe UI states.
    """

    from securescope.ui.evidence_collection_context import render_collection_return

    render_collection_return(client_name)
    notice = st.session_state.pop(f"evidence_notice::{client_name}", None)
    if notice:
        st.success(notice)
    actor, role = _identity(client_name)
    if not embedded:
        st.title("Evidence operations")
        st.caption(
            "Collect, verify and trace technical and manual evidence to the current "
            "engagement and ISMS scope. Source verification is separate from human ISO assessment."
        )
    if role is None:
        st.warning(
            "No active workspace identity is configured, so evidence editing is unavailable."
        )
        with workflow_section(
            "Enable workspace access",
            "Configure access before contributors can work in this workspace.",
        ):
            st.write(
                (
                    "On the computer running SecureScope, run the access setup once, "
                    "enter this workspace's exact name and your identity, then restart"
                    " the app."
                )
            )
            with st.expander("Technical details · Host setup"):
                st.caption("Use Client Workspace to configure access on the SecureScope host.")
            st.caption(
                (
                    "Workspace: "
                    f"{client_name}"
                    ". Existing roles remain enforced; remote visitors cannot "
                    "grant themselves access."
                )
            )
    else:
        from securescope.ui.components.primitives import identity_context

        identity_context(actor, role.value)
    try:
        saved_defaults = load_register(client_name, "evidence_defaults")
    except GrcRepositoryError as exc:
        st.error(str(exc))
        return
    defaults = saved_defaults["rows"][0] if saved_defaults["rows"] else {}
    st.session_state[f"evidence_defaults::{client_name}"] = defaults
    labels = [
        "Overview",
        "Evidence Register",
        "Collect Evidence",
        "Import Reports",
        "Manual Evidence",
        "Consultant Review",
        "Evidence Requests",
        "Auditor Package",
        "Evidence Settings",
    ]
    # Legacy renderer references remain documented here so embedded and standalone
    # workflows keep the same callable contract while using shared role-aware tabs:
    # _overview(client_name), _tool_catalog(), _collect_tab(client_name, actor, role),
    # _import_tab(client_name, actor, role), _manual_tab(client_name, actor, role),
    # _review_tab(client_name, actor, role), _requests_tab(client_name, actor, role),
    # _auditor_tab(client_name, actor, role)
    renderers = [
        lambda: _overview(client_name),
        lambda: _evidence_register(client_name, actor, role),
        lambda: _collect_tab(client_name, actor, role),
        lambda: _import_tab(client_name, actor, role),
        lambda: _manual_tab(client_name, actor, role),
        lambda: _review_tab(client_name, actor, role),
        lambda: _requests_tab(client_name, actor, role),
        lambda: _auditor_tab(client_name, actor, role),
        lambda: _evidence_settings(client_name, actor, role, saved_defaults),
    ]
    if role and role.value == "Auditor":
        visible = [0, 1, 6, 7]
        labels = [labels[index] for index in visible]
        renderers = [renderers[index] for index in visible]
    tab_key = f"evidence_section::{client_name}"
    if st.session_state.get(tab_key) not in labels:
        st.session_state[tab_key] = "Overview" if embedded else "Evidence Register"
    selected = section_navigation("Evidence workspace", labels, key=tab_key)
    with selected.panel:
        renderers[labels.index(selected)]()


def _evidence_settings(client_name, actor, role, saved_defaults):
    """Keep source setup and submission defaults outside the auditor read view.

    Args:
        client_name: Active workspace.
        actor: Session principal.
        role: Authorized workspace role.
        saved_defaults: Versioned existing settings record.
    Returns:
        None.
    Raises:
        Expected repository failures are displayed inline.
    """
    defaults = saved_defaults["rows"][0] if saved_defaults["rows"] else {}
    with workflow_section(
        "Shared evidence defaults",
        "Review the scope and ownership applied to evidence submissions.",
    ):
        scope = st.text_area(
            "Default scope",
            value=defaults.get("scope", ""),
            key=f"evidence_scope_default::{client_name}",
        )
        owner = st.text_input(
            "Default owner",
            value=defaults.get("owner") or actor,
            key=f"evidence_owner_default::{client_name}",
        )
        freshness = st.number_input(
            "Default freshness days",
            min_value=1,
            max_value=3650,
            value=int(defaults.get("freshness_days", 90)),
            key=f"evidence_age_default::{client_name}",
        )
        if st.button(
            "Save defaults",
            disabled=not (role and role_can(role, "submit")),
            key=f"evidence_defaults_save::{client_name}",
        ):
            try:
                save_register(
                    client_name,
                    "evidence_defaults",
                    [{"scope": scope, "owner": owner, "freshness_days": int(freshness)}],
                    actor=actor,
                    expected_revision=saved_defaults["revision"],
                )
            except (GrcRepositoryError, ValueError) as exc:
                st.error(str(exc))
            else:
                st.rerun()
    _tool_catalog(client_name, actor, role)


def _evidence_register(client_name, actor, role):
    """Present canonical evidence metadata and details without loading raw reports.

    Args:
        client_name: Active workspace.
        actor: Session principal.
        role: Authorized workspace role.
    Returns:
        None.
    Raises:
        Expected repository errors are displayed inline.
    """
    from securescope.ui.grc_workspace.context import selected_context_ids

    engagement, scope = selected_context_ids(client_name)
    view = st.selectbox(
        "Evidence scope",
        ["Current ISMS Scope", "All Client Evidence"] if scope else ["All Client Evidence"],
        key=f"evidence_scope_view::{client_name}::{engagement}::{scope}",
    )
    try:
        records = list_evidence_records(
            client_name,
            scope_id=scope if view == "Current ISMS Scope" else None,
            engagement_id=engagement,
        )
    except EvidenceRepositoryError as exc:
        st.error(f"Evidence register could not be loaded: {exc}")
        return
    st.subheader("Evidence Register")
    if not records:
        st.info("No supporting evidence is available in this view yet.")
        if role and role.value != "Auditor" and st.button(
            "Open automated collection",
            icon=":material/play_arrow:",
            key=f"empty_evidence_collect::{client_name}",
        ):
            st.session_state[f"evidence_section::{client_name}"] = "Collect Evidence"
            st.rerun()
        return
    columns = st.columns(3)
    source = columns[0].selectbox("Source", ["All", *sorted({r["tool_id"] for r in records})])
    status = columns[1].selectbox(
        "Review status",
        ["All", "Pending", "Validated", "Rejected", "More evidence required"],
        format_func=lambda v: {"Pending": "Unreviewed", "Validated": "Accepted"}.get(v, v),
    )
    freshness = columns[2].selectbox(
        "Freshness", ["All", "Current", "Expiring Soon", "Stale", "Unknown"]
    )
    controls = sorted({c["control_id"] for r in records for c in r.get("controls", [])})
    control_options = ["All", *controls]
    pending_control = st.session_state.pop(f"evidence_control_pending::{client_name}", None)
    control_key = f"evidence_control_filter::{client_name}::{scope}"
    if pending_control in control_options:
        st.session_state[control_key] = pending_control
    if st.session_state.get(control_key) not in control_options:
        st.session_state.pop(control_key, None)
    control = st.selectbox("Requirement / Control", control_options, key=control_key)
    query = st.text_input(
        "Search evidence",
        placeholder="Title, source, scope or reviewer",
        key=f"evidence_search::{client_name}::{engagement}::{scope}",
    )
    normalized_query = query.strip().casefold()
    with st.expander("Advanced evidence filters"):
        reviewer = st.text_input("Reviewer search")
        scope_text = st.text_input("Scope search")
    selected = [
        r
        for r in records
        if (source == "All" or r["tool_id"] == source)
        and (status == "All" or r["validation_status"] == status)
        and (freshness == "All" or r["freshness_status"] == freshness)
        and (control == "All" or any(c["control_id"] == control for c in r.get("controls", [])))
        and reviewer.casefold() in str(r.get("validator") or "").casefold()
        and scope_text.casefold() in str(r.get("scope_description") or "").casefold()
        and (
            not normalized_query
            or normalized_query
            in " ".join(
                str(r.get(field) or "")
                for field in ("title", "tool_id", "scope_description", "validator")
            ).casefold()
        )
    ]
    st.caption(f"{len(selected)} of {len(records)} evidence records")
    if not selected:
        st.info("No evidence matches these filters.")
        return
    display = [
        {
            "Evidence": r["title"],
            "Source": r["tool_id"],
            "Controls": ", ".join(c["control_id"] for c in r.get("controls", [])),
            "Scope": r.get("scope_description") or "Unassigned",
            "Status": (
                "Source requires review"
                if r.get("source_verification_current") is False
                else (
                    "System verified"
                    if r.get("verification_origin") == "System collector"
                    else {"Pending": "Unreviewed", "Validated": "Accepted"}.get(
                        r["validation_status"], r["validation_status"]
                    )
                )
            ),
            "Collected": r.get("collected_at"),
            "Expires": r.get("expires_at"),
            "Freshness": r["freshness_status"],
            "Reviewer": r.get("validator") or "—",
        }
        for r in selected
    ]
    event = st.dataframe(
        display,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key=(
            f"evidence_register::{client_name}::{engagement}::{scope}::{view}::"
            f"{source}::{status}::{freshness}::{control}::{query}::{reviewer}::{scope_text}"
        ),
    )
    if event.selection.rows and 0 <= event.selection.rows[0] < len(selected):
        record = selected[event.selection.rows[0]]
        with st.container(border=True):
            st.subheader(record["title"])
            st.write(record.get("summary") or "No evidence summary recorded.")
            if record.get("source_review_reason"):
                st.warning(record["source_review_reason"])
            st.table(
                {
                    "Field": [
                        "Source",
                        "Collection method",
                        "Owner",
                        "Freshness",
                        "Collected",
                        "Expires",
                        "Scope",
                        "Reviewer",
                        "Validation",
                    ],
                    "Value": [
                        str(record.get(k) or "—")
                        for k in [
                            "tool_id",
                            "collection_method",
                            "owner",
                            "freshness_status",
                            "collected_at",
                            "expires_at",
                            "scope_description",
                            "validator",
                            "validation_status",
                        ]
                    ],
                }
            )
            for linked_control in record.get("controls", []):
                if st.button(
                    "Open " + linked_control["control_id"],
                    key=f"ev_control::{record['id']}::{linked_control['control_id']}",
                ):
                    from securescope.ui.control_workspace import open_control_workspace

                    open_control_workspace(client_name, linked_control["control_id"])
            from securescope.ui.evidence_collection_context import current_collection_context

            origin = current_collection_context(client_name)
            if origin.get("mode") == "link" and role and role_can(role, "review"):
                from securescope.persistence.assurance_workspace_repository import (
                    load_workspace,
                    save_requirements,
                )
                from securescope.persistence.foundation_repository import FoundationError

                rationale = st.text_area(
                    "Why this evidence supports the requirement", key="requirement_link_rationale"
                )
                if st.button(
                    "Link to Requirement",
                    disabled=not rationale.strip(),
                    key="requirement_link_confirm",
                ):
                    try:
                        view = load_workspace(
                            client_name, origin["control_id"], actor, engagement, scope
                        )
                        bundle = view["bundle"]
                        if record["id"] not in {e["id"] for e in bundle["requirement_evidence"]}:
                            raise FoundationError(
                                "Select evidence already mapped to this control and scope."
                            )
                        profile = bundle["profile"]
                        config = profile["assessment_scope"]["implementation_requirements"]
                        requirements = [dict(r) for r in config["requirements"]]
                        requirement = next(
                            r for r in requirements if r["id"] == origin["requirement_id"]
                        )
                        links = [
                            r
                            for r in requirement.get("evidence_links", [])
                            if r["evidence_id"] != record["id"]
                        ]
                        requirement["evidence_links"] = [
                            *links,
                            dict(
                                evidence_id=record["id"], rationale=rationale, conclusion="UNKNOWN"
                            ),
                        ]
                        save_requirements(
                            client_name,
                            origin["control_id"],
                            actor,
                            engagement,
                            scope,
                            int(profile["profile_version"]),
                            requirements,
                            auto=bool(config.get("continuous_auto_assurance")),
                            owner=profile.get("control_owner") or actor,
                        )
                    except (FoundationError, GrcRepositoryError, StopIteration) as exc:
                        st.error(f"Requirement evidence link failed: {exc}")
                    else:
                        st.success("Evidence linked directly to the originating requirement.")
            with st.expander("Audit Details"):
                st.write("Evidence ID: " + str(record["id"]))
                st.write("SHA-256: " + str(record.get("sha256") or "Not recorded"))
                st.write(
                    "Source reference: "
                    + str(record.get("source_asset_or_system") or "Not recorded")
                )
