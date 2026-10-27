"""Client-scoped dashboard and implementation tracker inside Control Assurance."""

from __future__ import annotations

import csv
import io
import logging
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any

import pandas as pd
import streamlit as st

from securescope.grc.gap_dashboard import (
    RESULT_STATES,
    STANDARD_AREAS,
    area_summaries,
    dashboard_entries,
    summarize_entries,
)
from securescope.grc.isms_project_plan import (
    ProjectTaskUpdate,
    project_task_rows,
    project_totals,
)
from securescope.persistence.audit_scope_repository import default_schedule_rows, load_audit_scope
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.grc_repository import (
    GrcRepositoryError,
    latest_statement_of_applicability,
)
from securescope.persistence.isms_project_repository import (
    ProjectPlanError,
    load_project_plan,
    save_project_task,
)
from securescope.persistence.migration_service import MigrationError
from securescope.persistence.risk_register_repository import list_risk_register
from securescope.reporting.iso_assurance_export import build_iso_assurance_workbook
from securescope.reporting.spreadsheet_safety import spreadsheet_text
from securescope.ui.assurance_interactions import open_control_assessment
from securescope.ui.components.dashboard import DashboardMetric, render_dashboard_metrics
from securescope.ui.control_presenter import human_assessment_label
from securescope.ui.gap_charts import (
    conformity_chart,
    counts_chart,
    project_timeline,
    radar_chart,
)
from securescope.ui.project_planner_ui import render_batch_planner

LOGGER = logging.getLogger(__name__)
DASHBOARD_TAB = ":material/radar: Gap dashboard"
PROJECT_PLAN_TAB = ":material/event_note: Project plan"


def select_assurance_tab(client_name: str, tab: str) -> None:
    """Keep a dashboard or plan widget in its active workspace tab on rerun.

    Args:
        client_name: Exact active workspace.
        tab: Display label of an existing assurance tab.

    Returns:
        None. Updates session navigation state from a widget callback.

    Raises:
        StreamlitAPIException: If called after tab instantiation outside a callback.
    """

    st.session_state[f"assurance_active_tab::{client_name}"] = tab


def csv_export(records: Sequence[Mapping[str, Any]]) -> bytes:
    """Encode displayed records as an Excel-friendly CSV with formula protection.

    Args:
        records: Ordered mappings sharing a common column set.

    Returns:
        UTF-8 BOM-prefixed bytes. Dates remain ISO formatted; None remains blank.

    Raises:
        ValueError: If rows contain inconsistent column names.
    """

    if not records:
        return b""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(records[0]))
    writer.writeheader()
    for record in records:
        sanitized = {}
        for key, value in record.items():
            if isinstance(value, str):
                value = spreadsheet_text(value)
            sanitized[key] = value
        writer.writerow(sanitized)
    return stream.getvalue().encode("utf-8-sig")


def _percent(value: float | None) -> str:
    """Format a measured percent without fabricating a zero denominator.

    Args:
        value: Percentage or None.

    Returns:
        Human-readable percentage or an em dash.

    Raises:
        No exceptions are raised.
    """

    return f"{value:.1f}%" if value is not None else "—"


def render_gap_dashboard(client_name: str, rows: Sequence[Mapping[str, Any]]) -> None:
    """Render summary, three charts and assessment drilldown from one data snapshot.

    Args:
        client_name: Active workspace name.
        rows: Workspace-scoped current control overview.

    Returns:
        None. Renders the interactive assurance dashboard.

    Raises:
        ValueError: If source assessment records contain malformed values.
    """

    from securescope.ui.assurance_dashboard import render_assurance_dashboard

    if render_assurance_dashboard(client_name, list(rows)):
        return
    entries = dashboard_entries(rows)
    areas = area_summaries(entries)
    total = summarize_entries(entries)
    heading, refresh = st.columns([4, 1], vertical_alignment="center")
    with heading:
        st.subheader("ISO/IEC 27001 Gap Assessment")
        st.caption(
            f"{client_name} · Latest recorded assessments · "
            f"Refreshed {datetime.now(timezone.utc):%d %b %Y, %H:%M UTC}"
        )
    with refresh:
        st.button(
            "Refresh results",
            icon=":material/refresh:",
            key=f"gap_refresh::{client_name}",
            on_click=select_assurance_tab,
            args=(client_name, DASHBOARD_TAB),
        )
    render_dashboard_metrics(
        [
            DashboardMetric(
                "Conformity",
                _percent(total["conformity"]) if total["assessed"] else "Not Assessed",
                f'{total["met"]} of {total["in_scope"]} in-scope entries met',
                1,
            ),
            DashboardMetric(
                "Assessment coverage",
                _percent(total["assessment_coverage"]),
                f'{total["not_assessed"]} entries not assessed',
                2,
            ),
            DashboardMetric(
                "Gaps",
                str(total["not_met"] + total["partial"]) if total["assessed"] else "Not Determined",
                "Not met or partially met",
                3,
            ),
            DashboardMetric(
                "Review required",
                str(total["review_required"]),
                "Evidence, validation or applicability",
                4,
            ),
        ]
    )
    if total["assessed"] == 0:
        st.info("No in-scope assessment has been recorded yet. Choose an entry below to begin.")
    compact = [
        {
            "Area of standard": area["area"],
            "Entries": area["entries"],
            "In scope": area["in_scope"],
            "Met": area["met"],
            "Conformity (%)": area["conformity"],
        }
        for area in [*areas, {"area": "Total", **total}]
    ]
    table, radar = st.columns([1.3, 1], gap="medium")
    with table, st.container(border=True):
        st.markdown("**Gap assessment results**")
        st.dataframe(
            pd.DataFrame(compact),
            hide_index=True,
            width="stretch",
            height=460,
            column_config={
                "Conformity (%)": st.column_config.ProgressColumn(
                    "Conformity", min_value=0, max_value=100, format="%.1f%%"
                )
            },
        )
    if total["assessed"]:
        with radar, st.container(border=True):
            st.markdown("**Conformity by standard area**")
            st.vega_lite_chart(
                spec=radar_chart(areas),
                width="stretch",
                theme=None,
                key=f"gap_radar::{client_name}",
            )
            st.caption("Hover over a point for its area and counts. All axes use 0–100%.")
    else:
        with radar:
            st.info("No assessed controls yet. Complete an assessment to populate this chart.")
    count_column, percent_column = st.columns(2, gap="medium")
    with count_column, st.container(border=True):
        st.markdown("**In-scope entries and entries met**")
        st.vega_lite_chart(
            spec=counts_chart(areas), width="stretch", theme=None, key=f"gap_counts::{client_name}"
        )
    with percent_column, st.container(border=True):
        st.markdown("**Percentage of entries met**")
        if total["assessed"]:
            st.vega_lite_chart(
                spec=conformity_chart(areas),
                width="stretch",
                theme=None,
                key=f"gap_percent::{client_name}",
            )
        else:
            st.caption("No assessed controls yet.")
    with st.expander("Calculation method and detailed counts"):
        st.write(
            "Conformity = met ÷ in-scope entries × 100. An entry is met only when the latest "
            "assessment is Implemented and effective, is validated, and has current validated "
            "evidence. Partial results, achieved targets and accepted risk do not count as met. "
            "Not-assessed entries remain in the denominator."
        )
        st.write(
            "Only justified Annex A exclusions in the latest approved Statement of Applicability "
            "are removed from scope. Clauses 4–10 stay in scope. An empty denominator is N/A. "
            "Totals are calculated from entry counts, not an average of area percentages."
        )
        st.caption(
            "Assessment basis: 30 clause entries + 93 Annex A controls = 123 catalog units. "
            "The supplied spreadsheet uses 47 clause checklist items (140 total); those detailed "
            "items have not been provided. This dashboard measures the SecureScope catalog and "
            "does not constitute a certification decision."
        )
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Area": a["area"],
                        "Partial": a["partial"],
                        "Not met": a["not_met"],
                        "Not assessed": a["not_assessed"],
                        "Review required": a["review_required"],
                        "Excluded": a["excluded"],
                    }
                    for a in areas
                ]
            ),
            hide_index=True,
            width="stretch",
        )
        st.markdown(
            "Framework reference: [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)."
        )
    export_columns = st.columns(2, gap="small")
    with export_columns[0]:
        st.download_button(
            "Export area summary CSV",
            csv_export(compact),
            "iso_gap_summary.csv",
            "text/csv",
            key=f"gap_summary_export::{client_name}",
            on_click="ignore",
        )
    with export_columns[1]:
        try:
            from securescope.ui.grc_workspace.context import selected_context_ids

            engagement_id, scope_id = selected_context_ids(client_name)
            latest_soa = latest_statement_of_applicability(
                client_name, engagement_id=engagement_id, scope_id=scope_id
            )
            audit_scope = load_audit_scope(client_name)
            risks = list_risk_register(client_name)
        except (GrcRepositoryError, DatabaseConfigurationError):
            latest_soa = None
            audit_scope = None
            risks = []
        soa_rows = list((latest_soa or {}).get("items") or [])
        if not soa_rows:
            soa_rows = [
                {
                    "control_id": row.get("control_id"),
                    "control_name": row.get("control_name"),
                    "applicability": row.get("applicability") or "Applicable",
                    "implementation_status": row.get("assessment_status") or "Not assessed",
                    "control_owner": row.get("control_owner") or "Unassigned",
                }
                for row in rows
                if str(row.get("control_id") or "").startswith("A.")
            ]
        try:
            workbook_bytes = build_iso_assurance_workbook(
                client_name=client_name,
                gap_rows=rows,
                soa_rows=soa_rows,
                audit_scope=audit_scope,
                schedule_rows=list((audit_scope or {}).get("schedule") or default_schedule_rows()),
                risks=risks,
            )
        except Exception as exc:  # pragma: no cover - defensive UI boundary
            st.caption(f"Excel export unavailable: {type(exc).__name__}: {exc}")
        else:
            safe_name = "".join(
                char if char.isalnum() or char in "-_" else "_" for char in client_name
            )
            st.download_button(
                "Export Excel workbook + charts",
                workbook_bytes,
                f"securescope_iso_assurance_{safe_name}.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"gap_workbook_export::{client_name}",
                icon=":material/table_view:",
                on_click="ignore",
            )
    _render_assessment_drilldown(client_name, entries, rows)


def _render_assessment_drilldown(
    client_name: str,
    entries: Sequence[Mapping[str, Any]],
    source_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Filter assessment units and open their existing human review workflow.

    Args:
        client_name: Active workspace.
        entries: Complete classified catalog entries.
        source_rows: Existing profile rows available for editing.

    Returns:
        None.

    Raises:
        KeyError: If the supplied entry structure is incomplete.
    """

    st.markdown("**Explore the results**")
    area_column, result_column = st.columns(2)
    with area_column:
        area = st.selectbox(
            "Area of standard",
            ["All areas", *[f"{c} {label}" for c, label in STANDARD_AREAS]],
            key=f"gap_area::{client_name}",
            on_change=select_assurance_tab,
            args=(client_name, DASHBOARD_TAB),
        )
    with result_column:
        result = st.selectbox(
            "Result",
            ["All results", *RESULT_STATES],
            key=f"gap_result::{client_name}",
            on_change=select_assurance_tab,
            args=(client_name, DASHBOARD_TAB),
        )
    selected = [
        entry
        for entry in entries
        if (area == "All areas" or entry["area"] == area.split(" ")[0])
        and (result == "All results" or entry["result"] == result)
    ]
    if not selected:
        st.info("No entries match these filters.")
        return
    detail = [
        {
            "Reference": e["control_id"],
            "Entry": e["control_name"],
            "Result": e["result"],
            "Human Assessment": human_assessment_label(e.get("assessment_status")),
            "Owner": e.get("control_owner") or "Unassigned",
        }
        for e in selected
    ]
    st.dataframe(pd.DataFrame(detail), hide_index=True, width="stretch", height=320)
    st.download_button(
        "Export filtered entries CSV",
        csv_export(detail),
        "iso_gap_entries.csv",
        "text/csv",
        key=f"gap_detail_export::{client_name}",
        on_click="ignore",
    )
    available = {row["control_id"] for row in source_rows}
    choices = {
        e["control_id"]: f'{e["control_id"]} · {e["control_name"]}'
        for e in selected
        if e["control_id"] in available
    }
    if choices:
        selected_id = st.selectbox(
            "Entry to assess",
            list(choices),
            format_func=choices.get,
            key=f"gap_assess_entry::{client_name}",
            on_change=select_assurance_tab,
            args=(client_name, DASHBOARD_TAB),
        )
        st.button(
            "Assess selected entry",
            type="primary",
            key=f"gap_assess::{client_name}",
            on_click=open_control_assessment,
            args=(client_name, selected_id),
        )


def _reload_task(client_name: str, task_ref: int) -> None:
    """Discard one stale draft and reload the saved task on the next rerun.

    Args:
        client_name: Active workspace.
        task_ref: Selected task reference.

    Returns:
        None. Clears this task's draft widget keys and revision snapshot.

    Raises:
        No exceptions are raised.
    """

    prefix = f"plan_edit::{client_name}::{task_ref}::"
    for key in list(st.session_state):
        if str(key).startswith(prefix):
            del st.session_state[key]
    st.session_state.pop(f"plan_snapshot::{client_name}::{task_ref}", None)
    select_assurance_tab(client_name, PROJECT_PLAN_TAB)


def render_project_plan(client_name: str) -> None:
    """Render the thirty-task plan, weekday scheduling and persistent editing.

    Args:
        client_name: Active client workspace name.

    Returns:
        None. Persistence failures are displayed without presenting empty success.

    Raises:
        ValueError: If stored task values are malformed.
    """

    try:
        saved = load_project_plan(client_name)
    except (ProjectPlanError, MigrationError, DatabaseConfigurationError) as exc:
        LOGGER.error("Project plan unavailable for %s: %s", client_name, exc)
        st.error(f"Project plan is unavailable: {exc}")
        return
    rows = project_task_rows(saved["tasks"])
    total = project_totals(rows, date.today())
    message = st.session_state.pop(f"plan_success::{client_name}", None)
    if message:
        st.success(message)
    if st.session_state.get(f"plan_mode::{client_name}") == "Plan in one pass":
        if st.button("← Back to Project Plan", key=f"plan_back::{client_name}"):
            st.session_state.pop(f"plan_mode::{client_name}", None)
            st.rerun()
        render_batch_planner(client_name, rows)
        return
    table = [
        {
            "Ref": r["task_ref"],
            "Task": r["task"] + (" (summary)" if r["task_ref"] == 15 else ""),
            "Main ISO 27001 ref": r["iso_ref"],
            "Owner": r["resource"],
            "Start date": r["start_date"],
            "Work days": r["work_days"],
            "End date": r["end_date"],
            "Completed days": r["completed_days"],
            "Progress (%)": r["progress"],
            "Status": (
                "Completed"
                if r["progress"] == 100
                else "In Progress" if (r["progress"] or 0) > 0 else "Not Started"
            ),
        }
        for r in rows
    ]
    from securescope.ui.components_v2.assurance_plan import render_plan_view

    def plan_action(event):
        select_assurance_tab(client_name, PROJECT_PLAN_TAB)
        mode_key = f"plan_mode::{client_name}"
        if event.get("action") == "batch":
            st.session_state[mode_key] = "Plan in one pass"
            st.rerun()
        elif event.get("action") == "edit":
            ref = event.get("ref")
            valid_refs = {row["task_ref"] for row in rows if row["task_ref"] != 15}
            if ref is not None and ref not in valid_refs:
                return
            st.session_state[mode_key] = "Edit a task"
            if ref is not None:
                st.session_state[f"plan_task::{client_name}"] = ref

    render_plan_view(client_name, table, total, plan_action)
    edit_mode = st.session_state.get(f"plan_mode::{client_name}")
    if edit_mode == "Edit a task":
        _project_task_dialog(client_name, rows)
    with st.expander("Saved project timeline", expanded=False):
        if any(row["end_date"] for row in rows):
            st.vega_lite_chart(spec=project_timeline(rows), width="stretch", theme=None)
        else:
            st.info("Generate and save a schedule to display the timeline.")
    if saved["events"]:
        with st.expander("Recent project changes"):
            st.dataframe(
                pd.DataFrame(saved["events"]).rename(
                    columns={
                        "task_ref": "Task",
                        "revision": "Revision",
                        "actor": "Recorded by",
                        "created_at": "Saved at",
                    }
                ),
                hide_index=True,
                width="stretch",
            )


def _dismiss_task_dialog() -> None:
    """Clear the active task dialog intent; return None; raise no expected errors."""
    client = st.session_state.pop("plan_dialog_client", None)
    if client:
        st.session_state.pop(f"plan_mode::{client}", None)


@st.dialog("Edit Project Task", width="large", on_dismiss=_dismiss_task_dialog)
def _project_task_dialog(client_name: str, rows: Sequence[Mapping[str, Any]]) -> None:
    """Open the existing revision-checked editor in a focused dialog.

    Args:
        client_name: Active workspace name.
        rows: Authorized canonical task rows.
    Returns:
        None.
    Raises:
        StreamlitAPIException: For invalid dialog rendering.
    """
    st.session_state["plan_dialog_client"] = client_name
    _render_task_editor(client_name, rows)
    if st.button("Cancel", key=f"plan_cancel::{client_name}"):
        _dismiss_task_dialog()
        st.rerun(scope="app")


def _render_task_editor(client_name: str, rows: Sequence[Mapping[str, Any]]) -> None:
    """Edit one revision-bound task draft without mixing workspace state.

    Args:
        client_name: Active client workspace.
        rows: Current project task rows.

    Returns:
        None. Saves valid submissions and displays validation or conflict errors.

    Raises:
        No exceptions are raised for expected validation and persistence failures.
    """

    st.markdown("**Update a project task**")
    choices = {r["task_ref"]: r for r in rows if r["task_ref"] != 15}
    task_ref = st.selectbox(
        "Task",
        list(choices),
        format_func=lambda ref: f'{ref}. {choices[ref]["task"]}',
        key=f"plan_task::{client_name}",
        on_change=select_assurance_tab,
        args=(client_name, PROJECT_PLAN_TAB),
    )
    snapshot_key = f"plan_snapshot::{client_name}::{task_ref}"
    if snapshot_key not in st.session_state:
        st.session_state[snapshot_key] = dict(choices[task_ref])
    snapshot = st.session_state[snapshot_key]
    revision = int(snapshot["revision"])
    prefix = f"plan_edit::{client_name}::{task_ref}::{revision}::"
    if revision != choices[task_ref]["revision"]:
        st.warning("This task has a newer saved version. Reload before editing.")
    st.button(
        "Reload saved task",
        key=f"plan_reload::{client_name}::{task_ref}",
        on_click=_reload_task,
        args=(client_name, task_ref),
    )
    with st.form(prefix + "form"):
        resource = st.text_input(
            "Resource", value=snapshot["resource"], max_chars=1000, key=prefix + "resource"
        )
        date_column, work_column, completed_column = st.columns(3)
        start = date_column.date_input(
            "Start date",
            value=snapshot["start_date"],
            min_value=date(2000, 1, 1),
            max_value=date(2100, 12, 31),
            key=prefix + "start",
        )
        planned = work_column.number_input(
            "Work days",
            min_value=0,
            max_value=3650,
            value=int(snapshot["work_days"]),
            step=1,
            key=prefix + "work",
        )
        completed = completed_column.number_input(
            "Completed days",
            min_value=0,
            max_value=3650,
            value=int(snapshot["completed_days"]),
            step=1,
            key=prefix + "completed",
        )
        notes = st.text_area("Notes", value=snapshot["notes"], max_chars=5000, key=prefix + "notes")
        actor = st.text_input("Updated by", max_chars=250, key=prefix + "actor")
        submitted = st.form_submit_button(
            "Save Changes",
            type="primary",
            on_click=select_assurance_tab,
            args=(client_name, PROJECT_PLAN_TAB),
        )
    if submitted:
        try:
            save_project_task(
                client_name,
                task_ref,
                ProjectTaskUpdate(resource, start, int(planned), int(completed), notes),
                actor=actor,
                expected_revision=revision,
            )
        except (ValueError, ProjectPlanError, MigrationError, DatabaseConfigurationError) as exc:
            LOGGER.warning("Project task %s was not saved for %s: %s", task_ref, client_name, exc)
            st.error(str(exc))
        else:
            st.session_state.pop(snapshot_key, None)
            _dismiss_task_dialog()
            st.session_state[f"plan_success::{client_name}"] = (
                f"Task {task_ref} saved. Dates and progress have been recalculated."
            )
            st.rerun(scope="app")
