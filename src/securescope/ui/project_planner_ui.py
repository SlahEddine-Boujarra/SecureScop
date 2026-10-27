"""Batch planning with dependency-based dates and a reviewable preview."""

from __future__ import annotations

from datetime import date
from typing import Any

import pandas as pd
import streamlit as st

from securescope.grc.isms_project_plan import ProjectTaskUpdate, schedule_project
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.isms_project_repository import ProjectPlanError, save_project_tasks
from securescope.persistence.migration_service import MigrationError
from securescope.ui.workspace_inputs import working_actor


def render_batch_planner(client_name: str, rows: list[dict[str, Any]]) -> None:
    """Edit task dates and effort together and save the changed rows atomically.

    Args:
        client_name: Active workspace.
        rows: Thirty current project task rows with revisions.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected validation or storage failures.
    """
    prefix = f"planner::{client_name}"
    state_key = prefix + "::draft"
    if state_key not in st.session_state:
        st.session_state[state_key] = [dict(row) for row in rows if row["task_ref"] != 15]
    draft = st.session_state[state_key]
    st.markdown("**Plan the project in one pass**")
    st.caption(
        (
            "Choose one start date, generate the schedule, then adjust owners "
            "or durations in the table."
        )
    )
    col1, col2, col3 = st.columns([1, 1, 1.4], vertical_alignment="bottom")
    start = col1.date_input("Project starts", date.today(), key=prefix + "::start")
    pace = col2.selectbox(
        "Duration estimate", ["Standard", "Lean", "Extended"], key=prefix + "::pace"
    )
    only_missing = col3.checkbox("Keep dates already set", value=True, key=prefix + "::missing")
    if st.button("Suggest all dates", icon=":material/auto_fix_high:", key=prefix + "::suggest"):
        try:
            suggested = schedule_project(
                draft,
                start,
                only_unscheduled=only_missing,
                duration_scale={"Standard": 1.0, "Lean": 0.5, "Extended": 2.0}[pace],
            )
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.session_state[state_key] = [row for row in suggested if row["task_ref"] != 15]
            st.session_state[prefix + "::generation"] = (
                st.session_state.get(prefix + "::generation", 0) + 1
            )
            st.rerun()
    st.caption(
        "Suggestions use editable estimates and task dependencies. Controls can run in parallel. "
        "Started tasks keep their dates. Weekends are skipped; public "
        "holidays and team capacity are not modelled. "
        "Certification dates must be agreed with your certification body."
    )
    fields = [
        "task_ref",
        "task",
        "resource",
        "start_date",
        "work_days",
        "end_date",
        "completed_days",
        "notes",
    ]
    frame = pd.DataFrame([{field: row.get(field) for field in fields} for row in draft])
    for column in ("start_date", "end_date"):
        frame[column] = pd.to_datetime(frame[column]).dt.date
    generation = st.session_state.get(prefix + "::generation", 0)
    edited = st.data_editor(
        frame,
        hide_index=True,
        width="stretch",
        height=560,
        key=f"{prefix}::editor::{generation}",
        disabled=["task_ref", "task", "end_date"],
        column_config={
            "task_ref": st.column_config.NumberColumn("Ref", width="small"),
            "task": st.column_config.TextColumn("Task", width="large"),
            "resource": st.column_config.TextColumn("Owner / team", required=True),
            "start_date": st.column_config.DateColumn("Start", format="DD MMM YYYY"),
            "end_date": st.column_config.DateColumn("Finish (calculated)", format="DD MMM YYYY"),
            "work_days": st.column_config.NumberColumn(
                "Work days", min_value=0, max_value=3650, step=1
            ),
            "completed_days": st.column_config.NumberColumn(
                "Done days", min_value=0, max_value=3650, step=1
            ),
            "notes": st.column_config.TextColumn("Notes"),
        },
    )
    revisions = {row["task_ref"]: row["revision"] for row in draft}
    actor = working_actor(client_name, "plan")
    save, recalculate, reload_column = st.columns(3)
    records = edited.to_dict("records")
    updates = {}
    try:
        for record in records:
            task_ref = int(record["task_ref"])
            record["start_date"] = None if pd.isna(record["start_date"]) else record["start_date"]
            record["revision"] = revisions[task_ref]
            update = ProjectTaskUpdate(
                str(record["resource"] or ""),
                record["start_date"],
                int(record["work_days"] or 0),
                int(record["completed_days"] or 0),
                str(record["notes"] or ""),
            )
            update.validate()
            original = next(row for row in rows if row["task_ref"] == task_ref)
            if any(
                original.get(field) != getattr(update, field)
                for field in ("resource", "start_date", "work_days", "completed_days", "notes")
            ):
                updates[task_ref] = (update, revisions[task_ref])
    except (ValueError, TypeError) as exc:
        st.error(str(exc))
        return
    if recalculate.button("Recalculate dependent dates", key=prefix + "::recalculate"):
        try:
            refreshed = schedule_project(records, start, only_unscheduled=False)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.session_state[state_key] = [row for row in refreshed if row["task_ref"] != 15]
            st.session_state[prefix + "::generation"] = generation + 1
            st.rerun()
    if reload_column.button("Reload saved plan", key=prefix + "::reload"):
        st.session_state.pop(state_key, None)
        st.session_state[prefix + "::generation"] = generation + 1
        st.rerun()
    if save.button(
        f"Save {len(updates)} changed tasks",
        type="primary",
        disabled=not updates,
        key=prefix + "::save",
    ):
        try:
            save_project_tasks(client_name, updates, actor=actor)
        except (ValueError, ProjectPlanError, MigrationError, DatabaseConfigurationError) as exc:
            st.error(str(exc))
        else:
            st.session_state.pop(state_key, None)
            st.session_state[prefix + "::generation"] = generation + 1
            st.session_state[f"plan_success::{client_name}"] = (
                f"{len(updates)} tasks saved together."
            )
            st.rerun()
