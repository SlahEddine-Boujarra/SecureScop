"""Month and week planning views over client-owned source dates."""

from __future__ import annotations

import calendar
from datetime import date, datetime, timedelta, timezone

import streamlit as st

from securescope.persistence.calendar_repository import calendar_events
from securescope.persistence.workspace_planning import put_record
from securescope.ui.grc_workspace.context import current_actor, workspace_state_keys
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role
from securescope.ui.workflow_sections import workflow_section


def render_calendar_page_legacy(client: str) -> None:
    """Display real dated records and allow authorized users to create manual events."""
    st.title("Calendar")
    st.caption(
        (
            "Policy renewals, risk reviews, actions and audit dates for this "
            "client. Times are UTC. Queued scans show when they entered the "
            "queue, not a scheduled execution time."
        )
    )
    try:
        events = calendar_events(client)
        role = get_workspace_role(client, current_actor())
    except ERRORS as exc:
        st.error(f"Calendar unavailable: {exc}")
        return
    if not role:
        st.info(
            (
                "Sign in or complete Administrator setup in Client Workspace "
                "to access the calendar."
            )
        )
        return
    key = f"calendar::{client}"
    anchor = st.date_input("Calendar date", value=date.today(), key=key + "date")
    mode = st.segmented_control("View", ["Month", "Week"], default="Month", key=key + "mode")
    with workflow_section("Add event", "Schedule a client activity and save it to the calendar."):
        with st.form(key + "add"):
            title = st.text_input("Event title", max_chars=160)
            day = st.date_input("Event date", value=anchor)
            time = st.time_input("Time (UTC)")
            event_type = st.selectbox("Type", ["Review", "Meeting", "Audit", "Other"])
            linked_type = st.selectbox(
                "Optional linked record", ["None", "Policy", "Risk", "Asset"]
            )
            linked_reference = st.text_input("Policy ID, risk number or asset IP (optional)")
            notes = st.text_area("Notes")
            submitted = st.form_submit_button(
                "Save event",
                disabled=role not in {"Administrator", "Consultant", "Client contributor"},
            )
        if submitted:
            try:
                put_record(
                    client,
                    "calendar_event",
                    "",
                    {
                        "title": title.strip(),
                        "starts_at": datetime.combine(day, time, tzinfo=timezone.utc).isoformat(),
                        "type": event_type,
                        "notes": notes,
                        "linked_type": "" if linked_type == "None" else linked_type,
                        "linked_reference": linked_reference,
                    },
                    actor=current_actor(),
                )
            except (*ERRORS, ValueError) as exc:
                st.error(str(exc))
            else:
                st.rerun()
    if mode == "Week":
        first = anchor - timedelta(days=anchor.weekday())
        weeks = [[first + timedelta(days=i) for i in range(7)]]
    else:
        weeks = calendar.Calendar().monthdatescalendar(anchor.year, anchor.month)
    st.subheader(anchor.strftime("%B %Y"))
    for week in weeks:
        for col, day in zip(st.columns(7), week):
            with col:
                st.markdown(f"**{day:%a %d}**")
                for i, event in enumerate(events):
                    if str(event["starts_at"])[:10] != day.isoformat():
                        continue
                    if st.button(event["title"], key=key + f"event::{i}", width="stretch"):
                        st.session_state[key + "selected"] = event
                    st.caption(event["source"])
    if not events:
        st.info(
            "No dated records yet. Add an event or set a policy renewal, risk review or audit date."
        )
    selected = st.session_state.get(key + "selected")
    if selected:
        with st.container(border=True):
            st.subheader(selected["title"])
            st.write(selected["starts_at"])
            st.write(selected.get("notes", ""))
            if selected.get("route") and st.button("Open source record", key=key + "open"):
                from securescope.ui.navigation_runtime import navigate_to

                if selected["route"] == "Policies":
                    engagement_key, scope_key = workspace_state_keys(client)
                    st.session_state[engagement_key] = selected["engagement"]
                    st.session_state[scope_key] = selected["scope"]
                    st.session_state[
                        f"policies::{client}::{selected['engagement']}"
                        f"::{selected['scope']}::selected"
                    ] = selected["policy_id"]
                elif selected["route"] == "2 · Asset Management":
                    st.session_state["selected_ip"] = selected["asset_ip"]
                elif selected["route"] == "Risk":
                    st.session_state[f"risk::{client}::selected"] = selected["risk_ref"]
                navigate_to(selected["route"])


def render_calendar_page(client: str, on_open_client=None) -> None:
    """Render the calendar; callback switches clients; known errors appear in UI."""
    from securescope.ui.calendar_workbench import render_calendar_workbench

    render_calendar_workbench(client, on_open_client)
