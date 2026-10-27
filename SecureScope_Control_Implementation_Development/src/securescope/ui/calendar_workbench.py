"""Clickable client-work calendar over existing dated records."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Callable

import streamlit as st

from securescope.persistence.calendar_repository import calendar_events
from securescope.persistence.foundation_repository import FoundationError, workspace_cursor
from securescope.persistence.workspace_planning import EDITORS, put_record
from securescope.ui.assurance_workbench import _event
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.grc_workspace.context import current_actor
from securescope.ui.grc_workspace.formal import ERRORS, get_workspace_role

LOGGER = logging.getLogger(__name__)


def authorized_clients(client: str, actor: str) -> list[dict]:
    """Return only active client memberships for the authenticated principal.

    Args:
        client: Current workspace, used to obtain a database cursor.
        actor: Trusted session identity.
    Returns:
        Client names and roles.
    Raises:
        FoundationError: On persistence failure.
    """
    with workspace_cursor(client) as (cursor, _):
        cursor.execute(
            (
                "SELECT c.name,m.role FROM securescope_clients c JOIN "
                "securescope_workspace_memberships m ON m.client_id=c.id JOIN "
                "securescope_users u ON u.id=m.user_id WHERE u.email=%s AND "
                "m.active AND u.active ORDER BY c.name"
            ),
            (actor.strip().lower(),),
        )
        return [dict(r) for r in cursor.fetchall()]


def render_calendar_workbench(client: str, on_open_client: Callable | None = None) -> None:
    """Show date tiles and persist authorized client appointments.

    Args:
        client: Active workspace.
        on_open_client: Existing app callback for safe workspace switching.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; known failures are logged.
    """
    actor = current_actor()
    key = f"calendar_workbench::{actor}"
    try:
        clients = authorized_clients(client, actor)
        if not clients:
            st.info("Sign in or complete Administrator setup to plan client work.")
            return
        events = []
        for workspace in clients:
            for index, event in enumerate(calendar_events(workspace["name"])):
                events.append(
                    dict(
                        event,
                        client=workspace["name"],
                        uid=f"{workspace['name']}::{event.get('event_id', index)}",
                    )
                )
        data = dict(
            mode="calendar",
            actor=actor,
            client=client,
            clients=clients,
            events=events,
            selected=None,
            revision=0,
            response=st.session_state.get(key + ":response"),
        )
        action = _event(
            assurance_workbench(json.loads(json.dumps(data, default=str)), key=key), key
        )
        if not action:
            return
        response = {"nonce": action["nonce"]}
        try:
            payload = action["payload"]
            target = payload.get("client")
            membership = next((c for c in clients if c["name"] == target), None)
            if not membership:
                raise FoundationError("Select a workspace you can access.")
            if action["action"] == "calendar_save":
                if membership["role"] not in EDITORS:
                    raise FoundationError("Contributor membership is required.")
                starts = datetime.fromisoformat(str(payload["starts_at"]))
                if starts.tzinfo is None:
                    starts = starts.replace(tzinfo=timezone.utc)
                event_id = str(payload.get("event_id", ""))
                prior = next(
                    (
                        e
                        for e in events
                        if e.get("event_id") == event_id
                        and e["client"] == target
                        and e["source"] == "Manual"
                    ),
                    None,
                )
                if event_id and not prior:
                    raise FoundationError("Select an existing event in this workspace.")
                put_record(
                    target,
                    "calendar_event",
                    event_id,
                    dict(
                        title=str(payload["title"])[:160],
                        starts_at=starts.isoformat(),
                        type=str(payload.get("type", "Work")),
                        notes=str(payload.get("notes", "")),
                    ),
                    actor=actor,
                    expected=int(payload.get("revision", 0)),
                )
                response["message"] = "Client activity saved."
            elif action["action"] == "calendar_open":
                if on_open_client is None:
                    raise FoundationError("Open this client from the workspace selector.")
                if not get_workspace_role(target, actor):
                    raise FoundationError("Workspace access changed.")
                on_open_client(target)
                response["message"] = f"Opened workspace: {target}"
            else:
                raise FoundationError("Unsupported calendar action.")
        except (*ERRORS, ValueError, TypeError, KeyError) as exc:
            LOGGER.warning("Calendar action rejected: %s", type(exc).__name__)
            response["error"] = str(exc)
        st.session_state[key + ":response"] = response
    except ERRORS as exc:
        LOGGER.warning("Calendar unavailable: %s", type(exc).__name__)
        st.error(str(exc))
        return
    st.rerun()
