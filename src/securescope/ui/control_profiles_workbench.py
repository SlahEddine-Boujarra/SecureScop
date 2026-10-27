"""Editable control profiles using the shared table-and-drawer workbench."""

from __future__ import annotations

import json
import logging
from typing import Any

import streamlit as st

from securescope.core.gap_assessment_domain import ASSESSMENT_MODELS
from securescope.evidence.models import role_can
from securescope.persistence.grc_repository import create_profile_version
from securescope.ui.assurance_interactions import ASSESSMENT_TAB
from securescope.ui.assurance_workbench import _event
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.control_assessment_ui import ERRORS
from securescope.ui.evidence_hub_ui import _identity

LOGGER = logging.getLogger(__name__)
EDITABLE_FIELDS = (
    "organization_name",
    "implementation_description",
    "control_owner",
    "assessment_owner",
    "scope",
    "measurement_model",
    "automation_level",
    "assessment_methods",
    "evidence_requirements",
)


def profile_values(profile: dict[str, Any]) -> dict[str, Any]:
    """Prepare editable values while keeping non-editable profile data separate.

    Args:
        profile: Repository control profile.
    Returns:
        JSON-compatible record with editable fields and stable version identity.
    Raises:
        KeyError: If the profile lacks a control identifier.
    """
    scope = profile.get("assessment_scope") or {}
    result = {key: profile.get(key) or "" for key in EDITABLE_FIELDS}
    result["scope"] = scope.get("description", "")
    for name in ("organization_name", "implementation_description"):
        result[name] = scope.get(name, "")
    for key in ("assessment_methods", "evidence_requirements"):
        value = profile.get(key) or []
        result[key] = value if isinstance(value, str) else "\n".join(map(str, value))
    return dict(
        result,
        control_id=str(profile["control_id"]),
        control_name=profile.get("control_name") or "",
        control_objective=profile.get("control_objective") or "",
        profile_version=int(profile.get("profile_version") or 1),
        measurement_model=profile.get("measurement_model") or "checklist",
        automation_level=profile.get("automation_level") or "Manual",
        target=profile.get("target_description") or "No approved target",
        assessment_status=profile.get("assessment_status") or "Not assessed",
        implementation_status=(profile.get("implementation_evaluation") or {}).get(
            "status", "Not Assessed"
        ),
        current_value=profile.get("current_value"),
        assurance_score=profile.get("assurance_score"),
    )


def save_profile_edit(client: str, profile: dict, payload: dict, actor: str) -> int:
    """Save a whitelisted edit through the existing versioned profile service.

    Args:
        client: Authorized current workspace.
        profile: Profile resolved from that workspace, never from the payload.
        payload: Editable fields and the version the editor originally opened.
        actor: Principal obtained from the existing session identity helper.
    Returns:
        New profile version.
    Raises:
        ValueError: If the edit is malformed or excessively long.
        GrcRepositoryError: If validation, concurrency or persistence fails.
    """
    supplied = payload.get("fields")
    expected = payload.get("expected_version")
    if not isinstance(supplied, dict) or type(expected) is not int:
        raise ValueError("Reload the profile before saving this edit.")
    values = {}
    for key in EDITABLE_FIELDS:
        value = supplied.get(key, profile_values(profile).get(key, ""))
        if not isinstance(value, str) or len(value) > 20000:
            raise ValueError(f"Invalid value for {key.replace('_', ' ')}.")
        values[key] = value.strip()
    if values["automation_level"] not in {"Manual", "Partial", "Automated"}:
        raise ValueError("Choose a supported automation level.")
    return create_profile_version(
        client,
        str(profile["control_id"]),
        measurement_model=values["measurement_model"],
        control_owner=values["control_owner"],
        assessment_owner=values["assessment_owner"],
        assessment_scope={
            **(profile.get("assessment_scope") or {}),
            "description": values["scope"],
            "organization_name": values["organization_name"],
            "implementation_description": values["implementation_description"],
        },
        assessment_methods=[
            line.strip() for line in values["assessment_methods"].splitlines() if line.strip()
        ],
        evidence_requirements=[
            line.strip() for line in values["evidence_requirements"].splitlines() if line.strip()
        ],
        automation_level=values["automation_level"],
        supported_data_sources=profile.get("supported_data_sources") or [],
        actor=actor,
        expected_profile_version=expected,
        context_scope_id=(profile.get("assessment_scope") or {})
        .get("implementation_requirements", {})
        .get("scope_id"),
    )


def render_control_profiles(client: str, profiles: list[dict], summaries: list[dict]) -> None:
    """Render the profile register and editable drawer in the same component.

    Args:
        client: Active workspace.
        profiles: Filtered repository records belonging to this workspace.
        summaries: Corresponding advisory/assessment display summaries.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected service errors display.
    """
    key = f"control_drawers::{client}"
    try:
        actor, role = _identity(client)
        can_edit = bool(role and role_can(role, "review"))
        selected = st.session_state.get(key + "::implementation")
        if selected:
            from securescope.ui.control_workspace import render_control_workspace

            render_control_workspace(client, selected, role)
            return
        rows = [
            dict(
                profile_values(profile),
                summary={
                    **summary,
                    "Type": (
                        "Annex A Control"
                        if str(profile["control_id"]).startswith("A.")
                        else "ISO Requirement"
                    ),
                    "Implementation": (profile.get("implementation_evaluation") or {}).get(
                        "status", "Not Assessed"
                    ),
                    "Title": (profile.get("assessment_scope") or {}).get("organization_name")
                    or summary.get("Title", ""),
                },
            )
            for profile, summary in zip(profiles, summaries)
        ]
        data = dict(
            mode="control_profiles",
            full_workspace=True,
            rows=rows,
            can_edit=can_edit,
            models=list(ASSESSMENT_MODELS),
            response=st.session_state.get(key + "::response"),
        )
        from securescope.persistence.assurance_workspace_repository import assurance_overview
        from securescope.ui.grc_workspace.context import selected_context_ids

        engagement, scope_id = selected_context_ids(client)
        if engagement and scope_id and not st.session_state.get(key + "::implementation"):
            evaluated = {
                r["control_id"]: r["result"]
                for r in assurance_overview(client, actor, engagement, scope_id, profiles)
            }
            for row in rows:
                result = evaluated.get(row["control_id"])
                if result:
                    row["summary"].update(
                        {
                            "Applicability": result["applicability"],
                            "Implementation": result["implementation"],
                            "Evidence": (
                                f"{result['evidence_coverage']}%"
                                if result["evidence_coverage"] is not None
                                else "Not configured"
                            ),
                            "Assurance": result["assurance"],
                        }
                    )
        from securescope.ui.soa_ownership import pending_soa_applicability

        pending_soa = pending_soa_applicability(client, engagement, scope_id)
        if pending_soa:
            st.info(
                "SoA edits are shown as draft proposals. Save and appro"
                "ve the SoA version to update formal assurance metrics."
            )
            for row in rows:
                if row["control_id"] in pending_soa:
                    row["summary"]["Applicability"] = pending_soa[row["control_id"]] + " (draft)"
        event = _event(assurance_workbench(json.loads(json.dumps(data, default=str)), key=key), key)
        if not event:
            return
        payload = event.get("payload") or {}
        profile = next(
            (row for row in profiles if str(row["control_id"]) == payload.get("control_id")), None
        )
        if profile is None:
            raise ValueError("This control is no longer in the current workspace view.")
        if event["action"] == "profile_implementation":
            st.session_state[key + "::implementation"] = str(profile["control_id"])
            st.session_state[key + "::response"] = dict(
                nonce=event["nonce"], message="Control Workspace opened."
            )
            st.rerun()
        if event["action"] == "profile_assess":
            st.session_state[f"manual_control_pending::{client}"] = str(profile["control_id"])
            st.session_state[f"assurance_pending_tab::{client}"] = ASSESSMENT_TAB
            st.rerun()
        if event["action"] != "profile_save" or not can_edit:
            raise ValueError("Consultant or Administrator membership is required to edit profiles.")
        version = save_profile_edit(client, profile, payload, actor)
        st.session_state[key + "::response"] = dict(
            nonce=event["nonce"],
            message=f"Profile version {version} saved. Review its target before assessment.",
        )
        st.rerun()
    except ERRORS as exc:
        LOGGER.warning("Control profile edit failed: %s", type(exc).__name__)
        if "event" in locals() and event:
            st.session_state[key + "::response"] = dict(nonce=event["nonce"], error=str(exc))
            st.rerun()
        st.error(str(exc))
