"""Dedicated step-by-step editor for immutable ISMS scope versions."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Mapping, Sequence

import streamlit as st

from securescope.grc.engagement_models import ScopeDraft
from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.ui.workflow_sections import back_link

SERVICE = GrcWorkspaceService()
SCOPE_EDITOR_STEPS = (
    "Identity & purpose",
    "Organization & locations",
    "Services & technology",
    "Boundaries & interfaces",
    "Exclusions & dates",
    "Review & create",
)


def _prefix(client_name: str, engagement_id: int) -> str:
    """Return a stable session-state prefix for one scope editor.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        Namespaced widget and editor state prefix.

    Raises:
        No exceptions are raised.
    """

    safe_client = client_name.encode("utf-8").hex()
    return f"scope_editor::{safe_client}::{engagement_id}::"


def _key(prefix: str, name: str) -> str:
    """Build one editor state key.

    Args:
        prefix: Editor-specific session prefix.
        name: Field or state name.

    Returns:
        Namespaced key.

    Raises:
        No exceptions are raised.
    """

    return f"{prefix}{name}"


def _join_lines(value: Any) -> str:
    """Render a repository list as newline-delimited editor text.

    Args:
        value: Sequence, scalar, or empty value.

    Returns:
        Newline-delimited text.

    Raises:
        No exceptions are raised.
    """

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return "\n".join(str(item) for item in value)
    return str(value or "")


def _split_lines(value: Any) -> tuple[str, ...]:
    """Convert editor text into non-empty scope list values.

    Args:
        value: Newline-delimited text.

    Returns:
        Ordered non-empty values.

    Raises:
        No exceptions are raised.
    """

    return tuple(line.strip() for line in str(value or "").splitlines() if line.strip())


def _coerce_date(value: Any, fallback: date) -> date:
    """Coerce one repository value into a Streamlit date value.

    Args:
        value: Date, ISO date string, or empty value.
        fallback: Value used when parsing fails.

    Returns:
        Safe date value.

    Raises:
        No exceptions are raised.
    """

    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return fallback


def scope_editor_is_open(client_name: str, engagement_id: int) -> bool:
    """Return whether the dedicated editor is active for this context.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        ``True`` when the editor should replace the scope register view.

    Raises:
        No exceptions are raised.
    """

    prefix = _prefix(client_name, engagement_id)
    return bool(st.session_state.get(_key(prefix, "active"), False))


def start_scope_editor(
    client_name: str,
    engagement_id: int,
    selected_scope: Mapping[str, Any] | None,
    *,
    initial_step: int = 0,
) -> None:
    """Initialize a session-backed scope-version editor.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        selected_scope: Current scope row copied into the draft, if any.
        initial_step: Existing editor step to open for a boundary-specific action.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    prefix = _prefix(client_name, engagement_id)
    scope = dict(selected_scope or {})
    defaults = {
        "active": True,
        "step": max(0, min(initial_step, len(SCOPE_EDITOR_STEPS) - 1)),
        "new_definition": not bool(scope.get("id")),
        "scope_code": str(scope.get("scope_code") or ""),
        "scope_name": str(scope.get("name") or ""),
        "scope_statement": str(scope.get("scope_statement") or ""),
        "locations": _join_lines(scope.get("locations")),
        "organizational_units": _join_lines(scope.get("organizational_units")),
        "products_and_services": _join_lines(scope.get("products_and_services")),
        "technologies": _join_lines(scope.get("technologies")),
        "boundaries": str(scope.get("boundaries") or ""),
        "interfaces": str(scope.get("interfaces_and_dependencies") or ""),
        "exclusions": str(scope.get("exclusions") or ""),
        "assumptions": _join_lines(scope.get("assumptions")),
        "effective_dates": bool(scope.get("effective_from") or scope.get("effective_to")),
        "effective_from": _coerce_date(scope.get("effective_from"), date.today()),
        "effective_to": _coerce_date(
            scope.get("effective_to"),
            date.today() + timedelta(days=365),
        ),
        "source_scope_id": int(scope["id"]) if scope.get("id") else None,
    }
    st.session_state[_key(prefix, "values")] = dict(defaults)
    for name, value in defaults.items():
        st.session_state[_key(prefix, name)] = value


def _ensure_scope_editor_state(client_name: str, engagement_id: int) -> None:
    """Restore and retain all six steps before any widgets are instantiated.

    Args:
        client_name: Exact client identity.
        engagement_id: Selected engagement identity.
    Returns:
        None; durable values and transient widget values are synchronized.
    Raises:
        No exceptions for supported editor values.
    """
    prefix = _prefix(client_name, engagement_id)
    values = st.session_state.get(_key(prefix, "values"))
    if values is None:
        # Direct navigation or an older session needs the same complete defaults.
        existing = {
            name[len(prefix) :]: value
            for name, value in st.session_state.items()
            if str(name).startswith(prefix)
        }
        start_scope_editor(client_name, engagement_id, None)
        values = dict(st.session_state[_key(prefix, "values")])
        values.update({name: value for name, value in existing.items() if name in values})
    for name, default in values.items():
        field_key = _key(prefix, name)
        values[name] = st.session_state.get(field_key, default)
        # Detach absent-step fields from Streamlit's widget cleanup, before rendering.
        st.session_state[field_key] = values[name]
    st.session_state[_key(prefix, "values")] = dict(values)


def close_scope_editor(client_name: str, engagement_id: int) -> None:
    """Clear all state owned by one scope editor.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    prefix = _prefix(client_name, engagement_id)
    for state_key in tuple(st.session_state):
        if str(state_key).startswith(prefix):
            del st.session_state[state_key]


def _render_identity_step(prefix: str, has_source_scope: bool) -> None:
    """Render scope identity and purpose fields.

    Args:
        prefix: Editor-specific session prefix.
        has_source_scope: Whether an existing definition is being versioned.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    st.checkbox(
        "Create a separate scope definition",
        key=_key(prefix, "new_definition"),
        disabled=not has_source_scope,
        help=("Leave this off to create the next version of the selected scope."),
    )
    identity_columns = st.columns(2)
    with identity_columns[0]:
        st.text_input(
            "Scope code",
            key=_key(prefix, "scope_code"),
            disabled=(
                has_source_scope and not bool(st.session_state[_key(prefix, "new_definition")])
            ),
        )
    with identity_columns[1]:
        st.text_input("Scope name", key=_key(prefix, "scope_name"))
    st.text_area(
        "Formal scope statement",
        key=_key(prefix, "scope_statement"),
        height=150,
        help="State the organization, services, locations, and boundaries covered.",
    )


def _render_organization_step(prefix: str) -> None:
    """Render organization and location list fields.

    Args:
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    columns = st.columns(2)
    with columns[0]:
        st.text_area(
            "Locations — one per line",
            key=_key(prefix, "locations"),
            height=210,
        )
    with columns[1]:
        st.text_area(
            "Organizational units — one per line",
            key=_key(prefix, "organizational_units"),
            height=210,
        )


def _render_services_step(prefix: str) -> None:
    """Render services and technology list fields.

    Args:
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    columns = st.columns(2)
    with columns[0]:
        st.text_area(
            "Products and services — one per line",
            key=_key(prefix, "products_and_services"),
            height=210,
        )
    with columns[1]:
        st.text_area(
            "Technologies — one per line",
            key=_key(prefix, "technologies"),
            height=210,
        )
    st.caption(
        "Processes, information assets, and business-to-technical links can be "
        "maintained through the related records."
    )


def _render_boundaries_step(prefix: str) -> None:
    """Render scope boundaries and dependency fields.

    Args:
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    columns = st.columns(2)
    with columns[0]:
        st.text_area(
            "Organizational and technical boundaries",
            key=_key(prefix, "boundaries"),
            height=220,
        )
    with columns[1]:
        st.text_area(
            "Interfaces and dependencies",
            key=_key(prefix, "interfaces"),
            height=220,
        )


def _render_exclusions_step(prefix: str) -> None:
    """Render exclusions, assumptions, and effective dates.

    Args:
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    columns = st.columns(2)
    with columns[0]:
        st.text_area(
            "Exclusions and rationale",
            key=_key(prefix, "exclusions"),
            height=180,
        )
    with columns[1]:
        st.text_area(
            "Assumptions — one per line",
            key=_key(prefix, "assumptions"),
            height=180,
        )
    st.checkbox("Set effective dates", key=_key(prefix, "effective_dates"))
    date_columns = st.columns(2)
    enabled = bool(st.session_state[_key(prefix, "effective_dates")])
    with date_columns[0]:
        st.date_input(
            "Effective from",
            key=_key(prefix, "effective_from"),
            disabled=not enabled,
        )
    with date_columns[1]:
        st.date_input(
            "Effective to",
            key=_key(prefix, "effective_to"),
            disabled=not enabled,
        )


def _render_review_step(prefix: str) -> None:
    """Render a read-only summary before creating the draft version.

    Args:
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    st.markdown("#### Review the new draft version")
    summary_columns = st.columns(3)
    values = (
        ("Scope code", st.session_state[_key(prefix, "scope_code")]),
        ("Scope name", st.session_state[_key(prefix, "scope_name")]),
        (
            "Definition",
            (
                "New definition"
                if st.session_state[_key(prefix, "new_definition")]
                else "Next version of selected scope"
            ),
        ),
    )
    for column, (label, value) in zip(summary_columns, values):
        with column:
            st.metric(label, value or "Missing")
    st.markdown("**Formal statement**")
    st.info(st.session_state[_key(prefix, "scope_statement")] or "Missing")
    list_counts = {
        "Locations": len(_split_lines(st.session_state[_key(prefix, "locations")])),
        "Units": len(_split_lines(st.session_state[_key(prefix, "organizational_units")])),
        "Services": len(_split_lines(st.session_state[_key(prefix, "products_and_services")])),
        "Technologies": len(_split_lines(st.session_state[_key(prefix, "technologies")])),
        "Assumptions": len(_split_lines(st.session_state[_key(prefix, "assumptions")])),
    }
    st.dataframe(
        [{"Scope list": label, "Items": count} for label, count in list_counts.items()],
        hide_index=True,
        width="stretch",
    )
    st.warning(
        "This action creates a Draft scope version. A separate authorized human "
        "approval is required before the version becomes immutable."
    )


def _create_scope_version(
    client_name: str,
    engagement_id: int,
    actor: str,
    scope_state_key: str,
    prefix: str,
) -> None:
    """Validate and persist the completed scope editor draft.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        actor: Current audit principal.
        scope_state_key: State key updated to the new scope definition.
        prefix: Editor-specific session prefix.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    has_dates = bool(st.session_state[_key(prefix, "effective_dates")])
    new_definition = bool(st.session_state[_key(prefix, "new_definition")])
    source_scope_id = st.session_state.get(_key(prefix, "source_scope_id"))
    try:
        created = SERVICE.create_scope_version(
            client_name,
            engagement_id,
            ScopeDraft(
                scope_code=st.session_state[_key(prefix, "scope_code")],
                name=st.session_state[_key(prefix, "scope_name")],
                scope_statement=st.session_state[_key(prefix, "scope_statement")],
                boundaries=st.session_state[_key(prefix, "boundaries")],
                exclusions=st.session_state[_key(prefix, "exclusions")],
                interfaces_and_dependencies=st.session_state[_key(prefix, "interfaces")],
                locations=_split_lines(st.session_state[_key(prefix, "locations")]),
                organizational_units=_split_lines(
                    st.session_state[_key(prefix, "organizational_units")]
                ),
                products_and_services=_split_lines(
                    st.session_state[_key(prefix, "products_and_services")]
                ),
                technologies=_split_lines(st.session_state[_key(prefix, "technologies")]),
                assumptions=_split_lines(st.session_state[_key(prefix, "assumptions")]),
                effective_from=(
                    st.session_state[_key(prefix, "effective_from")] if has_dates else None
                ),
                effective_to=(
                    st.session_state[_key(prefix, "effective_to")] if has_dates else None
                ),
            ),
            actor=actor,
            scope_id=(None if new_definition or source_scope_id is None else int(source_scope_id)),
        )
    except GrcWorkspaceServiceError as exc:
        st.error(str(exc))
        return
    st.session_state[scope_state_key] = int(created["scope_id"])
    close_scope_editor(client_name, engagement_id)
    st.toast(
        (
            "Scope unchanged; no new version created."
            if created.get("unchanged")
            else f"Draft scope version {created['version_number']} created."
        ),
        icon="✅",
    )
    st.rerun()


def render_scope_editor(
    client_name: str,
    engagement_id: int,
    actor: str,
    scope_state_key: str,
) -> None:
    """Render the active six-step scope-version editor.

    Args:
        client_name: Active client workspace name.
        engagement_id: Selected engagement identifier.
        actor: Current audit principal.
        scope_state_key: State key updated after draft creation.

    Returns:
        None.

    Raises:
        No exceptions are raised; service failures become UI messages.
    """

    _ensure_scope_editor_state(client_name, engagement_id)
    prefix = _prefix(client_name, engagement_id)
    step = int(st.session_state.get(_key(prefix, "step"), 0))
    step = max(0, min(step, len(SCOPE_EDITOR_STEPS) - 1))
    st.markdown("## Scope version editor")
    st.caption(
        "Create a controlled draft in six focused steps. Editor values remain in "
        "this browser session until you create the version or cancel."
    )
    title_columns = st.columns([4, 1], vertical_alignment="center")
    with title_columns[0]:
        st.markdown(
            f"**Step {step + 1} of {len(SCOPE_EDITOR_STEPS)} · " f"{SCOPE_EDITOR_STEPS[step]}**"
        )
    with title_columns[1]:
        if st.button(
            "Cancel editor",
            icon=":material/close:",
            type="secondary",
            width="stretch",
            key=_key(prefix, "cancel_top"),
        ):
            close_scope_editor(client_name, engagement_id)
            st.rerun()
    st.progress((step + 1) / len(SCOPE_EDITOR_STEPS))

    renderers = (
        lambda: _render_identity_step(
            prefix,
            st.session_state.get(_key(prefix, "source_scope_id")) is not None,
        ),
        lambda: _render_organization_step(prefix),
        lambda: _render_services_step(prefix),
        lambda: _render_boundaries_step(prefix),
        lambda: _render_exclusions_step(prefix),
        lambda: _render_review_step(prefix),
    )
    with st.container(border=True):
        renderers[step]()

    back_column, spacer_column, next_column = st.columns([1, 2, 1])
    with back_column:
        if step > 0 and back_link(
            SCOPE_EDITOR_STEPS[step - 1],
            key=_key(prefix, f"back_{step}"),
        ):
            st.session_state[_key(prefix, "step")] = step - 1
            st.rerun()
    with spacer_column:
        st.caption("A draft version is persisted only after the final review.")
    with next_column:
        if step < len(SCOPE_EDITOR_STEPS) - 1:
            if st.button(
                "Save & continue",
                icon=":material/arrow_forward:",
                type="primary",
                width="stretch",
                key=_key(prefix, f"next_{step}"),
            ):
                if step == 0 and not all(
                    str(st.session_state.get(_key(prefix, field), "")).strip()
                    for field in ("scope_code", "scope_name", "scope_statement")
                ):
                    st.error("Scope code, name, and formal statement are required.")
                else:
                    st.session_state[_key(prefix, "step")] = step + 1
                    st.rerun()
        elif st.button(
            "Create draft version",
            icon=":material/save:",
            type="primary",
            width="stretch",
            key=_key(prefix, "create_version"),
        ):
            _create_scope_version(
                client_name,
                engagement_id,
                actor,
                scope_state_key,
                prefix,
            )
