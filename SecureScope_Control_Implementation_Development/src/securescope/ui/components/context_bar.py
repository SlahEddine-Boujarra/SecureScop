"""Persistent client, engagement, and scope context bar."""

from __future__ import annotations

from typing import Any, Mapping

from securescope.core.presentation import safe_text
from securescope.ui.components.html_renderer import render_html


def render_context_bar(
    client_name: str,
    context: Mapping[str, Any],
    *,
    actor: str,
) -> None:
    """Render the authoritative working context for an ISO programme page.

    Args:
        client_name: Active client workspace name.
        context: Resolved GRC service context.
        actor: Identity used for audit events and approval checks.

    Returns:
        None.

    Raises:
        No exceptions are raised.
    """

    overview = context.get("overview") or {}
    engagement = overview.get("engagement") or {}
    scope = overview.get("scope") or {}
    approved_version = overview.get("approved_scope_version")
    selected_scope = next(
        (
            row
            for row in context.get("scopes", ())
            if context.get("selected_scope_id") is not None
            and int(row.get("id") or 0) == int(context["selected_scope_id"])
        ),
        {},
    )
    if approved_version:
        scope_status = f"v{approved_version.get('version_number', '—')} · Approved"
    elif selected_scope:
        scope_status = (
            f"v{selected_scope.get('latest_version_number', '—')} · "
            f"{selected_scope.get('latest_status', 'Draft')}"
        )
    else:
        scope_status = "No scope"

    cells = (
        ("Client", client_name, "business"),
        (
            "Engagement",
            str(engagement.get("name") or "No engagement"),
            "work",
        ),
        ("ISMS scope", str(scope.get("name") or "No scope selected"), "select_all"),
        ("Scope state", scope_status, "verified_user"),
        ("Current actor", actor, "person"),
    )
    content = []
    for label, value, icon in cells:
        content.append(
            '<div class="ss-context-cell">'
            f'<span class="material-symbols-rounded" aria-hidden="true">{safe_text(icon)}</span>'
            "<div>"
            f"<small>{safe_text(label)}</small>"
            f'<strong title="{safe_text(value)}">{safe_text(value)}</strong>'
            "</div></div>"
        )
    render_html(
        '<div class="ss-context-bar" role="group" '
        'aria-label="Current client, engagement and ISMS scope">' + "".join(content) + "</div>"
    )
