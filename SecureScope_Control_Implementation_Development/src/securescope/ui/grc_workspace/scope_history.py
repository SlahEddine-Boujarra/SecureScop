"""Readable controlled-scope history and structured comparisons."""

import streamlit as st

from securescope.grc.scope_workflow import SCOPE_FIELDS, display_date, display_person, scope_changes
from securescope.grc.status_labels import status_label


def render_scope_history(history: list[dict], *, key: str, is_admin: bool = False) -> None:
    """Render versions, selected content and a field-level comparison.

    Args:
        history: Existing canonical versions, newest first.
        key: Context-specific widget namespace.
        is_admin: Whether optional technical audit details may be inspected.
    Returns:
        None.
    Raises:
        Unexpected malformed repository records propagate to the caller.
    """
    st.subheader("Scope Version History")
    st.dataframe(
        [
            {
                "Version": r["version_number"],
                "Status": status_label(r["status"]),
                "Created": display_date(r.get("created_at")),
                "Prepared by": display_person(r.get("prepared_by")),
                "Reviewed by": display_person(r.get("reviewed_by")),
                "Approved by": display_person(r.get("approved_by")),
            }
            for r in history
        ],
        hide_index=True,
        width="stretch",
    )
    by_version = {r["version_number"]: r for r in history}
    selected = st.selectbox(
        "View version", list(by_version), format_func=lambda n: f"Version {n}", key=key + "::view"
    )
    current = by_version[selected]
    st.markdown(f"### Version {selected} · {status_label(current['status'])}")
    for field, title in SCOPE_FIELDS.items():
        if current.get(field):
            st.markdown(f"**{title}**")
            value = current[field]
            st.write(", ".join(value) if isinstance(value, list) else value)
    st.caption(
        f"Reviewed: {display_date(current.get('reviewed_at'))} · "
        f"Approved: {display_date(current.get('approved_at'))}"
    )
    st.caption(
        f"Submitted by: {display_person(current.get('submitted_by'))} · "
        f"Submitted: {display_date(current.get('submitted_at'))}"
    )
    st.write("Submission rationale: " + str(current.get("submission_rationale") or "Not recorded"))
    st.write("Review rationale: " + str(current.get("review_rationale") or "Not recorded"))
    st.write("Approval rationale: " + str(current.get("approval_comment") or "Not recorded"))
    if len(history) > 1:
        with st.expander("Compare versions"):
            before = st.selectbox(
                "From version", list(by_version), index=len(history) - 1, key=key + "::before"
            )
            after = st.selectbox("To version", list(by_version), key=key + "::after")
            changes = scope_changes(by_version[before], by_version[after])
            if changes:
                st.dataframe(changes, hide_index=True, width="stretch")
            else:
                st.info("No scope content differences between the selected versions.")
    if is_admin:
        with st.expander("Technical audit details · Administrator"):
            st.json(current, expanded=False)
