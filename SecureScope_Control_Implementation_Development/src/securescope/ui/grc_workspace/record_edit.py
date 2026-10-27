"""Explicit edit and review actions on existing Foundation records."""

from datetime import date

import streamlit as st

from securescope.grc.engagement_models import ISSUE_TYPES, PARTY_TYPES, RELEVANCE_VALUES
from securescope.persistence.grc_workspace_repository import update_foundation_record

CONTEXT_CATEGORIES = {
    "Internal": (
        "Governance",
        "People and culture",
        "Processes",
        "Technology",
        "Resources",
        "Other",
    ),
    "External": (
        "Legal and regulatory",
        "Market and competition",
        "Customers",
        "Suppliers",
        "Threat landscape",
        "Climate and environment",
        "Other",
    ),
}


def render_record_edit(client, engagement, scope, section, record, actor, can_edit):
    """Edit one canonical row, retaining its context and concurrency token.

    Args:
        client: Active client name.
        engagement: Selected engagement ID.
        scope: Selected scope ID.
        section: Context or parties.
        record: Selected canonical record.
        actor: Trusted signed-in identity.
        can_edit: Whether the UI may offer a save action; checked again by repository.
    Returns:
        None.
    Raises:
        Repository and validation errors are handled by the parent view.
    """
    st.subheader("Edit / review " + str(record.get("title") or record.get("name")))
    prefix = f"foundation_edit::{client}::{section}::{record['id']}"
    values = {}
    if section == "context":
        values["issue_type"] = st.selectbox(
            "Issue type",
            ISSUE_TYPES,
            index=ISSUE_TYPES.index(record["issue_type"]),
            key=prefix + "::type",
            disabled=not can_edit,
        )
        categories = list(CONTEXT_CATEGORIES[values["issue_type"]])
        old_category = record.get("category", "Other")
        category = st.selectbox(
            "Category",
            categories,
            index=(
                categories.index(old_category)
                if old_category in categories
                else len(categories) - 1
            ),
            key=prefix + "::category",
            disabled=not can_edit,
        )
        values["category"] = (
            st.text_input(
                "Other category",
                value=old_category if old_category not in categories else "",
                key=prefix + "::other",
                disabled=not can_edit,
            )
            if category == "Other"
            else category
        )
    with st.form(prefix):
        fields = (
            (
                ("title", "Issue title"),
                ("description", "Issue description"),
                ("effect_on_isms", "Effect on the ISMS"),
                ("owner", "Owner"),
            )
            if section == "context"
            else (
                ("name", "Interested party"),
                ("relationship_description", "Relationship"),
                ("needs_and_expectations", "Needs & expectations"),
                ("communication_method", "Communication method"),
                ("owner", "Owner"),
            )
        )
        for key, label in fields:
            widget = (
                st.text_area
                if key
                in {
                    "description",
                    "effect_on_isms",
                    "needs_and_expectations",
                    "relationship_description",
                }
                else st.text_input
            )
            values[key] = widget(label, value=record.get(key) or "", disabled=not can_edit)
        if section == "context":
            values["relevance"] = st.selectbox(
                "Relevance",
                RELEVANCE_VALUES,
                index=RELEVANCE_VALUES.index(record["relevance"]),
                disabled=not can_edit,
            )
            raw = record.get("review_date")
            values["review_date"] = st.date_input(
                "Next review date",
                value=date.fromisoformat(str(raw)[:10]) if raw else None,
                disabled=not can_edit,
            )
            statuses = ("Open", "Monitoring", "Closed")
        else:
            values["party_type"] = st.selectbox(
                "Party type",
                PARTY_TYPES,
                index=PARTY_TYPES.index(record["party_type"]),
                disabled=not can_edit,
            )
            statuses = ("Active", "Inactive")
        values["status"] = st.selectbox(
            "Status", statuses, index=statuses.index(record["status"]), disabled=not can_edit
        )
        note = st.text_area("Change / review rationale", disabled=not can_edit)
        save = st.form_submit_button("Save changes", type="primary", disabled=not can_edit)
    if save:
        update_foundation_record(
            client,
            engagement,
            scope,
            int(record["id"]),
            section=section,
            values=values,
            expected_updated_at=str(record["updated_at"]),
            actor=actor,
            note=note,
        )
        st.success("Record saved. Return to the register to see the updated values.")
