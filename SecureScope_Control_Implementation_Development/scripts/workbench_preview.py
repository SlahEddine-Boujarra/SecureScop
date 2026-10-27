"""Local visual preview with synthetic records; no database reads or writes.

Run with: streamlit run scripts/workbench_preview.py
"""

import streamlit as st
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.policies.suggestions import policy_template, section_choices

st.set_page_config(layout="wide", page_title="SecureScope UI preview")
st.caption("Visual preview · synthetic records · no database writes")
page = st.selectbox(
    "Preview screen", ["Programme Foundation", "Policy editor", "Calendar", "Impacted assets"]
)
base = dict(
    actor="reviewer@example.test",
    revision=1,
    can_edit=True,
    is_admin=True,
    members=[],
    controls=[],
    selected=None,
)
if page == "Programme Foundation":
    data = dict(
        base,
        mode="foundation",
        selected="context",
        section="context",
        title="Context of the Organization (Clause 4.1)",
        description="Internal and external factors influencing ISMS objectives.",
        add_label="Add issue",
        filter_key="issue_type",
        columns={
            "title": "Issue",
            "issue_type": "Type",
            "relevance": "Relevance",
            "owner": "Owner",
            "status": "Status",
        },
        rows=[
            dict(
                _row_key="1",
                title="Cloud service dependency",
                issue_type="External",
                relevance="Relevant",
                owner="Security lead",
                status="Open",
                description="Review continuity arrangements and responsibilities for the hosting service.",
            )
        ],
    )
elif page == "Policy editor":
    draft = policy_template("Access Control", "Example client")
    data = dict(
        base,
        mode="policy_builder",
        selected="demo",
        detail=dict(draft, policy_version=1, owner="Security lead"),
        guidance={
            "".join(r["text"] for r in b["runs"]): section_choices(
                "".join(r["text"] for r in b["runs"])
            )
            for b in draft["blocks"]
            if b["kind"].startswith("h")
        },
        default_guidance=[],
    )
elif page == "Calendar":
    data = dict(
        base,
        mode="calendar",
        client="Example client",
        clients=[{"name": "Example client", "role": "Administrator"}],
        events=[],
    )
else:
    data = dict(
        base,
        mode="risk_detail",
        selected=1,
        detail=dict(
            risk_ref=1,
            revision=1,
            threat="Service interruption",
            asset_ids=[],
            control_references=[],
        ),
        groups=[],
        asset_groups=["Hardware"],
        tasks=[],
        assets=[{"id": 1, "asset_tag": "Application server", "ip": "192.0.2.10"}],
    )
action = assurance_workbench(data, key="preview-" + page)
if getattr(action, "action", None):
    st.info("Preview action received. No records were saved.")
