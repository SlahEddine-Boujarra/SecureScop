"""UI QA only: production renderers with explicit synthetic, in-memory records.

Run with Streamlit. Never connects to client data, saves records, or starts scanners.
Nmap/Client Workspace are field-component checks, not full routed-page tests.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import streamlit as st

from securescope.ui.securescope_ui_theme import apply_securescope_ui_theme
from securescope.ui.components.primitives import identity_context, metric_card
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.integration_presentation import integration_summary
from securescope.ui.workflow_sections import back_link
from securescope.grc.assurance_requirements import evaluate_assurance

st.set_page_config(layout="wide", page_title="SecureScope visual verification")
apply_securescope_ui_theme()
st.caption("UI verification · synthetic records · no persistence or scanner execution")
page = st.query_params.get("screen", "Foundation")
if st.query_params.get("sidebar") == "1":
    from securescope.ui.securescope_sidebar import render_sidebar_menu

    @st.dialog("Switch client workspace")
    def preview_client_dialog():
        """Show a synthetic callback result; return None and perform no writes."""
        st.write("Client switcher opened.")

    render_sidebar_menu("Northstar Services", 6, 9, open_workspace_dialog=preview_client_dialog)

if page in {"Assurance", "Project Plan", "Assess Control", "SoA"}:
    from securescope.ui.components.stitch import apply_assurance_design

    apply_assurance_design()
    navigation = [
        ":material/dashboard: Dashboard",
        ":material/calendar_month: Project Plan",
        ":material/table_view: Profiles",
        ":material/fact_check: Assess Control",
        ":material/folder_open: Evidence",
        ":material/assignment_late: Gap Actions",
        ":material/description: SoA",
        ":material/account_tree: Risk Treatments",
    ]
    index = {"Assurance": 0, "Project Plan": 1, "Assess Control": 3, "SoA": 6}[page]
    st.session_state["preview_navigation"] = navigation[index]
    st.container(key="control_assurance_tabs").tabs(
        navigation, key="preview_navigation", on_change="rerun"
    )
empty = st.query_params.get("empty") == "1"
base = dict(
    actor="consultant@example.test",
    is_admin=False,
    can_edit=True,
    revision=1,
    members=[],
    controls=[],
    groups=[dict(record_key="default", payload=dict(name="Production"))],
    templates=[],
    rows=[],
    guidance={},
    default_guidance=[],
    selected=None,
)
requirement = dict(
    id="monitoring",
    title="Monitoring review evidence",
    type="Technical",
    mandatory=True,
    rule="Manual validation",
    expected_result="Review monitoring alerts and record the response.",
    evidence_links=[],
    asset_ids=[1],
    max_age_days=90,
)
result = evaluate_assurance(
    dict(
        profile=dict(
            assessment_scope=dict(
                implementation_requirements=dict(requirements=[] if empty else [requirement])
            )
        ),
        soa=dict(applicability="Applicable"),
    ),
    now=datetime.now(timezone.utc),
)
if page == "Foundation":
    st.segmented_control(
        "Programme section",
        [
            "Overview",
            "Discovery",
            "Context",
            "Interested Parties",
            "ISMS Scope",
            "Governance",
            "Engagement",
        ],
        default="Overview",
        label_visibility="collapsed",
    )
    st.segmented_control("Governance", ["Roles & RACI", "Objectives"], default="Roles & RACI")
    from securescope.ui.grc_workspace import overview, formal

    context = dict(
        selected_engagement_id=2,
        selected_scope_id=9,
        scopes=[
            dict(
                id=9,
                name="Production",
                latest_status="Draft",
                latest_version_number=2,
                organizational_units=[] if empty else [1] * 12,
                locations=[] if empty else [1],
                technologies=[] if empty else [1, 2],
            )
        ],
    )

    def section(*args):
        return {
            name: [] if empty else [{"title": "Example"}]
            for name in ["context_issues", "interested_parties", "role_assignments"]
        }

    with (
        patch.object(formal.SERVICE, "load_section", side_effect=section),
        patch.object(formal, "versions", return_value=[]),
        patch.object(overview, "load_policies", return_value=([], [])),
        patch.object(overview, "list_risk_register", return_value=[]),
        patch.object(overview, "latest_statement_of_applicability", return_value=None),
    ):
        overview.render_overview(
            "Preview", context, lambda section: st.session_state.update(opened=section)
        )
elif page == "Assurance":
    from securescope.ui import assurance_dashboard as dashboard

    entries = (
        []
        if empty
        else [
            dict(
                control_id="A.8.16",
                title="Monitoring activities",
                owner="Security team",
                result=result,
                open_work=0,
                linked_risks=0,
            )
        ]
    )
    with (
        patch.object(dashboard, "selected_context_ids", return_value=(2, 9)),
        patch.object(dashboard, "current_actor", return_value="consultant@example.test"),
        patch.object(dashboard, "assurance_overview", return_value=entries),
    ):
        dashboard.render_assurance_dashboard("Preview", [])
elif page == "Control":
    st.title("Control Assurance")
    back_link("Control Profiles", key="control_back")
    assurance_workbench(
        dict(
            base,
            mode="control_workspace",
            result=result,
            control_id="A.8.16",
            title="Monitoring activities",
            scope=9,
            owner="Security team",
            actions=[],
            risks=[],
            history=[],
            evidence=[],
            documents=[],
        ),
        key="control",
    )
elif page == "Evidence":
    from securescope.ui.evidence_hub_ui import _manual_tab
    from securescope.evidence.models import WorkspaceRole

    st.title("Evidence")
    identity_context(base["actor"], "Consultant")
    with st.expander("Technical details"):
        st.caption("Provider identifiers and diagnostics are secondary information.")
    _manual_tab("Preview", base["actor"], WorkspaceRole.CONSULTANT)
elif page == "Risk":
    st.title("Risk Management")
    assurance_workbench(dict(base, mode="risk_overview"), key="risk")
elif page == "Remediation":
    from securescope.ui.exposure_management_ui import _workflow_step

    st.title("Remediation")
    for col, (label, value, tone) in zip(
        st.columns(4),
        [
            ("Remediation queue", 0 if empty else 12, "info"),
            ("High priority", 0 if empty else 4, "warning"),
            ("Overdue", 0, "neutral"),
            ("Ready to verify", 0 if empty else 2, "info"),
        ],
    ):
        with col:
            metric_card(
                label, value, "Current scope actions", tone if value else "neutral", compact=True
            )
    st.subheader("Remediation workflow")
    for col, label in zip(st.columns(5), ["Triage", "Planned", "In Progress", "Verify", "Closed"]):
        with col:
            _workflow_step(label, 0, "Current work items")
elif page == "Policies":
    assurance_workbench(
        dict(
            base,
            mode="policy_list",
            rows=(
                []
                if empty
                else [
                    dict(
                        policy_id="p1",
                        title="Information Security Policy for Customer Platforms and Shared Corporate Services",
                        status="Draft",
                        overall="Draft",
                        approvers=[],
                        owner="Security team",
                        controls=[],
                    )
                ]
            ),
        ),
        key="policies",
    )
elif page == "Policy Builder":
    from securescope.policies.suggestions import policy_template

    assurance_workbench(
        dict(
            base,
            mode="policy_builder",
            selected="p1",
            detail=dict(
                policy_template("Access Control", "Preview"),
                policy_version=1,
                owner="Security team",
            ),
        ),
        key="builder",
    )
elif page == "Wazuh":
    from securescope.ui.wazuh_settings_ui import render_wazuh_settings

    integration_summary("Wazuh SIEM", "Needs setup", "Configure the API, then test the connection.")
    with patch("securescope.ui.wazuh_settings_ui.require_connector_admin"):
        render_wazuh_settings("Preview")
elif page == "Nmap":
    st.title("Discover Assets / Nmap · field component verification")
    integration_summary("Nmap", "Unavailable", "Install Nmap on the scanner host before discovery.")
    st.text_input("Authorized target / CIDR / hostname", value="192.0.2.0/24")
    with st.expander("Advanced settings"):
        st.text_input("Host timeout")
    st.button("Start discovery", disabled=True, type="primary")
elif page == "Client Workspace":
    st.title("Client Workspace · field component verification")
    st.text_input("Search workspaces", placeholder="Search by workspace name")
    st.checkbox("Include archived workspaces")
    st.date_input("Review date")
    st.radio("Workspace view", ["Active", "Archived"], horizontal=True)
    st.slider("Page size", 10, 100, 25)

elif page in {"Control Profiles", "Assess Control"}:
    from securescope.ui import control_profiles_workbench as profiles
    from securescope.ui import control_assessment_ui as assessment
    from securescope.evidence.models import WorkspaceRole

    profile = dict(
        control_id="A.8.16",
        control_name="Monitoring activities",
        profile_id=1,
        profile_version=2,
        measurement_model="checklist",
        automation_level="Manual",
        control_owner="Security team",
        assessment_owner="Consultant",
        assessment_scope={
            "implementation_requirements": {
                "requirements": [
                    dict(requirement, id="monitoring-" + str(i), title=title)
                    for i, title in enumerate(
                        [
                            "Defined monitoring approach",
                            "Monitoring implementation",
                            "Regular operating review",
                        ]
                    )
                ]
            }
        },
        evidence_requirements=["Monitoring review reports"],
        target_id=1,
        target_version=1,
        target_description="Monitoring is performed and reviewed.",
    )
    with (
        patch(
            "securescope.ui.grc_workspace.context.selected_context_ids", return_value=(None, None)
        ),
        patch.object(profiles, "_identity", return_value=(base["actor"], WorkspaceRole.CONSULTANT)),
        patch.object(assessment, "working_actor", return_value=base["actor"]),
        patch.object(assessment, "load_register", return_value={"rows": [], "revision": 0}),
        patch.object(
            assessment,
            "list_evidence_records",
            return_value=[
                dict(
                    id=21,
                    title="Monitoring review report",
                    source="Evidence Workspace",
                    freshness_status="Current",
                    controls=[dict(control_id="A.8.16", approved=True)],
                )
            ],
        ),
        patch.object(assessment, "list_risk_register", return_value=[]),
        patch.object(assessment, "control_detail_history", return_value={"assessments": []}),
    ):
        if page == "Control Profiles":
            profiles.render_control_profiles(
                "Preview",
                [profile],
                [
                    {
                        "Control": "A.8.16",
                        "Title": "Monitoring activities",
                        "Applicability": "Pending",
                        "Evidence": "0%",
                        "Assurance": "Needs Review",
                        "Open gaps": 2,
                        "Owner": "Security team",
                    }
                ],
            )
        else:
            assessment.render_assessment("Preview", [profile])
elif page == "Project Plan":
    from datetime import date
    from securescope.ui import gap_dashboard_ui as plan

    tasks = (
        []
        if empty
        else [
            dict(
                task_ref=1,
                resource="Project Manager",
                start_date=date(2026, 8, 3),
                work_days=5,
                completed_days=5,
                revision=1,
            ),
            dict(
                task_ref=2,
                resource="Security team",
                start_date=date(2026, 9, 1),
                work_days=10,
                completed_days=4,
                revision=1,
            ),
        ]
    )
    with patch.object(plan, "load_project_plan", return_value={"tasks": tasks, "events": []}):
        plan.render_project_plan("Preview")
elif page == "SoA":
    from securescope.ui.soa_ownership import render_soa_working_editor

    rows = [
        dict(
            control_id=f"A.5.{i}",
            control_name=title,
            necessary_control=True,
            applicability="Applicable",
            inclusion_justification=(
                "" if i == 2 else "Required for information security governance."
            ),
            exclusion_justification="",
            implementation_status="Not assessed",
            control_owner="Security team",
            related_risks="",
            related_treatment_plans="",
            evidence="",
            effectiveness_review="",
            approved=False,
        )
        for i, title in enumerate(
            [
                "Policies for information security",
                "Information security roles and responsibilities",
                "Segregation of duties",
            ],
            1,
        )
    ]
    render_soa_working_editor("Preview", 2, 9, rows)
    st.caption(
        "Presentation fixture only. Version creation and approval are verified separately by regression tests."
    )
