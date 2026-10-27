"""Preview production UI components with synthetic data and session-only saves.

Run: python -m streamlit run scripts/preview_assurance_ux.py
No client database, credentials, scanner or external service is used.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import streamlit as st

from securescope.ui import control_assessment_ui as assessment
from securescope.ui import control_profiles_workbench as profiles
from securescope.ui.risk_register_table import render_risk_register_table

st.set_page_config(page_title="SecureScope · UI preview", layout="wide")
st.caption("SECURESCOPE · INTERACTIVE PREVIEW · SYNTHETIC RECORDS")
mode = st.radio(
    "Preview workspace", ["Control profiles", "Assess control", "Risk register"], horizontal=True
)
row = st.session_state.setdefault(
    "preview_profile",
    {
        "control_id": "A.8.8",
        "control_name": "Management of technical vulnerabilities",
        "control_objective": "Identify, evaluate and address technical vulnerabilities across the approved scope.",
        "profile_id": 1,
        "profile_version": 3,
        "measurement_model": "checklist",
        "automation_level": "Manual",
        "control_owner": "Infrastructure team",
        "assessment_owner": "Security consultant",
        "assessment_scope": {"description": "Production services and managed endpoints"},
        "assessment_methods": ["Review vulnerability reports", "Sample completed remediation"],
        "evidence_requirements": ["Current vulnerability register", "Approved change records"],
        "target_id": 1,
        "target_version": 2,
        "target_description": "Critical findings are remediated within the approved service target.",
    },
)
profiles._identity = lambda *args: ("preview@example.test", "Consultant")
assessment._identity = profiles._identity
assessment.working_actor = lambda *args: "preview@example.test"
assessment.load_register = lambda *args: st.session_state.get(
    "preview_draft", {"rows": [], "revision": 0}
)
assessment.list_evidence_records = lambda *args, **kwargs: []
assessment.control_detail_history = lambda *args: {"assessments": []}


def save_draft(client, key, rows, **kwargs):
    """Retain preview drafts in this browser session only."""
    revision = kwargs["expected_revision"] + 1
    st.session_state.preview_draft = {"rows": rows, "revision": revision}
    return revision


def save_profile(client, control, **values):
    """Demonstrate versioned updates without connecting to a database."""
    row.update({key: value for key, value in values.items() if key in row})
    row["profile_version"] += 1
    return row["profile_version"]


assessment.save_register = save_draft
assessment.save_manual_control_assessment = lambda *args, **kwargs: None
assessment.create_control_target = lambda *args, **kwargs: None
profiles.create_profile_version = save_profile
if st.session_state.pop("manual_control_pending::Preview", None):
    mode = "Assess control"
if mode == "Control profiles":
    st.title("Control profiles")
    st.caption("Select a control to inspect and update its assessment profile.")
    profiles.render_control_profiles(
        "Preview",
        [row],
        [
            {
                "Control": "A.8.8",
                "Human assessment": "Not Reviewed",
                "SecureScope recommendation": "Evidence review required",
            }
        ],
    )
elif mode == "Assess control":
    assessment.render_assessment("Preview", [row])
else:
    st.title("Risk register")
    render_risk_register_table(
        [
            {
                "risk_ref": 1,
                "asset": "Customer services platform",
                "asset_group": "Information",
                "threat": "External access to confidential customer data through an unpatched internet-facing service",
                "vulnerability": "A critical dependency requires an approved security update",
                "risk_owner": "security.owner@example.test",
                "pre_likelihood": 3,
                "pre_impact": 4,
                "post_likelihood": 2,
                "post_impact": 3,
                "treatment_option": "Mitigate",
                "treatment_status": "In Progress",
                "existing_controls": "Managed access and central monitoring",
                "pre_impact_rationale": "Loss of confidentiality could affect customers and interrupt contracted services.",
            }
        ],
        key="preview_risks",
    )
