"""Risk-register vocabulary, scoring and starter records for ISO workflows."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ASSET_GROUPS = (
    "Business activities",
    "Information",
    "Software",
    "Hardware",
    "Network",
    "Physical/Site",
    "People",
    "Organization",
    "Other",
)

ASSET_TAXONOMY: dict[str, dict[str, tuple[str, ...]]] = {
    "Business activities": {
        "": ("Business-critical activities", "Supporting activities", "Compliance")
    },
    "Information": {
        "Cloud customer data": ("Personally identifiable information (PII)", "Non-PII"),
        "Corporate": ("Budgets", "Sales forecasts", "Corporate plans", "Corporate policies"),
        "Sales and Marketing": (
            "Customer records - names, addresses, contacts",
            "Customer credit card information",
            "Customer bank details",
            "Website information",
            "Customer preferences and purchase history",
            "Customer correspondence and complaints",
        ),
        "Human Resources": (
            "Employee records",
            "Employee expense claims",
            "Payroll information",
            "Training records",
            "Recruitment information",
            "Security clearance/check information",
            "Employee complaints/disciplinary records",
            "Sickness/occupational health records",
            "Employment contracts",
        ),
        "Finance": ("Accounting records", "Business account banking details"),
        "Buying": ("Supplier contact details", "Buying plans", "Commercial terms"),
        "Legal": (
            "Supplier contracts",
            "Customer contracts",
            "Property leases",
            "Credit agreements",
            "Insurance policies",
        ),
        "Operations": (
            "Documents held on behalf of customers",
            "Product specifications and bills of materials",
            "Process and procedural documentation",
            "Intellectual Property specific to the organisation",
            "Resource plans",
        ),
        "Audit and Compliance": (
            "Internal audit records",
            "External audit reports",
            "Risk assessments",
        ),
    },
    "Software": {
        "": (
            "Email",
            "Accounting",
            "Payroll",
            "Bespoke software",
            "Intranet",
            "Website",
            "Design",
            "Office applications",
            "Marketing",
            "Industry-specific applications",
        )
    },
    "Hardware": {
        "": (
            "Computer servers",
            "Networking equipment",
            "Personal Computers",
            "Mobile devices",
            "Mobile/Smart phones",
        )
    },
    "Network": {"": ("Network connections", "Network devices", "Network configurations")},
    "Physical/Site": {
        "": (
            "Buildings",
            "Server rooms",
            "Machinery",
            "Stock",
            "Vehicles",
            "Gas supply",
            "Water",
            "Network services",
            "Telephone services",
        )
    },
    "People": {
        "Key resources": ("Owner/Chief Executive", "Managers", "Engineers", "Knowledge holders")
    },
    "Organization": {"": ("Management", "Structure", "Project", "Suppliers")},
    "Other": {"": ("Other",)},
}

TREATMENT_OPTIONS = ("Modify", "Accept", "Avoid", "Transfer / Share")
TREATMENT_STATUSES = (
    "Not Started",
    "In Progress",
    "Completed",
    "Blocked",
    "Cancelled",
    "Rejected",
    "Accepted risk",
)
RISK_TYPES = ("C", "I", "A", "CIA")


def risk_score(likelihood: Any, impact: Any) -> int | None:
    """Return the 1–25 score when both assessment values are complete."""

    try:
        likelihood_value = int(likelihood)
        impact_value = int(impact)
    except (TypeError, ValueError):
        return None
    if not 1 <= likelihood_value <= 5 or not 1 <= impact_value <= 5:
        return None
    return likelihood_value * impact_value


def risk_level(score: Any) -> str:
    """Map a 1–25 risk score to a readable level."""

    try:
        numeric = int(score)
    except (TypeError, ValueError):
        return "Not assessed"
    if numeric <= 0:
        return "Not assessed"
    if numeric <= 4:
        return "Low"
    if numeric <= 9:
        return "Medium"
    if numeric <= 16:
        return "High"
    return "Critical"


def risk_row_with_scores(row: Mapping[str, Any]) -> dict[str, Any]:
    """Copy one stored row and expose derived pre/post scores and levels."""

    result = dict(row)
    pre_score = risk_score(row.get("pre_likelihood"), row.get("pre_impact"))
    post_score = risk_score(row.get("post_likelihood"), row.get("post_impact"))
    result["pre_risk_score"] = pre_score
    result["pre_risk_level"] = risk_level(pre_score)
    result["post_risk_score"] = post_score
    result["post_risk_level"] = risk_level(post_score)
    return result


def starter_risks() -> list[dict[str, Any]]:
    """Return conservative starter records based on the supplied ISO examples."""

    examples = (
        (
            1,
            "Information",
            "",
            "Customer database",
            "External hacker gains access and steals confidential data",
            "Internet-facing web server",
            "CIO",
            3,
            4,
            "Modify",
            "Improve patching and anti-malware",
            "A.8.7, A.8.8",
            2,
            4,
        ),
        (
            2,
            "Network",
            "",
            "Network storage",
            "Ransomware encrypts connected data",
            "Backup strategy needs improvement",
            "CIO",
            3,
            4,
            "Modify",
            "Improve backups and anti-malware",
            "A.8.7, A.8.13",
            2,
            4,
        ),
        (
            3,
            "Network",
            "",
            "Web server",
            "DDoS attack brings the web server down",
            "Internet exposure is required",
            "CIO",
            3,
            4,
            "Transfer / Share",
            "Distribute service across locations",
            "A.8.20, A.8.21",
            None,
            None,
        ),
        (
            4,
            "Hardware",
            "",
            "Removable media",
            "Media is lost or stolen without effective protection",
            "Unencrypted memory sticks are used",
            "CIO",
            4,
            4,
            "Avoid",
            "Restrict removable media and provide secure alternatives",
            "A.7.10",
            2,
            2,
        ),
        (
            5,
            "Software",
            "",
            "CRM system",
            "Vulnerable software exposes confidential data",
            "Secure-coding guidance is missing",
            "Development Manager",
            4,
            4,
            "Modify",
            "Establish secure development standards and training",
            "A.8.25, A.8.32",
            2,
            4,
        ),
        (
            6,
            "Organization",
            "",
            "Supplier service",
            "Supplier breach involves organizational information",
            "Contracts lack minimum security requirements",
            "Supplier Manager",
            3,
            3,
            "Modify",
            "Add security requirements to supplier contracts",
            "A.5.19, A.5.20",
            2,
            3,
        ),
        (
            7,
            "Information",
            "",
            "Incident response",
            "Responsibilities are unclear during an incident",
            "No defined incident-management plan",
            "CISO",
            4,
            3,
            "Modify",
            "Create an incident-management plan with roles",
            "A.5.2, A.5.24, A.5.26",
            2,
            3,
        ),
        (
            8,
            "Physical/Site",
            "",
            "Head Office",
            "Sensitive areas are not clearly separated",
            "Shared locations have unclear boundaries",
            "Facilities Manager",
            2,
            2,
            "Accept",
            "Document the residual risk and review access",
            "A.7.1, A.7.2",
            2,
            2,
        ),
        (
            9,
            "People",
            "Key resources",
            "User accounts",
            "Shared accounts allow unauthorized access",
            "Temporary staff use shared credentials",
            "COO",
            4,
            3,
            "Modify",
            "Enforce named accounts and access control",
            "A.5.15",
            2,
            3,
        ),
        (
            10,
            "Information",
            "Corporate",
            "Confidential information",
            "Employees expose information accidentally",
            "Classification and labelling are inconsistent",
            "CISO",
            4,
            3,
            "Modify",
            "Define and implement classification and labelling",
            "A.5.12, A.5.13",
            2,
            3,
        ),
        (
            11,
            "People",
            "Key resources",
            "Recruitment",
            "A new employee deliberately breaches security",
            "References and background checks are inconsistent",
            "HR Manager",
            3,
            4,
            "Modify",
            "Adopt role-sensitive screening procedures",
            "A.6.1",
            2,
            4,
        ),
        (
            12,
            "Business activities",
            "",
            "Security knowledge",
            "Threat knowledge becomes outdated",
            "No budget for specialist groups or training",
            "CISO",
            3,
            3,
            "Modify",
            "Create a budget for specialist information-security groups",
            "A.5.6",
            3,
            3,
        ),
        (
            13,
            "Information",
            "Operations",
            "Work in progress",
            "Support staff read sensitive information left unattended",
            "Clear-desk practices are inconsistent",
            "COO",
            4,
            3,
            "Modify",
            "Adopt and inspect a clear-desk policy",
            "A.7.7",
            2,
            3,
        ),
    )
    rows: list[dict[str, Any]] = []
    for (
        ref,
        group,
        subcategory,
        asset,
        threat,
        vulnerability,
        owner,
        likelihood,
        impact,
        option,
        action,
        controls,
        post_likelihood,
        post_impact,
    ) in examples:
        rows.append(
            {
                "risk_ref": ref,
                "asset_group": group,
                "asset_subcategory": subcategory,
                "asset": asset,
                "threat": threat,
                "vulnerability": vulnerability,
                "risk_type": "CIA" if ref in {5, 7, 10} else "C",
                "risk_owner": owner,
                "existing_controls": "Documented controls require review",
                "pre_likelihood": likelihood,
                ("pre_likelihood_rationale"): (
                    "Based on current exposure and observed threat " "frequency."
                ),
                "pre_impact": impact,
                "pre_impact_rationale": (
                    "Based on confidentiality, integrity and availability " "consequences."
                ),
                "treatment_option": option,
                "treatment_action": action,
                "control_references": [item.strip() for item in controls.split(",")],
                "treatment_cost": None,
                "treatment_action_owner": owner,
                "treatment_action_timescale": "90 days",
                "treatment_action_progress": "Starter record — validate with the risk owner",
                "treatment_action_status": "Not Started",
                "post_likelihood": post_likelihood,
                ("post_likelihood_rationale"): (
                    "Expected likelihood after treatment; confirm during " "review."
                ),
                "post_impact": post_impact,
                "post_impact_rationale": "Expected impact after treatment; confirm during review.",
                "comments": "Starter example from the ISO risk-register workflow.",
            }
        )
    return rows
