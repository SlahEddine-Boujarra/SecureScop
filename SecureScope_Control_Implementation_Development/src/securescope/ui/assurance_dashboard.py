"""Scoped assurance metrics with actionable filters over canonical evaluations."""

import logging

import streamlit as st

from securescope.grc.assurance_requirements import assurance_metrics
from securescope.grc.gap_dashboard import STANDARD_AREAS, area_for_control
from securescope.grc.requirement_templates import item_type
from securescope.persistence.assurance_workspace_repository import assurance_overview
from securescope.persistence.foundation_repository import FoundationError
from securescope.ui.control_workspace import open_control_workspace
from securescope.ui.grc_workspace.context import current_actor, selected_context_ids

LOGGER = logging.getLogger(__name__)


def attention_categories(entry: dict) -> set[str]:
    """Identify actionable conditions without inventing failed assessments.

    Args:
        entry: Current scoped evaluation and canonical open action count.
    Returns:
        Set of drill-down categories.
    Raises:
        KeyError: For malformed internal evaluation records.
    """
    result = entry["result"]
    if result["applicability"] == "Not Applicable":
        return set()
    required = [r for r in result["requirements"] if r["mandatory"]]
    categories = set()
    if any(r["result"] == "NO EVIDENCE" for r in required):
        categories.add("Missing Evidence")
    if any(r["rule"] == "Approved policy" and r["result"] != "PASS" for r in required):
        categories.add("Missing Required Policy")
    if any(r["result"] == "FAIL" for r in required):
        categories.add("Failed Requirement")
    if any(r["freshness"] == "Stale" for r in required):
        categories.add("Stale Evidence")
    if result["applicability"] == "Pending":
        categories.add("Applicability Pending")
    if not result["assessed"]:
        categories.add("Requires Assessment")
    if entry.get("open_work", 0):
        categories.add("Open Remediation")
    return categories


def render_assurance_dashboard(client: str, rows: list[dict]) -> bool:
    """Render metrics and direct entry navigation for the current ISMS Scope.

    Args:
        client: Selected workspace.
        rows: Current scoped profile summaries.
    Returns:
        True when the scoped dashboard is rendered, otherwise False.
    Raises:
        Unexpected programming errors propagate; expected read failures display inline.
    """
    engagement, scope = selected_context_ids(client)
    if not engagement or not scope:
        st.info("Select an ISMS Scope to view implementation assurance.")
        return False
    try:
        entries = assurance_overview(client, current_actor(), engagement, scope, rows)
    except FoundationError as exc:
        LOGGER.warning("Assurance dashboard unavailable: %s", type(exc).__name__)
        st.error(f"Assurance metrics unavailable: {exc}")
        return True
    key = f"assurance_dashboard::{client}::{engagement}::{scope}"
    from securescope.ui.components_v2.assurance_pages import assurance_page
    from securescope.ui.soa_ownership import pending_soa_applicability

    pending_soa = pending_soa_applicability(client, engagement, scope)
    if pending_soa:
        st.info(
            f"{len(pending_soa)} unsaved SoA applicability change(s). "
            "The metrics below reflect approved decisions; save and approve the SoA "
            "version to apply these changes."
        )
    results = [entry["result"] for entry in entries]
    metrics = assurance_metrics(results)
    applicable = [result for result in results if result["applicability"] == "Applicable"]
    counts = [{"label": "Applicable Items", "value": len(applicable)}]
    for status in [
        "Implemented",
        "Partially Implemented",
        "Not Implemented",
        "Insufficient Evidence",
    ]:
        counts.append(
            {"label": status, "value": sum(r["implementation"] == status for r in applicable)}
        )
    counts.append({"label": "Not Assessed", "value": sum(not r["assessed"] for r in results)})
    coverage = []
    for field, label in [
        ("implementation_coverage", "Implementation Coverage"),
        ("assessment_coverage", "Assessment Coverage"),
        ("evidence_coverage", "Evidence Coverage"),
    ]:
        value = metrics[field]
        if field == "assessment_coverage":
            value = value or 0
        if field == "implementation_coverage" and not any(
            r["assessed"] or r["evidence_coverage"] for r in results
        ):
            value = None
        coverage.append(
            {
                "label": label,
                "value": (
                    f"{value:.1f}%"
                    if value is not None
                    else "Not Assessed" if field == "implementation_coverage" else "Not Configured"
                ),
                "percent": value,
            }
        )
    coverage.append(
        {
            "label": "Effective Items",
            "value": sum(r["assurance"] == "Effective" for r in applicable),
        }
    )
    configured = any(r["mandatory_count"] and not r.get("baseline_preview") for r in results)
    coverage.append(
        {
            "label": "Open Requirement Gaps",
            "value": (
                sum(
                    sum(q["mandatory"] and q["result"] != "PASS" for q in r["requirements"])
                    for r in applicable
                )
                if configured
                else "Not Determined"
            ),
        }
    )
    categories = [
        "Missing Evidence",
        "Missing Required Policy",
        "Failed Requirement",
        "Stale Evidence",
        "Applicability Pending",
        "Requires Assessment",
        "Open Remediation",
    ]
    from securescope.persistence.db_service import DatabaseConfigurationError
    from securescope.persistence.grc_repository import (
        GrcRepositoryError,
        list_statement_of_applicability_versions,
    )
    from securescope.ui.control_presenter import human_assessment_label

    try:
        versions = list_statement_of_applicability_versions(
            client, engagement_id=engagement, scope_id=scope
        )
    except (GrcRepositoryError, DatabaseConfigurationError) as exc:
        LOGGER.warning("SoA applicability summary unavailable: %s", type(exc).__name__)
        st.error("SoA applicability summary is unavailable. Refresh after checking the connection.")
        return True
    approved_soa = any(v.get("status") == "Approved" for v in versions)
    if not approved_soa:
        st.info("Applicability review pending")
    area_rows = []
    for code, _label in STANDARD_AREAS:
        group = [
            e["result"]
            for e in entries
            if area_for_control(e["control_id"]) == code
            and e["result"]["applicability"] == "Applicable"
        ]
        area_rows.append(
            {
                "Area": code,
                "Applicable": sum(r["applicability"] == "Applicable" for r in group),
                "Assessed": sum(r["assessed"] for r in group),
                "Implemented": sum(r["implementation"] == "Implemented" for r in group),
                "Partial": sum(r["implementation"] == "Partially Implemented" for r in group),
                "Not Implemented": sum(r["implementation"] == "Not Implemented" for r in group),
                "Evidence Gaps": sum(
                    r["evidence_status"] in {"Missing", "Partial", "Stale"} for r in group
                ),
                "Open Gaps": (
                    sum(
                        e.get("open_work", 0)
                        for e in entries
                        if area_for_control(e["control_id"]) == code
                        and e["result"]["applicability"] == "Applicable"
                    )
                    if any(r["assessed"] for r in group)
                    else "Not Determined"
                ),
                "Review": "Not Assessed" if not any(r["assessed"] for r in group) else "Recorded",
            }
        )

    view_rows = [
        dict(
            control_id=e["control_id"],
            title=e["title"],
            owner=e["owner"] or "Unassigned",
            kind=item_type(e["control_id"]),
            area=area_for_control(e["control_id"]),
            applicability=e["result"]["applicability"],
            implementation=e["result"]["implementation"],
            evidence_status=e["result"]["evidence_status"],
            assurance=human_assessment_label(
                next(
                    (
                        r.get("assessment_status")
                        for r in rows
                        if r["control_id"] == e["control_id"]
                    ),
                    None,
                )
            ),
            attention=sorted(attention_categories(e)),
            open_work=e.get("open_work", 0),
            linked_risks=e.get("linked_risks", 0),
        )
        for e in entries
    ]

    def navigate(event):
        """Navigate an authorized control action; return None; preserve scope."""
        from securescope.ui.assurance_interactions import open_control_assessment
        from securescope.ui.gap_dashboard_ui import select_assurance_tab

        if event.get("action") == "profiles":
            select_assurance_tab(client, ":material/table_view: Control profiles")
        elif event.get("action") == "assess":
            open_control_assessment(client)
        elif event.get("action") == "open" and event.get("id") in {
            r["control_id"] for r in view_rows
        }:
            open_control_workspace(client, event["id"])

    assurance_page(
        dict(
            mode="dashboard",
            title="Assurance Dashboard",
            subtitle=f"Current ISMS Scope #{scope} · ISO Requirements & Annex A Controls",
            metrics=counts,
            coverage=coverage,
            areas=area_rows if approved_soa else [],
            attention=[
                {"label": c, "value": sum(c in attention_categories(e) for e in entries)}
                for c in categories
            ],
            rows=view_rows,
            filters=[
                {"key": key, "label": label}
                for key, label in [
                    ("kind", "All types"),
                    ("area", "All ISO areas"),
                    ("owner", "All owners"),
                    ("applicability", "All applicability"),
                    ("implementation", "All implementation"),
                    ("evidence_status", "All evidence"),
                    ("assurance", "All assessments"),
                ]
            ],
            columns=[
                {
                    "key": key,
                    "label": label,
                    "kind": (
                        "status"
                        if key
                        in {"applicability", "implementation", "evidence_status", "assurance"}
                        else "text"
                    ),
                }
                for key, label in [
                    ("control_id", "Control"),
                    ("title", "Title"),
                    ("owner", "Owner"),
                    ("applicability", "Applicability"),
                    ("implementation", "Implementation"),
                    ("evidence_status", "Evidence"),
                    ("assurance", "Human Assessment"),
                    ("open_work", "Open actions"),
                ]
            ],
        ),
        key=key,
        on_action=navigate,
    )
    return True
