"""Calculate transparent, catalog-based ISO assessment dashboard results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from securescope.grc.control_catalog import ISO_CONTROL_CATALOG

STANDARD_AREAS = (
    ("4", "Context of the organization"),
    ("5", "Leadership"),
    ("6", "Planning"),
    ("7", "Support"),
    ("8", "Operation"),
    ("9", "Performance evaluation"),
    ("10", "Improvement"),
    ("A.5", "Organizational controls"),
    ("A.6", "People controls"),
    ("A.7", "Physical controls"),
    ("A.8", "Technological controls"),
)
RESULT_STATES = ("Met", "Partially met", "Not met", "Not assessed", "Review required", "Excluded")


def area_for_control(control_id: str) -> str:
    """Resolve an existing catalog entry to its dashboard area.

    Args:
        control_id: Clause or Annex A control identifier.

    Returns:
        Area code, such as ``4`` or ``A.8``.

    Raises:
        ValueError: If the identifier is outside the assessment catalog.
    """

    if control_id not in ISO_CONTROL_CATALOG:
        raise ValueError(f"Unknown catalog entry: {control_id}")
    parts = control_id.split(".")
    return ".".join(parts[:2]) if parts[0] == "A" else parts[0]


def assessment_result(row: Mapping[str, Any]) -> str:
    """Classify one latest assessment without promoting advisory results.

    Args:
        row: Overview row with validation, current evidence and SoA metadata.

    Returns:
        One of ``RESULT_STATES``. Only approved Annex A exclusions reduce scope.

    Raises:
        ValueError: If an evidence count is invalid.
    """

    control_id = str(row.get("control_id") or "")
    soa_exclusion = row.get("soa_applicability") == "Not applicable"
    if (
        control_id.startswith("A.")
        and soa_exclusion
        and row.get("soa_approved") is True
        and str(row.get("soa_exclusion_justification") or "").strip()
    ):
        return "Excluded"
    status = str(row.get("assessment_status") or "Not assessed")
    if soa_exclusion or row.get("applicability") == "Not applicable" or status == "Not applicable":
        return "Review required"
    evaluation = row.get("implementation_evaluation")
    if evaluation:
        return {
            "Implemented": "Met",
            "Partially Implemented": "Partially met",
            "Not Implemented": "Not met",
            "Not Assessed": "Not assessed",
        }.get(evaluation.get("status"), "Review required")
    if status in {"Not assessed", "Manual assessment required"}:
        return "Not assessed"
    if status in {"Gap identified", "Not implemented"}:
        return "Not met"
    if status == "Partially implemented":
        return "Partially met"
    evidence_count = sum(
        int(row.get(field) or 0)
        for field in ("current_evidence_count", "assessment_current_evidence_count")
    )
    if (
        status == "Implemented and effective"
        and row.get("validation_status") == "Validated"
        and row.get("evidence_freshness") in {"Current", "Approaching expiration"}
        and evidence_count > 0
    ):
        return "Met"
    return "Review required"


def dashboard_entries(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Produce one entry per catalog unit, retaining missing units as unassessed.

    Args:
        rows: Client-scoped overview records, possibly with duplicate versions.

    Returns:
        Ordered assessment units with an area and a conservative result.

    Raises:
        ValueError: If profile versions or evidence counts are malformed.
    """

    latest: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        identifier = str(row.get("control_id") or "")
        if identifier not in ISO_CONTROL_CATALOG:
            continue
        previous = latest.get(identifier)
        rank = (int(row.get("profile_version") or 0), str(row.get("assessed_at") or ""))
        previous_rank = (
            (int(previous.get("profile_version") or 0), str(previous.get("assessed_at") or ""))
            if previous
            else (-1, "")
        )
        if rank >= previous_rank:
            latest[identifier] = row
    entries = []
    for identifier, metadata in ISO_CONTROL_CATALOG.items():
        record = {"control_id": identifier, **latest.get(identifier, {})}
        entries.append(
            {
                **record,
                "control_name": record.get("control_name") or metadata["name"],
                "area": area_for_control(identifier),
                "result": assessment_result(record),
            }
        )
    return entries


def summarize_entries(entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate units with a weighted denominator and explicit unknown results.

    Args:
        entries: Unique assessment units produced by ``dashboard_entries``.

    Returns:
        Counts, percentage of in-scope units met and assessment coverage.
        Percentages are None when every unit is legitimately excluded.

    Raises:
        KeyError: If an entry has no recognized result.
    """

    counts = {state: 0 for state in RESULT_STATES}
    for entry in entries:
        counts[entry["result"]] += 1
    total = len(entries)
    required = total - counts["Excluded"]
    assessed = required - counts["Not assessed"]
    return {
        "entries": total,
        "in_scope": required,
        "met": counts["Met"],
        "partial": counts["Partially met"],
        "not_met": counts["Not met"],
        "not_assessed": counts["Not assessed"],
        "review_required": counts["Review required"],
        "excluded": counts["Excluded"],
        "assessed": assessed,
        "conformity": 100 * counts["Met"] / required if required and assessed else None,
        "assessment_coverage": 100 * assessed / required if required else None,
    }


def area_summaries(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate the eleven standard areas in their natural display order.

    Args:
        entries: Unique catalog assessment units.

    Returns:
        Summary records containing code, label and counts for every area.

    Raises:
        KeyError: If a supplied entry lacks an area or result.
    """

    return [
        {
            "code": code,
            "area": f"{code} {label}",
            "label": label,
            **summarize_entries([entry for entry in entries if entry["area"] == code]),
        }
        for code, label in STANDARD_AREAS
    ]
