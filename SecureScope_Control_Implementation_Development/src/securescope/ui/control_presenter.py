"""Conservative, framework-independent labels for human control assessments."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

ASSESSMENT_LABELS = {
    "Not assessed": "Not Reviewed",
    "Manual assessment required": "Not Reviewed",
    "Insufficient evidence": "Insufficient Evidence",
    "Not implemented": "Not Implemented",
    "Gap identified": "Not Implemented",
    "Partially implemented": "Partially Implemented",
    "Implemented but not verified": "Verification Pending",
    "Target achieved": "Target Achieved",
    "Implemented": "Implemented",
    "Implemented and effective": "Implemented",
    "Accepted residual risk": "Accepted Risk",
    "Not applicable": "Not Applicable",
}


def human_assessment_label(value: Any) -> str:
    """Preserve incomplete verification, risk acceptance and target decisions.

    Args:
        value: Stored human assessment status, or None.

    Returns:
        Display label; unfamiliar stored statuses remain visible verbatim.

    Raises:
        No exceptions are intentionally raised.
    """

    status = str(value or "Not assessed").strip()
    return ASSESSMENT_LABELS.get(status, status)


def status_tone(value: Any) -> str:
    """Select a chip tone without treating unverified evidence as success.

    Args:
        value: A human decision, advisory signal or evidence label.

    Returns:
        A supported semantic tone: success, warning, danger or muted.

    Raises:
        No exceptions are intentionally raised.
    """

    label = str(value or "").casefold()
    if any(word in label for word in ("expired", "rejected", "gap signal")):
        return "danger"
    if label in {"not implemented", "gap identified", "critical", "high"}:
        return "danger"
    if any(
        word in label
        for word in (
            "pending",
            "partial",
            "insufficient",
            "not verified",
            "accepted",
            "target achieved",
            "approaching",
            "unknown",
            "likely",
            "manual review",
            "review required",
            "need review",
        )
    ):
        return "warning"
    if label in {"implemented", "implemented and effective"}:
        return "success"
    if "current" in label or "validated" in label:
        return "success"
    return "muted"


def evidence_coverage_counts(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[int, int]:
    """Count applicable controls with current, validated and approved evidence.

    Args:
        rows: Current workspace control overview including current_evidence_count.

    Returns:
        Covered and applicable counts, deduplicated by control ID. Evidence for
        excluded controls never contributes to the numerator.

    Raises:
        TypeError: If rows contain non-mapping values.
        ValueError: If a repository evidence count is not an integer.
    """

    applicable = {
        str(row["control_id"]): row
        for row in rows
        if row.get("control_id")
        and str(row.get("applicability") or "").casefold() != "not applicable"
    }
    covered = sum(int(row.get("current_evidence_count") or 0) > 0 for row in applicable.values())
    return covered, len(applicable)
