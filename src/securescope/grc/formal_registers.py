"""Shared minimal formal-register validation; no independent risk scoring."""

from __future__ import annotations

from datetime import date
from typing import Any

FIELDS = {
    "policy": ("title", "policy_text", "owner", "evidence"),
    "objectives": (
        "title",
        "measure",
        "baseline",
        "target",
        "action_plan",
        "resources",
        "due_date",
        "owner",
        "evidence",
    ),
}
TRANSITIONS = {
    "Not started": {"Suggested", "Draft"},
    "Suggested": {"Draft", "In review"},
    "Draft": {"Draft", "In review"},
    "In review": {"Draft", "Approved"},
    "Approved": {"Draft"},
}


def validate_records(kind: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate formal rows before review.

    Args:
        kind: Policy, objectives or existing risk snapshot key.
        records: User-entered records or canonical risks.
    Returns:
        Validated records.
    Raises:
        ValueError: If a required input is missing or invalid.
    """
    if kind not in {"policy", "objectives", "risks"}:
        raise ValueError("Unknown formal register.")
    if not records:
        raise ValueError("Add at least one record before review.")
    required = {
        "policy": ("title", "policy_text", "owner"),
        "objectives": (
            "title",
            "measure",
            "target",
            "action_plan",
            "resources",
            "due_date",
            "owner",
        ),
        "risks": (
            "risk_ref",
            "threat",
            "risk_owner",
            "pre_likelihood",
            "pre_impact",
            "treatment_option",
        ),
    }[kind]
    for number, row in enumerate(records, 1):
        missing = [key for key in required if not str(row.get(key) or "").strip()]
        if missing:
            raise ValueError(f"Row {number}: complete {', '.join(missing)}.")
        if kind == "objectives":
            date.fromisoformat(str(row["due_date"])[:10])
        if kind == "risks":
            for field in ("pre_likelihood", "pre_impact"):
                value = row[field]
                if type(value) is not int or value not in (1, 2, 3, 4, 5):
                    raise ValueError(f"Row {number}: ratings must be integers 1–5.")
    return records


def next_status(previous: str, requested: str, role: str, note: str) -> str:
    """Enforce review before approval and prevent auditor writes.

    Args:
        previous: Stored latest status or Not started.
        requested: Requested next status.
        role: Active database membership role.
        note: Human review or approval rationale.
    Returns:
        Validated next status.
    Raises:
        ValueError: For an unauthorized or invalid transition.
    """
    if role not in {"Administrator", "Consultant", "Client contributor"}:
        raise ValueError("An active contributor membership is required.")
    if requested not in TRANSITIONS.get(previous, set()):
        raise ValueError(f"Cannot move from {previous} to {requested}.")
    if requested in {"In review", "Approved"} and not note.strip():
        raise ValueError("Record the review rationale.")
    if requested == "Approved" and role != "Administrator":
        raise ValueError("Only a workspace Administrator can approve.")
    return requested


def risk_signature(records: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """Return canonical references/revisions for stale-review detection.

    Args:
        records: Existing canonical risks or a saved review snapshot.
    Returns:
        Sorted reference and revision pairs.
    Raises:
        ValueError: If persisted identifiers are invalid.
    """
    return sorted((int(row["risk_ref"]), int(row["revision"])) for row in records)
