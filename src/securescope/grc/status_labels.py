"""User-facing labels for existing persisted workflow states."""

LABELS = {
    "under_review": "Submitted for Review",
    "Under review": "Submitted for Review",
    "In review": "Submitted for Review",
    "Changes requested": "Changes Requested",
    "Not started": "Not Started",
    "In progress": "In Progress",
    "Monitoring & review": "Monitoring & Review",
    "Treatment plan": "Treatment Plan",
    "Residual assessment": "Residual Assessment",
    "Risk assessment": "Risk Assessment",
}


def status_label(value: str | None) -> str:
    """Format an existing state without changing its stored enum.

    Args:
        value: Existing status or title.
    Returns:
        Human-readable consistent label.
    Raises:
        No exceptions are raised.
    """
    return LABELS.get(value, value or "Not Started")
