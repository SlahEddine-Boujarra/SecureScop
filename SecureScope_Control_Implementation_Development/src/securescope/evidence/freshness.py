"""Shared evidence currency derived from canonical timestamps."""

from datetime import datetime, timedelta


def evidence_freshness(evidence: dict, days: int, now: datetime) -> str:
    """Determine currency from collection and expiry timestamps, never from display text.

    Args:
        evidence: Canonical evidence metadata.
        days: Requirement maximum age.
        now: Evaluation timestamp with timezone.
    Returns:
        Current, Expiring Soon, Stale or Unknown.
    Raises:
        ValueError: If the evaluation timestamp is naive.
    """
    from securescope.grc.control_implementation import as_datetime

    days = min(days, evidence.get("max_age_days") or days)
    if now.tzinfo is None:
        raise ValueError("Evaluation time must include a timezone.")
    if evidence.get("freshness_status") == "Expired":
        return "Stale"
    if evidence.get("freshness_status") == "Unknown":
        return "Unknown"
    collected = as_datetime(evidence.get("collected_at"))
    if not collected or collected > now:
        return "Unknown"
    expires = as_datetime(evidence.get("expires_at"))
    if evidence.get("expires_at") and not expires:
        return "Unknown"
    deadline = (
        min(collected + timedelta(days=days), expires)
        if expires
        else collected + timedelta(days=days)
    )
    if deadline <= now:
        return "Stale"
    return "Expiring Soon" if deadline - now <= timedelta(days=min(7, days / 5)) else "Current"
