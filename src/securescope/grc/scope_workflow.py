"""Scope presentation and comparison without changing stored historical values."""

from datetime import date, datetime

SCOPE_FIELDS = {
    "scope_statement": "Scope Statement",
    "organizational_units": "Organizational Units",
    "locations": "Locations",
    "technologies": "Technologies",
    "products_and_services": "Products / Services",
    "boundaries": "Boundaries",
    "interfaces_and_dependencies": "Dependencies & Interfaces",
    "exclusions": "Exclusions & Justification",
    "assumptions": "Assumptions",
}


def display_person(value):
    """Format an audit identity for display.

    Args:
        value: Stored person or migration identifier.
    Returns:
        str: Readable identity, without modifying the stored value.
    Raises:
        No exceptions are raised.
    """
    text = str(value or "").strip()
    return "System migration" if text.startswith("migration-") else text or "—"


def display_date(value):
    """Format dates without exposing Python serialization.

    Args:
        value: Stored date, datetime or ISO string.
    Returns:
        str: Readable calendar date, or an em dash when absent.
    Raises:
        No exceptions are raised for invalid dates.
    """
    if not value:
        return "—"
    try:
        parsed = (
            value if isinstance(value, (date, datetime)) else date.fromisoformat(str(value)[:10])
        )
        return parsed.strftime("%d %b %Y")
    except ValueError:
        return "Unknown date"


def scope_changes(before: dict, after: dict) -> list[dict]:
    """Compare user-facing scope fields.

    Args:
        before: Earlier scope version.
        after: Later scope version or proposed draft.
    Returns:
        list[dict]: Changed fields with readable before/after values.
    Raises:
        No exceptions are raised for mapping inputs.
    """
    rows = []
    for key, label in SCOPE_FIELDS.items():
        old, new = before.get(key) or "", after.get(key) or ""
        if isinstance(old, (list, tuple)) or isinstance(new, (list, tuple)):
            old, new = list(old or []), list(new or [])
            if old != new:
                rows.append(
                    {
                        "Field": label,
                        "Before": ", ".join(old) or "—",
                        "After": ", ".join(new) or "—",
                        "Added": ", ".join(x for x in new if x not in old) or "—",
                        "Removed": ", ".join(x for x in old if x not in new) or "—",
                    }
                )
        elif old != new:
            rows.append({"Field": label, "Before": str(old) or "—", "After": str(new) or "—"})
    return rows


def filter_scope_risks(rows: list[dict], mode: str, scope_id: int | None) -> list[dict]:
    """Filter canonical risks without assigning legacy data to a guessed scope.

    Args:
        rows: Client-scoped canonical risks.
        mode: All client risks, Current ISMS Scope or Unassigned scope.
        scope_id: Selected scope, if present.
    Returns:
        list[dict]: Matching original records.
    Raises:
        ValueError: For unsupported filter modes.
    """
    if mode == "All client risks":
        return rows
    if mode == "Unassigned scope":
        return [r for r in rows if r.get("primary_scope_id") is None]
    if mode == "Current ISMS Scope":
        return [r for r in rows if scope_id is not None and r.get("primary_scope_id") == scope_id]
    raise ValueError("Choose a supported risk scope filter.")


def compose_scope_proposal(
    existing: dict, generated: dict, *, replace_text: bool = False, replace_lists: bool = False
) -> dict:
    """Merge a suggestion without silently discarding human-entered scope content.

    Args:
        existing: Current scope definition and version.
        generated: Proposed scope fields from confirmed Discovery facts.
        replace_text: Explicit permission to replace statement and boundary text.
        replace_lists: Explicit permission to replace boundary lists.
    Returns:
        A new proposal, retaining unrelated metadata and manual fields.
    Raises:
        No exceptions are raised for validated scope mappings.
    """
    proposal = dict(existing)
    for key, value in generated.items():
        current = existing.get(key)
        if isinstance(value, (list, tuple)):
            proposal[key] = (
                list(value) if replace_lists else list(dict.fromkeys([*(current or []), *value]))
            )
        elif not current or replace_text and key in {"scope_statement", "boundaries"}:
            proposal[key] = value
    return proposal


def scope_content_matches(current: dict, proposed: dict) -> bool:
    """Compare editable scope content, excluding version decision metadata.

    Args:
        current: Latest persisted version plus definition name.
        proposed: Validated draft values.
    Returns:
        True if saving would produce an identical content version.
    Raises:
        No exceptions are raised for scope mappings.
    """
    return not scope_changes(current, proposed) and all(
        str(current.get(key) or "") == str(proposed.get(key) or "")
        for key in ("name", "effective_from", "effective_to")
    )
