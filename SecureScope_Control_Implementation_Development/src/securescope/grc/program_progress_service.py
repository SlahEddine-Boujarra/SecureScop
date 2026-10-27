"""Deterministic ISO 27001 programme-foundation progress calculations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class ProgressItem:
    """Represent one required programme-foundation work item.

    Args:
        key: Stable machine identifier.
        label: Human-readable work-item label.
        complete: Whether the item currently satisfies its explicit rule.
        section: Programme Setup section that resolves the item.
        action: Short next action shown when the item is incomplete.

    Raises:
        No exceptions are raised.
    """

    key: str
    label: str
    complete: bool
    section: str
    action: str


@dataclass(frozen=True)
class ProgressDimension:
    """Describe one ISO 27001 programme progress dimension.

    Args:
        key: Stable dimension identifier.
        label: Human-readable dimension name.
        completed: Completed required items for measured dimensions.
        total: Total required items for measured dimensions.
        status: Explicit state such as ``Measured`` or ``Not measured``.
        route: Application route associated with the dimension.

    Raises:
        No exceptions are raised.
    """

    key: str
    label: str
    completed: int
    total: int
    status: str
    route: str

    @property
    def percentage(self) -> int | None:
        """Return the rounded percentage for a measured dimension.

        Returns:
            Integer percentage, or ``None`` when the dimension is not measured.

        Raises:
            No exceptions are raised.
        """

        if self.total <= 0:
            return None
        return round((self.completed / self.total) * 100)


@dataclass(frozen=True)
class AttentionItem:
    """Represent one actionable programme priority.

    Args:
        label: Human-readable priority text.
        section: Programme Setup section that should be opened.
        severity: Accessible text severity.
        count: Number of affected records.

    Raises:
        No exceptions are raised.
    """

    label: str
    section: str
    severity: str
    count: int = 1


@dataclass(frozen=True)
class ProgramProgressSnapshot:
    """Provide one conservative ISO programme-foundation snapshot.

    Args:
        completed: Number of completed required foundation items.
        total: Total number of required foundation items.
        percentage: Rounded completion percentage.
        readiness: Human-readable readiness state.
        items: Required foundation work items.
        dimensions: Measured and explicitly unmeasured programme dimensions.
        attention: Prioritized incomplete or overdue work.

    Raises:
        No exceptions are raised.
    """

    completed: int
    total: int
    percentage: int
    readiness: str
    items: tuple[ProgressItem, ...]
    dimensions: tuple[ProgressDimension, ...]
    attention: tuple[AttentionItem, ...]


def _coerce_date(value: Any) -> date | None:
    """Convert a repository date value into a date when possible.

    Args:
        value: Date, datetime, ISO date string, or empty value.

    Returns:
        Parsed date or ``None`` when the value cannot be interpreted safely.

    Raises:
        No exceptions are raised.
    """

    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def calculate_program_progress(
    overview: Mapping[str, Any],
    climate_determinations: Sequence[Mapping[str, Any]],
    milestones: Sequence[Mapping[str, Any]],
    *,
    today: date | None = None,
) -> ProgramProgressSnapshot:
    """Calculate programme progress without inferring ISO compliance.

    Only the engagement-scoped foundation created in migration 005 contributes
    to the percentage. Risk, control, evidence, and audit dimensions remain
    explicitly unmeasured until their records are engagement-and-scope scoped.

    Args:
        overview: Workspace overview returned by the GRC repository.
        climate_determinations: Climate relevance versions for the engagement.
        milestones: Engagement milestones visible in the active context.
        today: Optional deterministic date used by tests.

    Returns:
        Immutable progress snapshot with checklist and attention items.

    Raises:
        No exceptions are raised.
    """

    engagement = overview.get("engagement") or {}
    engagement_status = str(engagement.get("status") or "Draft")
    approved_scope = bool(overview.get("approved_scope_version"))
    items = (
        ProgressItem(
            "engagement",
            "Engagement activated",
            engagement_status in {"Planned", "Active", "Completed"},
            "engagement",
            "Confirm the certification cycle and activate its schedule.",
        ),
        ProgressItem(
            "context",
            "Organizational context recorded",
            int(overview.get("context_issues") or 0) > 0,
            "discovery",
            "Review SecureScope context recommendations or add a verified issue.",
        ),
        ProgressItem(
            "climate",
            "Climate relevance determined",
            bool(climate_determinations),
            "context",
            "Record the ISO management-system climate determination.",
        ),
        ProgressItem(
            "parties",
            "Interested parties identified",
            int(overview.get("interested_parties") or 0) > 0,
            "discovery",
            "Review suggested interested parties for this organization.",
        ),
        ProgressItem(
            "requirements",
            "Applicable requirements recorded",
            int(overview.get("applicable_requirements") or 0) > 0,
            "discovery",
            "Confirm applicable requirements while reviewing interested parties.",
        ),
        ProgressItem(
            "scope",
            "ISMS scope approved",
            approved_scope,
            "scope",
            "Complete human review and approve an immutable scope version.",
        ),
        ProgressItem(
            "raci",
            "ISMS responsibilities assigned",
            int(overview.get("role_assignments") or 0) > 0,
            "roles",
            "Assign accountable and responsible workspace members.",
        ),
        ProgressItem(
            "milestones",
            "Programme milestones scheduled",
            bool(milestones),
            "engagement",
            "Schedule at least one audit or programme milestone.",
        ),
    )
    completed = sum(1 for item in items if item.complete)
    total = len(items)
    percentage = round((completed / total) * 100) if total else 0
    if percentage == 100:
        readiness = "Foundation ready for internal review"
    elif percentage >= 60:
        readiness = "Foundation needs attention"
    else:
        readiness = "Setup incomplete"

    attention = [
        AttentionItem(item.action, item.section, "Action required")
        for item in items
        if not item.complete
    ]
    comparison_date = today or date.today()
    overdue_count = sum(
        1
        for milestone in milestones
        if str(milestone.get("status") or "") not in {"Completed", "Cancelled"}
        and (due_date := _coerce_date(milestone.get("due_date"))) is not None
        and due_date < comparison_date
    )
    if overdue_count:
        attention.insert(
            0,
            AttentionItem(
                "Overdue programme milestones require review.",
                "engagement",
                "Overdue",
                count=overdue_count,
            ),
        )

    dimensions = (
        ProgressDimension(
            "foundation",
            "ISMS Foundation",
            completed,
            total,
            "Measured",
            "Programme Setup",
        ),
        ProgressDimension(
            "risk",
            "Risk Management",
            0,
            0,
            "Not measured",
            "Programme Setup",
        ),
        ProgressDimension(
            "controls",
            "Controls & SoA",
            0,
            0,
            "Client register available",
            "Gap Assessment",
        ),
        ProgressDimension(
            "evidence",
            "Evidence",
            0,
            0,
            "Client register available",
            "ISO Evidence Hub",
        ),
        ProgressDimension(
            "audit",
            "Audit Readiness",
            0,
            0,
            "Not measured until audit records exist",
            "Programme Setup",
        ),
    )
    return ProgramProgressSnapshot(
        completed=completed,
        total=total,
        percentage=percentage,
        readiness=readiness,
        items=items,
        dimensions=dimensions,
        attention=tuple(attention),
    )
