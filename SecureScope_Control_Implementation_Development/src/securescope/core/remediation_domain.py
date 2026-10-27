"""Validation models for vulnerability remediation plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from securescope.core.finding_domain import TREATMENT_DECISIONS

PLAN_PRIORITIES = ("Critical", "High", "Medium", "Low")
PLAN_STATUSES = (
    "Draft",
    "Approved",
    "In progress",
    "Blocked",
    "Ready for verification",
    "Completed",
    "Cancelled",
)


class RemediationValidationError(ValueError):
    """Raised when a remediation record lacks mandatory management fields."""


@dataclass(frozen=True)
class RemediationPlanInput:
    """Validated fields required to create a remediation plan.

    Args:
        title: Concise remediation plan title.
        description: Affected weakness and intended change.
        priority: Critical, High, Medium or Low.
        treatment_decision: Remediate, Mitigate, Accept, Avoid or False positive.
        remediation_owner: Accountable remediation owner.
        technical_owner: Technical implementation owner.
        business_owner: Affected business owner.
        risk_owner: Accountable risk owner.
        due_date: Approved completion due date.
        sla_days: Positive remediation SLA in days.
        success_criteria: Observable definition of success.
        validation_method: Re-scan, test or analyst validation method.
        start_date: Optional planned start date.
        required_resources: Required people, budget or tools.
        dependencies: Blocking dependencies.
        implementation_steps: Planned technical/organizational steps.
        compensating_controls: Interim safeguards.
        expected_risk_reduction: Expected residual risk change.

    Returns:
        Immutable validated plan input.

    Raises:
        RemediationValidationError: If mandatory fields, dates or choices are invalid.
    """

    title: str
    description: str
    priority: str
    treatment_decision: str
    remediation_owner: str
    technical_owner: str
    business_owner: str
    risk_owner: str
    due_date: date
    sla_days: int
    success_criteria: str
    validation_method: str
    start_date: date | None = None
    required_resources: str = ""
    dependencies: str = ""
    implementation_steps: str = ""
    compensating_controls: str = ""
    expected_risk_reduction: str = ""

    def __post_init__(self) -> None:
        """Validate mandatory fields and plan dates.

        Returns:
            None.

        Raises:
            RemediationValidationError: If the plan cannot be safely persisted.
        """

        mandatory = {
            "title": self.title,
            "description": self.description,
            "remediation_owner": self.remediation_owner,
            "technical_owner": self.technical_owner,
            "business_owner": self.business_owner,
            "risk_owner": self.risk_owner,
            "success_criteria": self.success_criteria,
            "validation_method": self.validation_method,
        }
        missing = [name for name, value in mandatory.items() if not value.strip()]
        if missing:
            raise RemediationValidationError("Remediation plan is missing: " + ", ".join(missing))
        if self.priority not in PLAN_PRIORITIES:
            raise RemediationValidationError(f"Unsupported remediation priority: {self.priority}")
        if self.treatment_decision not in TREATMENT_DECISIONS:
            raise RemediationValidationError(
                f"Unsupported treatment decision: {self.treatment_decision}"
            )
        if isinstance(self.sla_days, bool) or self.sla_days <= 0:
            raise RemediationValidationError("Remediation SLA must be positive.")
        if self.start_date and self.due_date < self.start_date:
            raise RemediationValidationError(
                "Remediation due date cannot be before its start date."
            )
