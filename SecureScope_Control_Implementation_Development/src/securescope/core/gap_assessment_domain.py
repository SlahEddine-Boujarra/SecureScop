"""Multi-model ISO control assessment rules for SecureScope.

The module separates quantitative coverage, qualitative criteria, process
capability, SLA, effectiveness tests, documentation, risk and composite
assessment models. Automated technical evidence can recommend a conservative
status but cannot declare ISO/IEC 27001 compliance or validate effectiveness.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

ASSESSMENT_MODELS = (
    "quantitative_coverage",
    "checklist",
    "process_capability",
    "timeliness_sla",
    "effectiveness_test",
    "evidence_documentation",
    "risk_based",
    "composite",
)

ASSESSMENT_STATUSES = (
    "Not assessed",
    "Manual assessment required",
    "Insufficient evidence",
    "Not implemented",
    "Gap identified",
    "Partially implemented",
    "Implemented but not verified",
    "Target achieved",
    "Implemented and effective",
    "Accepted residual risk",
    "Not applicable",
)

CRITERION_RESULTS = (
    "Pass",
    "Partial",
    "Fail",
    "Not assessed",
    "Not applicable",
)

TEST_RESULTS = (
    "Successful",
    "Partially successful",
    "Failed",
    "Not tested",
    "Inconclusive",
)

ASSURANCE_DIMENSIONS = (
    "Design adequacy",
    "Implementation",
    "Scope coverage",
    "Operating effectiveness",
    "Evidence assurance",
    "Validation",
)

EVIDENCE_FRESHNESS = ("Current", "Approaching expiration", "Expired", "Unknown")

_USER_ENDPOINT_TYPES = frozenset(
    {
        "desktop",
        "desktop computer",
        "endpoint",
        "laptop",
        "notebook",
        "pc",
        "user endpoint",
        "workstation",
    }
)

_EXCLUDED_ENDPOINT_TYPES = frozenset(
    {
        "firewall",
        "iot",
        "network device",
        "printer",
        "router",
        "server",
        "switch",
        "unknown",
    }
)


class GapAssessmentError(ValueError):
    """Base exception for invalid control assessment data."""


class InvalidCoverageScopeError(GapAssessmentError):
    """Raised when numerator, denominator or target values are invalid."""


class InvalidAssessmentStatusError(GapAssessmentError):
    """Raised when a status violates conservative assurance rules."""


class RiskAcceptanceValidationError(GapAssessmentError):
    """Raised when a risk acceptance is incomplete or invalid."""


@dataclass(frozen=True)
class CoverageResult:
    """Result of one valid population-based coverage measurement.

    Args:
        total_in_scope: Approved denominator.
        covered_in_scope: Validated covered/compliant units.
        target_coverage: Approved target percentage.
        current_coverage: Current percentage, or ``None`` for no population.
        coverage_gap: Remaining percentage points, or ``None`` when unassessed.
        additional_required: Minimum additional covered units required.
        status: Conservative measurement status.

    Returns:
        Immutable coverage result.

    Raises:
        InvalidCoverageScopeError: If the values are internally inconsistent.
    """

    total_in_scope: int
    covered_in_scope: int
    target_coverage: float
    current_coverage: float | None
    coverage_gap: float | None
    additional_required: int | None
    status: str

    def __post_init__(self) -> None:
        """Validate the result fields.

        Returns:
            None.

        Raises:
            InvalidCoverageScopeError: If stored values are inconsistent.
        """

        if self.total_in_scope < 0 or self.covered_in_scope < 0:
            raise InvalidCoverageScopeError("Coverage counts cannot be negative.")
        if self.covered_in_scope > self.total_in_scope:
            raise InvalidCoverageScopeError("covered_in_scope cannot exceed total_in_scope.")
        if not 0 <= self.target_coverage <= 100:
            raise InvalidCoverageScopeError("Target coverage must be from 0 to 100.")


@dataclass(frozen=True)
class CriterionResult:
    """One requirement/checklist criterion assessment.

    Args:
        criterion_id: Stable criterion identifier.
        description: Requirement description.
        required: Whether the criterion is mandatory.
        result: Explicit criterion result.
        evidence_reference: Traceable evidence reference.
        assessor: Person or automation that produced the result.
        validated: Whether an authorized reviewer validated the result.

    Returns:
        Immutable criterion result.

    Raises:
        GapAssessmentError: If the criterion result is unsupported.
    """

    criterion_id: str
    description: str
    required: bool
    result: str
    evidence_reference: str = ""
    assessor: str = ""
    validated: bool = False

    def __post_init__(self) -> None:
        """Validate criterion identity and result.

        Returns:
            None.

        Raises:
            GapAssessmentError: If identifier or result is invalid.
        """

        if not self.criterion_id.strip():
            raise GapAssessmentError("A criterion requires an identifier.")
        if self.result not in CRITERION_RESULTS:
            raise GapAssessmentError(f"Unsupported criterion result: {self.result}")


@dataclass(frozen=True)
class EvidenceRecord:
    """Traceable evidence metadata used by an assessment result.

    Args:
        evidence_id: Stable evidence identifier.
        source: Evidence source or integration.
        collected_at: UTC collection timestamp.
        expires_at: Optional UTC expiration timestamp.
        confidence: Low, Medium or High evidence confidence.
        validated: Whether an authorized reviewer validated the evidence.
        raw_reference: Reference to retained raw evidence.

    Returns:
        Immutable evidence metadata.

    Raises:
        GapAssessmentError: If required metadata is missing.
    """

    evidence_id: str
    source: str
    collected_at: datetime
    expires_at: datetime | None = None
    confidence: str = "Low"
    validated: bool = False
    raw_reference: str = ""

    def __post_init__(self) -> None:
        """Validate evidence metadata.

        Returns:
            None.

        Raises:
            GapAssessmentError: If identity, source or confidence is invalid.
        """

        if not self.evidence_id.strip() or not self.source.strip():
            raise GapAssessmentError("Evidence requires an identifier and source.")
        if self.confidence not in {"Low", "Medium", "High"}:
            raise GapAssessmentError(f"Unsupported evidence confidence: {self.confidence}")

    def freshness(self, now: datetime | None = None, warning_days: int = 30) -> str:
        """Return current evidence freshness.

        Args:
            now: Evaluation timestamp, defaulting to current UTC time.
            warning_days: Days before expiration that trigger a warning.

        Returns:
            Current, Approaching expiration, Expired or Unknown.

        Raises:
            ValueError: If ``warning_days`` is negative.
        """

        if warning_days < 0:
            raise ValueError("warning_days cannot be negative.")
        if self.expires_at is None:
            return "Unknown"
        current = now or datetime.now(timezone.utc)
        current = _as_aware_utc(current)
        expiration = _as_aware_utc(self.expires_at)
        if expiration <= current:
            return "Expired"
        if (expiration - current).days <= warning_days:
            return "Approaching expiration"
        return "Current"


@dataclass(frozen=True)
class RiskAcceptance:
    """Approved residual-risk acceptance decision.

    Args:
        linked_reference: Finding, gap or risk identifier.
        business_justification: Business rationale for acceptance.
        risk_owner: Accountable risk owner.
        approver: Authorized approver.
        approval_date: Formal approval date.
        residual_likelihood: Residual likelihood label or value.
        residual_impact: Residual impact label or value.
        residual_risk_level: Residual risk rating.
        compensating_controls: Existing compensating safeguards.
        evidence_reference: Approval/evidence reference.
        effective_date: Acceptance effective date.
        expiration_date: Mandatory review/expiration date.
        acceptance_scope: Explicit acceptance scope.

    Returns:
        Validated immutable risk acceptance.

    Raises:
        RiskAcceptanceValidationError: If mandatory fields or dates are invalid.
    """

    linked_reference: str
    business_justification: str
    risk_owner: str
    approver: str
    approval_date: date
    residual_likelihood: str
    residual_impact: str
    residual_risk_level: str
    compensating_controls: str
    evidence_reference: str
    effective_date: date
    expiration_date: date
    acceptance_scope: str

    def __post_init__(self) -> None:
        """Validate mandatory approval data and dates.

        Returns:
            None.

        Raises:
            RiskAcceptanceValidationError: If the decision is incomplete.
        """

        mandatory = {
            "linked_reference": self.linked_reference,
            "business_justification": self.business_justification,
            "risk_owner": self.risk_owner,
            "approver": self.approver,
            "residual_likelihood": self.residual_likelihood,
            "residual_impact": self.residual_impact,
            "residual_risk_level": self.residual_risk_level,
            "compensating_controls": self.compensating_controls,
            "evidence_reference": self.evidence_reference,
            "acceptance_scope": self.acceptance_scope,
        }
        missing = [name for name, value in mandatory.items() if not value.strip()]
        if missing:
            raise RiskAcceptanceValidationError("Risk acceptance is missing: " + ", ".join(missing))
        if self.approval_date > self.effective_date:
            raise RiskAcceptanceValidationError("Approval date cannot be after the effective date.")
        if self.expiration_date <= self.effective_date:
            raise RiskAcceptanceValidationError("Expiration date must be after the effective date.")

    def status_on(self, evaluation_date: date | None = None) -> str:
        """Return acceptance status for a date.

        Args:
            evaluation_date: Date to evaluate, defaulting to today.

        Returns:
            Pending, Active or Due for review.

        Raises:
            ValueError: Never raised for a valid date.
        """

        current = evaluation_date or date.today()
        if current < self.effective_date:
            return "Pending"
        if current >= self.expiration_date:
            return "Due for review"
        return "Active"


@dataclass(frozen=True)
class CompositeAssessmentResult:
    """Conservative result across independently assessed sub-objectives.

    Args:
        status: Composite conservative status.
        sub_objective_statuses: Original sub-objective statuses.
        target_achieved: Whether every required sub-objective reached target.
        requires_manual_review: Whether any result requires human assessment.

    Returns:
        Immutable composite result.

    Raises:
        GapAssessmentError: If status values are unsupported.
    """

    status: str
    sub_objective_statuses: tuple[str, ...]
    target_achieved: bool
    requires_manual_review: bool

    def __post_init__(self) -> None:
        """Validate the composite status.

        Returns:
            None.

        Raises:
            GapAssessmentError: If a status is unsupported.
        """

        invalid = [
            item
            for item in (self.status, *self.sub_objective_statuses)
            if item not in ASSESSMENT_STATUSES
        ]
        if invalid:
            raise GapAssessmentError("Unsupported assessment status: " + ", ".join(invalid))


@dataclass(frozen=True)
class SlaAssessmentResult:
    """Result of a representative timeliness or SLA measurement.

    Args:
        sample_size: Number of assessed records in the period.
        items_within_sla: Records completed within the approved SLA.
        items_outside_sla: Records that exceeded the SLA.
        overdue_items: Records still overdue at measurement time.
        target_performance: Approved percentage target.
        current_performance: Observed within-SLA percentage, if assessed.
        remaining_gap: Percentage-point gap, if assessed.
        status: Conservative assessment status.

    Returns:
        Immutable SLA assessment result.

    Raises:
        InvalidCoverageScopeError: If stored sample values are inconsistent.
    """

    sample_size: int
    items_within_sla: int
    items_outside_sla: int
    overdue_items: int
    target_performance: float
    current_performance: float | None
    remaining_gap: float | None
    status: str

    def __post_init__(self) -> None:
        """Validate sample counts and target.

        Returns:
            None.

        Raises:
            InvalidCoverageScopeError: If the result is internally inconsistent.
        """

        if (
            min(
                self.sample_size,
                self.items_within_sla,
                self.items_outside_sla,
                self.overdue_items,
            )
            < 0
        ):
            raise InvalidCoverageScopeError("SLA counts cannot be negative.")
        if self.items_within_sla + self.items_outside_sla != self.sample_size:
            raise InvalidCoverageScopeError(
                "Within-SLA and outside-SLA counts must equal the sample size."
            )
        if not 0 <= self.target_performance <= 100:
            raise InvalidCoverageScopeError("SLA target must be from 0 to 100.")


def _as_aware_utc(value: datetime) -> datetime:
    """Return an aware UTC timestamp.

    Args:
        value: Naive or timezone-aware timestamp.

    Returns:
        UTC-aware timestamp.

    Raises:
        TypeError: If ``value`` is not a datetime.
    """

    if not isinstance(value, datetime):
        raise TypeError("Expected a datetime value.")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def calculate_coverage(
    total_in_scope: int,
    covered_in_scope: int,
    target_coverage: float,
) -> CoverageResult:
    """Calculate a denominator-safe quantitative coverage gap.

    Args:
        total_in_scope: Explicit approved denominator.
        covered_in_scope: Validated covered units.
        target_coverage: Approved target percentage from 0 to 100.

    Returns:
        Coverage result. A zero denominator produces ``Not assessed`` and
        ``None`` values instead of a fabricated 0 percent.

    Raises:
        InvalidCoverageScopeError: If counts or target are invalid.
    """

    if isinstance(total_in_scope, bool) or isinstance(covered_in_scope, bool):
        raise InvalidCoverageScopeError("Coverage counts must be integers.")
    if int(total_in_scope) != total_in_scope or int(covered_in_scope) != covered_in_scope:
        raise InvalidCoverageScopeError("Coverage counts must be whole units.")
    total = int(total_in_scope)
    covered = int(covered_in_scope)
    try:
        target = float(target_coverage)
    except (TypeError, ValueError) as exc:
        raise InvalidCoverageScopeError("Target coverage must be numeric.") from exc
    if total < 0 or covered < 0:
        raise InvalidCoverageScopeError("Coverage counts cannot be negative.")
    if covered > total:
        raise InvalidCoverageScopeError("covered_in_scope cannot exceed total_in_scope.")
    if not 0 <= target <= 100:
        raise InvalidCoverageScopeError("Target coverage must be from 0 to 100.")
    if total == 0:
        return CoverageResult(
            total_in_scope=0,
            covered_in_scope=0,
            target_coverage=target,
            current_coverage=None,
            coverage_gap=None,
            additional_required=None,
            status="Not assessed",
        )
    current = covered / total * 100
    gap = max(0.0, target - current)
    additional = max(0, math.ceil(total * target / 100) - covered)
    return CoverageResult(
        total_in_scope=total,
        covered_in_scope=covered,
        target_coverage=target,
        current_coverage=round(current, 2),
        coverage_gap=round(gap, 2),
        additional_required=additional,
        status="Target achieved" if gap == 0 else "Gap identified",
    )


def endpoint_in_a81_scope(asset: Mapping[str, Any]) -> bool:
    """Return whether an asset belongs to approved A.8.1 user-endpoint scope.

    Args:
        asset: SecureScope asset mapping.

    Returns:
        True only for explicitly included or recognized user endpoint devices.

    Raises:
        ValueError: Never raised for mapping values.
    """

    explicit_scope = asset.get("a81_endpoint_in_scope")
    if explicit_scope is not None:
        return bool(explicit_scope)
    general_scope = asset.get("in_scope")
    if general_scope is False:
        return False
    device_type = (
        str(asset.get("device_type") or asset.get("asset_type") or "unknown").strip().lower()
    )
    if device_type in _EXCLUDED_ENDPOINT_TYPES:
        return False
    return device_type in _USER_ENDPOINT_TYPES


def a81_wazuh_endpoint_coverage(
    assets: Iterable[Mapping[str, Any]],
    wazuh_rows: Iterable[Mapping[str, Any]],
    target_coverage: float,
) -> CoverageResult:
    """Calculate Wazuh coverage using endpoint-only A.8.1 scope.

    Args:
        assets: Workspace asset inventory.
        wazuh_rows: Latest workspace Wazuh matching rows.
        target_coverage: Approved endpoint monitoring target percentage.

    Returns:
        Endpoint-only coverage result.

    Raises:
        InvalidCoverageScopeError: If the target is invalid.
    """

    endpoints = [asset for asset in assets if endpoint_in_a81_scope(asset)]
    active_identities: set[str] = set()
    for row in wazuh_rows:
        from securescope.integrations.wazuh_monitoring import evaluate_monitoring

        if evaluate_monitoring(dict(row))["monitoring_state"] != "verified":
            continue
        identity = (
            str(row.get("asset_tag") or row.get("asset_ip") or row.get("ip") or "").strip().lower()
        )
        if identity:
            active_identities.add(identity)
    covered = 0
    for asset in endpoints:
        identities = {
            str(asset.get("asset_tag") or "").strip().lower(),
            str(asset.get("ip") or asset.get("asset_ip") or "").strip().lower(),
        }
        if any(identity and identity in active_identities for identity in identities):
            covered += 1
    return calculate_coverage(len(endpoints), covered, target_coverage)


def evaluate_checklist(criteria: Sequence[CriterionResult]) -> str:
    """Evaluate explicit checklist criteria without inventing a percentage.

    Args:
        criteria: Criterion-level results.

    Returns:
        Conservative assessment status.

    Raises:
        GapAssessmentError: If no criteria are supplied.
    """

    if not criteria:
        raise GapAssessmentError("Checklist assessment requires criteria.")
    required = [criterion for criterion in criteria if criterion.required]
    if not required:
        return "Manual assessment required"
    results = {criterion.result for criterion in required}
    if "Not assessed" in results:
        return "Manual assessment required"
    if "Fail" in results:
        return "Gap identified"
    if "Partial" in results:
        return "Partially implemented"
    if all(criterion.result in {"Pass", "Not applicable"} for criterion in required):
        if all(
            criterion.validated or criterion.result == "Not applicable" for criterion in required
        ):
            return "Target achieved"
        return "Implemented but not verified"
    return "Insufficient evidence"


def evaluate_process_capability(
    capabilities: Mapping[str, bool | None],
    *,
    authorized_validation: bool = False,
) -> str:
    """Assess explicit process capabilities without deriving a CMMI level.

    Args:
        capabilities: Named evidence criteria such as defined, owned, performed,
            monitored, reviewed and improved. ``None`` means insufficient evidence.
        authorized_validation: Whether an authorized reviewer validated all criteria.

    Returns:
        Conservative process assessment status.

    Raises:
        GapAssessmentError: If no explicit capability criteria are supplied.
    """

    if not capabilities:
        raise GapAssessmentError("Process assessment requires capability criteria.")
    values = list(capabilities.values())
    if any(value is False for value in values):
        return "Gap identified"
    if any(value is None for value in values):
        return "Insufficient evidence"
    return "Target achieved" if authorized_validation else "Implemented but not verified"


def evaluate_sla(
    sample_size: int,
    items_within_sla: int,
    overdue_items: int,
    target_performance: float,
) -> SlaAssessmentResult:
    """Evaluate SLA performance across an explicit measurement sample.

    Args:
        sample_size: Representative records assessed in the period.
        items_within_sla: Sample records completed within SLA.
        overdue_items: Records currently overdue; cannot exceed outside-SLA items.
        target_performance: Approved within-SLA target percentage.

    Returns:
        Denominator-safe SLA assessment result.

    Raises:
        InvalidCoverageScopeError: If counts or target are invalid.
    """

    if any(isinstance(value, bool) for value in (sample_size, items_within_sla, overdue_items)):
        raise InvalidCoverageScopeError("SLA counts must be integers.")
    if any(int(value) != value for value in (sample_size, items_within_sla, overdue_items)):
        raise InvalidCoverageScopeError("SLA counts must be whole units.")
    sample = int(sample_size)
    within = int(items_within_sla)
    overdue = int(overdue_items)
    try:
        target = float(target_performance)
    except (TypeError, ValueError) as exc:
        raise InvalidCoverageScopeError("SLA target must be numeric.") from exc
    if sample < 0 or within < 0 or within > sample:
        raise InvalidCoverageScopeError("SLA sample counts are invalid.")
    outside = sample - within
    if overdue < 0 or overdue > outside:
        raise InvalidCoverageScopeError("Overdue items cannot exceed records outside SLA.")
    if not 0 <= target <= 100:
        raise InvalidCoverageScopeError("SLA target must be from 0 to 100.")
    if sample == 0:
        return SlaAssessmentResult(
            sample_size=0,
            items_within_sla=0,
            items_outside_sla=0,
            overdue_items=0,
            target_performance=target,
            current_performance=None,
            remaining_gap=None,
            status="Not assessed",
        )
    current = within / sample * 100
    gap = max(0.0, target - current)
    return SlaAssessmentResult(
        sample_size=sample,
        items_within_sla=within,
        items_outside_sla=outside,
        overdue_items=overdue,
        target_performance=target,
        current_performance=round(current, 2),
        remaining_gap=round(gap, 2),
        status="Target achieved" if gap == 0 else "Gap identified",
    )


def evaluate_effectiveness_test(result: str, *, validated: bool = False) -> str:
    """Convert one explicit effectiveness test result to a cautious status.

    Args:
        result: Successful, partially successful, failed, not tested or inconclusive.
        validated: Whether an authorized reviewer validated the test result.

    Returns:
        Conservative control assessment status.

    Raises:
        GapAssessmentError: If the test result is unsupported.
    """

    if result not in TEST_RESULTS:
        raise GapAssessmentError(f"Unsupported effectiveness result: {result}")
    if result == "Successful":
        return "Target achieved" if validated else "Implemented but not verified"
    if result == "Partially successful":
        return "Partially implemented"
    if result == "Failed":
        return "Gap identified"
    if result == "Not tested":
        return "Manual assessment required"
    return "Insufficient evidence"


def validate_assessment_status(
    status: str,
    *,
    automated: bool,
    effectiveness_evidence: bool = False,
    authorized_validation: bool = False,
    not_applicable_approved: bool = False,
    risk_acceptance_approved: bool = False,
) -> None:
    """Enforce conservative ISO assessment status rules.

    Args:
        status: Requested assessment status.
        automated: Whether the conclusion is produced only by automation.
        effectiveness_evidence: Whether effectiveness evidence is sufficient.
        authorized_validation: Whether an authorized reviewer validated it.
        not_applicable_approved: Whether Not Applicable is justified/approved.
        risk_acceptance_approved: Whether residual-risk acceptance is valid.

    Returns:
        None when the status is permitted.

    Raises:
        InvalidAssessmentStatusError: If the conclusion violates assurance rules.
    """

    if status not in ASSESSMENT_STATUSES:
        raise InvalidAssessmentStatusError(f"Unsupported assessment status: {status}")
    if automated and status in {
        "Implemented and effective",
        "Accepted residual risk",
        "Not applicable",
    }:
        raise InvalidAssessmentStatusError(f"Automated evidence cannot assign status: {status}")
    if status == "Implemented and effective" and not (
        effectiveness_evidence and authorized_validation
    ):
        raise InvalidAssessmentStatusError(
            "Implemented and effective requires effectiveness evidence and authorized validation."
        )
    if status == "Not applicable" and not not_applicable_approved:
        raise InvalidAssessmentStatusError(
            "Not applicable requires documented justification and approval."
        )
    if status == "Accepted residual risk" and not risk_acceptance_approved:
        raise InvalidAssessmentStatusError(
            "Accepted residual risk requires an approved, non-expired decision."
        )


def evaluate_composite_control(
    sub_objective_statuses: Sequence[str],
) -> CompositeAssessmentResult:
    """Evaluate a composite control from independent sub-objectives.

    Args:
        sub_objective_statuses: Conservative status for each sub-objective.

    Returns:
        Composite result that never hides an unassessed or failed objective.

    Raises:
        GapAssessmentError: If no objectives or invalid statuses are supplied.
    """

    if not sub_objective_statuses:
        raise GapAssessmentError("Composite control requires sub-objectives.")
    invalid = [status for status in sub_objective_statuses if status not in ASSESSMENT_STATUSES]
    if invalid:
        raise GapAssessmentError("Unsupported sub-objective status: " + ", ".join(invalid))
    statuses = tuple(sub_objective_statuses)
    if "Not implemented" in statuses or "Gap identified" in statuses:
        status = "Gap identified"
    elif "Partially implemented" in statuses:
        status = "Partially implemented"
    elif any(item in {"Not assessed", "Manual assessment required"} for item in statuses):
        status = "Manual assessment required"
    elif "Insufficient evidence" in statuses:
        status = "Insufficient evidence"
    elif "Implemented but not verified" in statuses:
        status = "Implemented but not verified"
    elif all(
        item in {"Target achieved", "Implemented and effective", "Not applicable"}
        for item in statuses
    ):
        status = (
            "Implemented and effective"
            if all(item in {"Implemented and effective", "Not applicable"} for item in statuses)
            else "Target achieved"
        )
    else:
        status = "Insufficient evidence"
    requires_manual = any(
        item
        in {
            "Not assessed",
            "Manual assessment required",
            "Insufficient evidence",
            "Implemented but not verified",
        }
        for item in statuses
    )
    target_achieved = all(
        item in {"Target achieved", "Implemented and effective", "Not applicable"}
        for item in statuses
    )
    return CompositeAssessmentResult(
        status=status,
        sub_objective_statuses=statuses,
        target_achieved=target_achieved,
        requires_manual_review=requires_manual,
    )


def assurance_score(
    dimension_scores: Mapping[str, float | None],
) -> dict[str, Any]:
    """Calculate a transparent Assurance Score across six visible dimensions.

    Args:
        dimension_scores: Mapping of dimension names to 0–100 values or None.

    Returns:
        Score, included/missing dimensions and the explicit equal-weight formula.

    Raises:
        GapAssessmentError: If a dimension name or numeric value is invalid.
    """

    unknown = set(dimension_scores) - set(ASSURANCE_DIMENSIONS)
    if unknown:
        raise GapAssessmentError("Unknown assurance dimension: " + ", ".join(sorted(unknown)))
    included: dict[str, float] = {}
    missing: list[str] = []
    for dimension in ASSURANCE_DIMENSIONS:
        value = dimension_scores.get(dimension)
        if value is None:
            missing.append(dimension)
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise GapAssessmentError(f"Assurance dimension must be numeric: {dimension}") from exc
        if not 0 <= numeric <= 100:
            raise GapAssessmentError(f"Assurance dimension must be from 0 to 100: {dimension}")
        included[dimension] = numeric
    score = round(sum(included.values()) / len(included), 2) if included else None
    return {
        "assurance_score": score,
        "included_dimensions": included,
        "missing_dimensions": missing,
        "formula": "sum(included dimension values) / number of included dimensions",
        "is_complete": not missing,
    }
