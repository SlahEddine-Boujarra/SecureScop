"""Validated domain inputs for engagement, context and ISMS scope records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Iterable

ENGAGEMENT_TYPES = (
    "ISO 27001 implementation",
    "Initial gap assessment",
    "Stage 1 readiness",
    "Stage 2 readiness",
    "Internal audit",
    "Surveillance audit",
    "Recertification",
    "Continuous vCISO",
    "Other",
)
ENGAGEMENT_STATUSES = (
    "Draft",
    "Planned",
    "Active",
    "On hold",
    "Completed",
    "Cancelled",
)
ISSUE_TYPES = ("Internal", "External")
RELEVANCE_VALUES = ("Relevant", "Not relevant", "Under review")
PARTY_TYPES = (
    "Customer",
    "Employee",
    "Regulator",
    "Supplier",
    "Partner",
    "Shareholder",
    "Certification body",
    "Public authority",
    "Other",
)
REQUIREMENT_TYPES = (
    "Legal",
    "Regulatory",
    "Contractual",
    "Stakeholder",
    "Internal",
)
UNIT_TYPES = ("Legal entity", "Site", "Business unit", "Department", "Team")
RACI_TYPES = ("Responsible", "Accountable", "Consulted", "Informed")
ENGAGEMENT_ROLES = (
    "Engagement lead",
    "Consultant",
    "Independent reviewer",
    "Client sponsor",
    "ISMS manager",
    "Control owner",
    "Auditor",
    "Contributor",
)
MILESTONE_TYPES = (
    "Workshop",
    "Scope approval",
    "Risk assessment",
    "Internal audit",
    "Management review",
    "Stage 1",
    "Stage 2",
    "Surveillance",
    "Deliverable",
    "Other",
)


class GrcValidationError(ValueError):
    """Raised when a GRC domain record violates a business rule."""


def required_text(value: Any, field_name: str, *, max_length: int = 4_000) -> str:
    """Normalize and validate one required text value.

    Args:
        value: Candidate value supplied by the UI or API.
        field_name: Human-readable field label for validation errors.
        max_length: Maximum accepted character count.

    Returns:
        Stripped non-empty text.

    Raises:
        GrcValidationError: If the value is empty or exceeds ``max_length``.
    """

    text = str(value or "").strip()
    if not text:
        raise GrcValidationError(f"{field_name} is required.")
    if len(text) > max_length:
        raise GrcValidationError(f"{field_name} cannot exceed {max_length} characters.")
    return text


def optional_text(value: Any, *, max_length: int = 4_000) -> str:
    """Normalize and validate one optional text value.

    Args:
        value: Candidate value supplied by the UI or API.
        max_length: Maximum accepted character count.

    Returns:
        Stripped text, which may be empty.

    Raises:
        GrcValidationError: If the value exceeds ``max_length``.
    """

    text = str(value or "").strip()
    if len(text) > max_length:
        raise GrcValidationError(f"Text cannot exceed {max_length} characters.")
    return text


def choice(value: Any, field_name: str, allowed: Iterable[str]) -> str:
    """Validate a value against an explicit business vocabulary.

    Args:
        value: Candidate value.
        field_name: Human-readable field label.
        allowed: Exact accepted values.

    Returns:
        The validated value.

    Raises:
        GrcValidationError: If the value is not allowlisted.
    """

    resolved = str(value or "").strip()
    allowed_values = tuple(allowed)
    if resolved not in allowed_values:
        raise GrcValidationError(f"Unsupported {field_name}: {resolved or 'empty value'}.")
    return resolved


def clean_text_list(values: Iterable[Any] | None) -> tuple[str, ...]:
    """Return a stable, duplicate-free list of non-empty text values.

    Args:
        values: Optional iterable supplied by a form or API payload.

    Returns:
        Ordered tuple with duplicates and blank values removed.

    Raises:
        GrcValidationError: If more than 250 values are supplied.
    """

    result: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        text = optional_text(value, max_length=500)
        if not text or text.casefold() in seen:
            continue
        seen.add(text.casefold())
        result.append(text)
    if len(result) > 250:
        raise GrcValidationError("A scope list cannot contain more than 250 items.")
    return tuple(result)


def normalize_reference(value: Any) -> str:
    """Normalize a human engagement or scope reference.

    Args:
        value: Candidate reference.

    Returns:
        Uppercase reference using letters, numbers, dots, slashes and dashes.

    Raises:
        GrcValidationError: If no usable characters remain.
    """

    text = required_text(value, "Reference", max_length=80).upper()
    normalized = re.sub(r"\s+", "-", text)
    normalized = re.sub(r"[^A-Z0-9._/-]", "", normalized).strip("-./")
    if not normalized:
        raise GrcValidationError("Reference must contain letters or numbers.")
    return normalized


@dataclass(frozen=True)
class EngagementDraft:
    """Validated input used to create a certification engagement.

    Args:
        reference: Client-unique engagement reference.
        name: Human-readable engagement name.
        engagement_type: Allowlisted consulting engagement type.
        objective: Intended outcome and contractual purpose.
        status: Initial lifecycle status.
        target_standard: Framework or standard targeted by the engagement.
        cycle_year: Optional certification or service year.
        planned_start_date: Optional planned start.
        planned_end_date: Optional planned completion.
        certification_target_date: Optional external audit target date.
        client_sponsor: Optional client sponsor name.

    Raises:
        GrcValidationError: If required values, dates or vocabularies are invalid.
    """

    reference: str
    name: str
    engagement_type: str
    objective: str
    status: str = "Draft"
    target_standard: str = "ISO/IEC 27001:2022"
    cycle_year: int | None = None
    planned_start_date: date | None = None
    planned_end_date: date | None = None
    certification_target_date: date | None = None
    client_sponsor: str = ""

    def validate(self) -> "EngagementDraft":
        """Return a normalized engagement draft.

        Returns:
            New immutable validated draft.

        Raises:
            GrcValidationError: If a business rule is violated.
        """

        if (
            self.planned_start_date
            and self.planned_end_date
            and self.planned_end_date < self.planned_start_date
        ):
            raise GrcValidationError("Planned end date cannot be before the planned start date.")
        if self.cycle_year is not None and not 2000 <= int(self.cycle_year) <= 2200:
            raise GrcValidationError("Cycle year must be between 2000 and 2200.")
        return EngagementDraft(
            reference=normalize_reference(self.reference),
            name=required_text(self.name, "Engagement name", max_length=250),
            engagement_type=choice(
                self.engagement_type,
                "engagement type",
                ENGAGEMENT_TYPES,
            ),
            objective=required_text(self.objective, "Objective"),
            status=choice(self.status, "engagement status", ENGAGEMENT_STATUSES),
            target_standard=required_text(
                self.target_standard,
                "Target standard",
                max_length=150,
            ),
            cycle_year=int(self.cycle_year) if self.cycle_year is not None else None,
            planned_start_date=self.planned_start_date,
            planned_end_date=self.planned_end_date,
            certification_target_date=self.certification_target_date,
            client_sponsor=optional_text(self.client_sponsor, max_length=250),
        )


@dataclass(frozen=True)
class ScopeDraft:
    """Validated input for a new immutable ISMS scope version.

    Args:
        scope_code: Stable code of the scope definition.
        name: Scope display name.
        scope_statement: Formal scope statement.
        boundaries: Organizational and technical boundaries.
        exclusions: Explained scope exclusions.
        interfaces_and_dependencies: Important internal/external interfaces.
        locations: Sites included in the version.
        organizational_units: Departments or entities included in the version.
        products_and_services: Products and services covered by the ISMS.
        technologies: Important technology boundaries.
        assumptions: Assumptions requiring later validation.
        effective_from: Optional effective date.
        effective_to: Optional end date.

    Raises:
        GrcValidationError: If required text, lists or dates are invalid.
    """

    scope_code: str
    name: str
    scope_statement: str
    boundaries: str = ""
    exclusions: str = ""
    interfaces_and_dependencies: str = ""
    locations: tuple[str, ...] = field(default_factory=tuple)
    organizational_units: tuple[str, ...] = field(default_factory=tuple)
    products_and_services: tuple[str, ...] = field(default_factory=tuple)
    technologies: tuple[str, ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    effective_from: date | None = None
    effective_to: date | None = None

    def validate(self) -> "ScopeDraft":
        """Return a normalized scope draft.

        Returns:
            New immutable validated draft.

        Raises:
            GrcValidationError: If a scope rule is violated.
        """

        if self.effective_from and self.effective_to and self.effective_to < self.effective_from:
            raise GrcValidationError("Scope effective-to date cannot precede effective-from date.")
        return ScopeDraft(
            scope_code=normalize_reference(self.scope_code),
            name=required_text(self.name, "Scope name", max_length=250),
            scope_statement=required_text(
                self.scope_statement,
                "Scope statement",
                max_length=10_000,
            ),
            boundaries=optional_text(self.boundaries, max_length=10_000),
            exclusions=optional_text(self.exclusions, max_length=10_000),
            interfaces_and_dependencies=optional_text(
                self.interfaces_and_dependencies,
                max_length=10_000,
            ),
            locations=clean_text_list(self.locations),
            organizational_units=clean_text_list(self.organizational_units),
            products_and_services=clean_text_list(self.products_and_services),
            technologies=clean_text_list(self.technologies),
            assumptions=clean_text_list(self.assumptions),
            effective_from=self.effective_from,
            effective_to=self.effective_to,
        )


@dataclass(frozen=True)
class ContextIssueDraft:
    """Validated internal or external issue affecting an engagement."""

    issue_type: str
    category: str
    title: str
    description: str
    effect_on_isms: str
    relevance: str
    owner: str
    review_date: date | None = None

    def validate(self) -> "ContextIssueDraft":
        """Return a normalized context issue.

        Returns:
            New immutable validated issue.

        Raises:
            GrcValidationError: If required fields or vocabularies are invalid.
        """

        return ContextIssueDraft(
            issue_type=choice(self.issue_type, "issue type", ISSUE_TYPES),
            category=required_text(self.category, "Issue category", max_length=120),
            title=required_text(self.title, "Issue title", max_length=250),
            description=required_text(self.description, "Issue description"),
            effect_on_isms=required_text(self.effect_on_isms, "Effect on the ISMS"),
            relevance=choice(self.relevance, "relevance", RELEVANCE_VALUES),
            owner=required_text(self.owner, "Issue owner", max_length=250),
            review_date=self.review_date,
        )


@dataclass(frozen=True)
class ClimateDeterminationDraft:
    """Validated ISO management-system climate relevance determination."""

    determination: str
    rationale: str
    identified_impacts: str
    determined_by: str
    determination_date: date
    next_review_date: date | None = None

    def validate(self) -> "ClimateDeterminationDraft":
        """Return a normalized climate determination.

        Returns:
            New immutable validated determination.

        Raises:
            GrcValidationError: If the determination or dates are invalid.
        """

        if self.next_review_date and self.next_review_date < self.determination_date:
            raise GrcValidationError(
                "Climate next-review date cannot precede the determination date."
            )
        return ClimateDeterminationDraft(
            determination=choice(
                self.determination,
                "climate determination",
                RELEVANCE_VALUES,
            ),
            rationale=required_text(self.rationale, "Climate rationale"),
            identified_impacts=optional_text(self.identified_impacts),
            determined_by=required_text(
                self.determined_by,
                "Determined by",
                max_length=250,
            ),
            determination_date=self.determination_date,
            next_review_date=self.next_review_date,
        )


@dataclass(frozen=True)
class InterestedPartyDraft:
    """Validated interested-party register entry."""

    name: str
    party_type: str
    relationship_description: str
    needs_and_expectations: str
    communication_method: str
    owner: str

    def validate(self) -> "InterestedPartyDraft":
        """Return a normalized interested-party entry.

        Returns:
            New immutable validated party.

        Raises:
            GrcValidationError: If required text or the party type is invalid.
        """

        return InterestedPartyDraft(
            name=required_text(self.name, "Interested party name", max_length=250),
            party_type=choice(self.party_type, "party type", PARTY_TYPES),
            relationship_description=optional_text(self.relationship_description),
            needs_and_expectations=required_text(
                self.needs_and_expectations,
                "Needs and expectations",
            ),
            communication_method=optional_text(
                self.communication_method,
                max_length=1_000,
            ),
            owner=required_text(self.owner, "Interested party owner", max_length=250),
        )


@dataclass(frozen=True)
class PartyRequirementDraft:
    """Validated requirement attached to an interested party."""

    requirement_type: str
    requirement: str
    source_reference: str
    applicability: str
    mandatory: bool
    owner: str
    review_date: date | None = None

    def validate(self) -> "PartyRequirementDraft":
        """Return a normalized interested-party requirement.

        Returns:
            New immutable validated requirement.

        Raises:
            GrcValidationError: If required text or a vocabulary is invalid.
        """

        return PartyRequirementDraft(
            requirement_type=choice(
                self.requirement_type,
                "requirement type",
                REQUIREMENT_TYPES,
            ),
            requirement=required_text(self.requirement, "Requirement"),
            source_reference=optional_text(self.source_reference, max_length=500),
            applicability=choice(
                self.applicability,
                "applicability",
                ("Applicable", "Not applicable", "Under review"),
            ),
            mandatory=bool(self.mandatory),
            owner=required_text(self.owner, "Requirement owner", max_length=250),
            review_date=self.review_date,
        )


@dataclass(frozen=True)
class OrganizationalUnitDraft:
    """Validated site, department or organization unit."""

    unit_type: str
    name: str
    description: str
    address: str
    in_scope: bool
    owner: str
    parent_unit_id: int | None = None

    def validate(self) -> "OrganizationalUnitDraft":
        """Return a normalized organizational unit.

        Returns:
            New immutable validated unit.

        Raises:
            GrcValidationError: If required text or the unit type is invalid.
        """

        if self.parent_unit_id is not None and int(self.parent_unit_id) <= 0:
            raise GrcValidationError("Parent unit ID must be positive.")
        return OrganizationalUnitDraft(
            unit_type=choice(self.unit_type, "unit type", UNIT_TYPES),
            name=required_text(self.name, "Unit name", max_length=250),
            description=optional_text(self.description),
            address=optional_text(self.address, max_length=1_000),
            in_scope=bool(self.in_scope),
            owner=optional_text(self.owner, max_length=250),
            parent_unit_id=(int(self.parent_unit_id) if self.parent_unit_id is not None else None),
        )


@dataclass(frozen=True)
class MilestoneDraft:
    """Validated milestone for an engagement or certification cycle."""

    title: str
    milestone_type: str
    description: str
    due_date: date
    acceptance_criteria: str
    owner_user_id: int | None = None

    def validate(self) -> "MilestoneDraft":
        """Return a normalized engagement milestone.

        Returns:
            New immutable validated milestone.

        Raises:
            GrcValidationError: If required text or owner identity is invalid.
        """

        if self.owner_user_id is not None and int(self.owner_user_id) <= 0:
            raise GrcValidationError("Milestone owner user ID must be positive.")
        return MilestoneDraft(
            title=required_text(self.title, "Milestone title", max_length=250),
            milestone_type=choice(
                self.milestone_type,
                "milestone type",
                MILESTONE_TYPES,
            ),
            description=optional_text(self.description),
            due_date=self.due_date,
            acceptance_criteria=optional_text(self.acceptance_criteria),
            owner_user_id=(int(self.owner_user_id) if self.owner_user_id is not None else None),
        )


@dataclass(frozen=True)
class RaciAssignmentDraft:
    """Validated user-backed ISMS responsibility assignment."""

    user_id: int
    role_name: str
    responsibility: str
    raci_type: str
    authority: str
    effective_from: date
    effective_to: date | None = None

    def validate(self) -> "RaciAssignmentDraft":
        """Return a normalized RACI assignment.

        Returns:
            New immutable validated assignment.

        Raises:
            GrcValidationError: If identity, dates or required text are invalid.
        """

        if int(self.user_id) <= 0:
            raise GrcValidationError("RACI user ID must be positive.")
        if self.effective_to and self.effective_to < self.effective_from:
            raise GrcValidationError("RACI effective-to date cannot precede effective-from date.")
        return RaciAssignmentDraft(
            user_id=int(self.user_id),
            role_name=required_text(self.role_name, "ISMS role", max_length=250),
            responsibility=required_text(self.responsibility, "Responsibility"),
            raci_type=choice(self.raci_type, "RACI type", RACI_TYPES),
            authority=optional_text(self.authority),
            effective_from=self.effective_from,
            effective_to=self.effective_to,
        )
