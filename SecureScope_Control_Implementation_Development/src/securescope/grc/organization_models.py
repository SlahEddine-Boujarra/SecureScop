"""Validated organization-knowledge inputs for SecureScope programme discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from securescope.grc.engagement_models import (
    GrcValidationError,
    clean_text_list,
    optional_text,
    required_text,
)

EMPLOYEE_BANDS = (
    "Unknown",
    "1-10",
    "11-25",
    "26-50",
    "51-100",
    "101-250",
    "251-500",
    "501+",
)
INFRASTRUCTURE_MODELS = (
    "Unknown",
    "Cloud",
    "On-premises",
    "Hybrid",
    "Mostly SaaS",
)
PROFILE_STATUSES = ("Draft", "Confirmed")
FACT_SOURCE_TYPES = (
    "Guided discovery",
    "Document",
    "Import",
    "Technical discovery",
    "Integration",
    "Manual",
    "AI proposal",
)
FACT_STATUSES = ("Proposed", "Confirmed", "Rejected", "Superseded")


def _choice(value: Any, field_name: str, allowed: Iterable[str]) -> str:
    """Validate one organization-knowledge vocabulary value.

    Args:
        value: Candidate value.
        field_name: Human-readable field name.
        allowed: Accepted exact values.

    Returns:
        Validated text.

    Raises:
        GrcValidationError: If the candidate is outside the allowed vocabulary.
    """

    resolved = str(value or "").strip()
    choices = tuple(allowed)
    if resolved not in choices:
        raise GrcValidationError(f"Unsupported {field_name}: {resolved or 'empty value'}.")
    return resolved


@dataclass(frozen=True)
class OrganizationProfileDraft:
    """Validated quick profile used to seed the organization knowledge layer.

    Args:
        industry: Plain-language industry or business sector.
        main_activity: Short description of what the organization does.
        employee_band: Approximate employee-count range.
        infrastructure_model: High-level infrastructure operating model.
        locations: Known operating locations.
        departments: Known organizational units or teams.
        products_and_services: Products/services relevant to the programme.
        technologies: Important technology platforms and providers.
        customer_markets: Customer or operating markets.
        certification_drivers: Reasons the organization is pursuing ISO 27001.
        profile_status: Draft or Confirmed.

    Raises:
        GrcValidationError: If required values or vocabularies are invalid.
    """

    industry: str
    main_activity: str
    employee_band: str = "Unknown"
    infrastructure_model: str = "Unknown"
    locations: tuple[str, ...] = field(default_factory=tuple)
    departments: tuple[str, ...] = field(default_factory=tuple)
    products_and_services: tuple[str, ...] = field(default_factory=tuple)
    technologies: tuple[str, ...] = field(default_factory=tuple)
    customer_markets: tuple[str, ...] = field(default_factory=tuple)
    certification_drivers: tuple[str, ...] = field(default_factory=tuple)
    profile_status: str = "Confirmed"

    def validate(self) -> "OrganizationProfileDraft":
        """Return a normalized immutable organization profile.

        Returns:
            Validated profile draft.

        Raises:
            GrcValidationError: If required values or list sizes are invalid.
        """

        return OrganizationProfileDraft(
            industry=required_text(self.industry, "Industry", max_length=180),
            main_activity=required_text(
                self.main_activity,
                "Main activity",
                max_length=1_500,
            ),
            employee_band=_choice(
                self.employee_band,
                "employee band",
                EMPLOYEE_BANDS,
            ),
            infrastructure_model=_choice(
                self.infrastructure_model,
                "infrastructure model",
                INFRASTRUCTURE_MODELS,
            ),
            locations=clean_text_list(self.locations),
            departments=clean_text_list(self.departments),
            products_and_services=clean_text_list(self.products_and_services),
            technologies=clean_text_list(self.technologies),
            customer_markets=clean_text_list(self.customer_markets),
            certification_drivers=clean_text_list(self.certification_drivers),
            profile_status=_choice(
                self.profile_status,
                "profile status",
                PROFILE_STATUSES,
            ),
        )


@dataclass(frozen=True)
class OrganizationFactDraft:
    """Validated single fact with provenance and review state.

    Args:
        fact_type: Stable category such as ``technology`` or ``location``.
        fact_key: Stable key used for deterministic deduplication.
        value_text: Human-readable fact value.
        source_type: Origin of the fact.
        source_reference: Optional source document/integration reference.
        confidence: Confidence from 0.0 to 1.0.
        status: Review state.

    Raises:
        GrcValidationError: If fields, source type, status or confidence are invalid.
    """

    fact_type: str
    fact_key: str
    value_text: str
    source_type: str
    source_reference: str = ""
    confidence: float = 1.0
    status: str = "Confirmed"

    def validate(self) -> "OrganizationFactDraft":
        """Return a normalized immutable organization fact.

        Returns:
            Validated fact draft.

        Raises:
            GrcValidationError: If the fact is malformed.
        """

        confidence = float(self.confidence)
        if not 0.0 <= confidence <= 1.0:
            raise GrcValidationError("Fact confidence must be between 0 and 1.")
        return OrganizationFactDraft(
            fact_type=required_text(
                self.fact_type,
                "Fact type",
                max_length=100,
            ).lower(),
            fact_key=required_text(
                self.fact_key,
                "Fact key",
                max_length=220,
            ).lower(),
            value_text=required_text(
                self.value_text,
                "Fact value",
                max_length=2_000,
            ),
            source_type=_choice(
                self.source_type,
                "fact source type",
                FACT_SOURCE_TYPES,
            ),
            source_reference=optional_text(
                self.source_reference,
                max_length=1_000,
            ),
            confidence=confidence,
            status=_choice(self.status, "fact status", FACT_STATUSES),
        )
