"""Organization discovery, reusable facts, and deterministic ISO proposals."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from securescope.grc.engagement_models import GrcValidationError
from securescope.grc.organization_models import (
    OrganizationFactDraft,
    OrganizationProfileDraft,
)
from securescope.persistence import organization_knowledge_repository as repository
from securescope.persistence.organization_knowledge_repository import (
    OrganizationKnowledgeRepositoryError,
)


class OrganizationKnowledgeServiceError(RuntimeError):
    """Raised when organization discovery cannot be validated or persisted."""


@dataclass(frozen=True)
class ContextRecommendation:
    """One reviewable organizational-context recommendation.

    Args:
        issue_type: Internal or External.
        category: Short context category.
        title: Consultant-facing recommendation title.
        description: Proposed issue description.
        effect_on_isms: Proposed ISMS relevance explanation.
        rationale: Why SecureScope proposed the issue.
    """

    issue_type: str
    category: str
    title: str
    description: str
    effect_on_isms: str
    rationale: str


@dataclass(frozen=True)
class PartyRecommendation:
    """One reviewable interested-party recommendation.

    Args:
        name: Proposed party name.
        party_type: Existing GRC party vocabulary value.
        relationship_description: Proposed relationship description.
        needs_and_expectations: Proposed consolidated needs.
        requirements: Suggested requirement statements.
        rationale: Why SecureScope proposed the party.
    """

    name: str
    party_type: str
    relationship_description: str
    needs_and_expectations: str
    requirements: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class ScopeComposition:
    """Deterministic draft scope assembled from confirmed organization facts.

    Args:
        statement: Proposed formal scope statement.
        boundaries: Proposed boundary summary.
        locations: Included locations.
        departments: Included organizational units.
        products_and_services: Included services/products.
        technologies: Included technology boundaries.
        assumptions: Missing information that still requires confirmation.
    """

    statement: str
    boundaries: str
    locations: tuple[str, ...]
    departments: tuple[str, ...]
    products_and_services: tuple[str, ...]
    technologies: tuple[str, ...]
    assumptions: tuple[str, ...]


def _slug(value: str) -> str:
    """Create a stable lowercase fact key from human text.

    Args:
        value: Human-readable value.

    Returns:
        Safe lowercase key.

    Raises:
        No exceptions are raised.
    """

    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return normalized[:180] or "value"


def _as_tuple(profile: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """Normalize one profile list field from PostgreSQL/JSON.

    Args:
        profile: Organization-profile mapping.
        key: Profile field name.

    Returns:
        Non-empty string tuple.

    Raises:
        No exceptions are raised.
    """

    value = profile.get(key) or ()
    if isinstance(value, str):
        value = [value]
    return tuple(str(item).strip() for item in value if str(item).strip())


class OrganizationKnowledgeService:
    """Coordinate quick discovery, fact creation, and safe ISO recommendations."""

    def get_profile(self, client_name: str) -> dict[str, Any] | None:
        """Return the current organization profile.

        Args:
            client_name: Exact active client workspace name.

        Returns:
            Profile row or ``None``.

        Raises:
            OrganizationKnowledgeServiceError: If persistence is unavailable.
        """

        try:
            return repository.get_organization_profile(client_name)
        except OrganizationKnowledgeRepositoryError as exc:
            raise OrganizationKnowledgeServiceError(str(exc)) from exc

    def save_profile(
        self,
        client_name: str,
        engagement_id: int,
        draft: OrganizationProfileDraft,
        *,
        actor: str,
    ) -> dict[str, Any]:
        """Persist a quick profile and materialize reusable confirmed facts.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Quick organization-profile input.
            actor: Human principal confirming the information.

        Returns:
            Persisted profile row.

        Raises:
            OrganizationKnowledgeServiceError: If validation/persistence fails.
        """

        try:
            validated = draft.validate()
            profile = repository.upsert_organization_profile(
                client_name,
                validated,
                actor=actor,
            )
            scalar_facts = (
                ("industry", "industry", validated.industry),
                ("main_activity", "main-activity", validated.main_activity),
                ("employee_band", "employee-band", validated.employee_band),
                (
                    "infrastructure_model",
                    "infrastructure-model",
                    validated.infrastructure_model,
                ),
            )
            for fact_type, fact_key, value in scalar_facts:
                repository.upsert_organization_fact(
                    client_name,
                    OrganizationFactDraft(
                        fact_type=fact_type,
                        fact_key=fact_key,
                        value_text=value,
                        source_type="Guided discovery",
                        source_reference="Organization quick profile",
                        confidence=1.0,
                        status="Confirmed",
                    ),
                    actor=actor,
                    engagement_id=engagement_id,
                )
            collection_facts = (
                ("location", validated.locations),
                ("department", validated.departments),
                ("product_service", validated.products_and_services),
                ("technology", validated.technologies),
                ("customer_market", validated.customer_markets),
                ("certification_driver", validated.certification_drivers),
            )
            for fact_type, values in collection_facts:
                for value in values:
                    repository.upsert_organization_fact(
                        client_name,
                        OrganizationFactDraft(
                            fact_type=fact_type,
                            fact_key=_slug(value),
                            value_text=value,
                            source_type="Guided discovery",
                            source_reference="Organization quick profile",
                            confidence=1.0,
                            status="Confirmed",
                        ),
                        actor=actor,
                        engagement_id=engagement_id,
                    )
            return profile
        except (
            GrcValidationError,
            OrganizationKnowledgeRepositoryError,
        ) as exc:
            raise OrganizationKnowledgeServiceError(str(exc)) from exc

    def list_facts(
        self,
        client_name: str,
        engagement_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return confirmed/reviewable organization facts.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Optional selected engagement identifier.

        Returns:
            Organization-fact rows.

        Raises:
            OrganizationKnowledgeServiceError: If persistence is unavailable.
        """

        try:
            return repository.list_organization_facts(
                client_name,
                engagement_id=engagement_id,
            )
        except OrganizationKnowledgeRepositoryError as exc:
            raise OrganizationKnowledgeServiceError(str(exc)) from exc

    @staticmethod
    def context_recommendations(
        profile: Mapping[str, Any],
    ) -> tuple[ContextRecommendation, ...]:
        """Build deterministic context recommendations from confirmed profile data.

        Args:
            profile: Persisted organization profile.

        Returns:
            Ordered recommendations requiring human review.

        Raises:
            No exceptions are raised.
        """

        industry = str(profile.get("industry") or "").casefold()
        employee_band = str(profile.get("employee_band") or "Unknown")
        infrastructure = str(profile.get("infrastructure_model") or "Unknown")
        technologies = _as_tuple(profile, "technologies")
        markets = _as_tuple(profile, "customer_markets")
        drivers = _as_tuple(profile, "certification_drivers")
        technology_text = " ".join(technologies).casefold()
        market_text = " ".join(markets).casefold()
        driver_text = " ".join(drivers).casefold()

        recommendations: list[ContextRecommendation] = [
            ContextRecommendation(
                issue_type="Internal",
                category="Business operations",
                title="Dependence on information systems",
                description=(
                    "Core business activities depend on the confidentiality, "
                    "integrity and availability of information systems and data."
                ),
                effect_on_isms=(
                    "The ISMS should prioritize systems and information that are "
                    "necessary to deliver the organization's main products/services."
                ),
                rationale="Derived from the organization profile and certification scope.",
            ),
            ContextRecommendation(
                issue_type="External",
                category="Cybersecurity",
                title="Evolving cyber threat environment",
                description=(
                    "The organization operates in an environment where cyber threats "
                    "and vulnerabilities can affect service delivery and information."
                ),
                effect_on_isms=(
                    "Threat and vulnerability information should inform risk "
                    "assessment, technical assurance and treatment priorities."
                ),
                rationale="Baseline information-security context for an ISO 27001 ISMS.",
            ),
        ]
        if infrastructure in {"Cloud", "Hybrid", "Mostly SaaS"} or any(
            token in technology_text for token in ("aws", "azure", "google cloud", "microsoft 365")
        ):
            recommendations.append(
                ContextRecommendation(
                    issue_type="External",
                    category="Third-party dependency",
                    title="Dependence on cloud and SaaS providers",
                    description=(
                        "Important business services depend on external cloud or SaaS "
                        "providers for hosting, identity, collaboration or operations."
                    ),
                    effect_on_isms=(
                        "Supplier security, availability, shared-responsibility and "
                        "service-continuity risks should be addressed by the ISMS."
                    ),
                    rationale="Cloud/SaaS infrastructure is recorded in the profile.",
                )
            )
        if any(token in industry for token in ("software", "saas", "technology")) or any(
            token in technology_text for token in ("github", "gitlab", "jenkins")
        ):
            recommendations.append(
                ContextRecommendation(
                    issue_type="Internal",
                    category="Software development",
                    title="Software development and change velocity",
                    description=(
                        "Software development and frequent changes can introduce "
                        "security defects or configuration drift if not governed."
                    ),
                    effect_on_isms=(
                        "Secure development, change control, access and technical "
                        "vulnerability management should be considered in the ISMS."
                    ),
                    rationale="Software-development characteristics are present.",
                )
            )
        if employee_band in {"1-10", "11-25", "26-50"}:
            recommendations.append(
                ContextRecommendation(
                    issue_type="Internal",
                    category="People and responsibilities",
                    title="Concentrated security responsibilities",
                    description=(
                        "A smaller organization may depend on a limited number of "
                        "people for IT, security and continuity responsibilities."
                    ),
                    effect_on_isms=(
                        "Responsibilities, segregation where practical, backup roles "
                        "and management oversight should be made explicit."
                    ),
                    rationale=f"Employee band is {employee_band}.",
                )
            )
        if "europe" in market_text or "eu" in market_text:
            recommendations.append(
                ContextRecommendation(
                    issue_type="External",
                    category="Legal and privacy",
                    title="European customer and data-protection expectations",
                    description=(
                        "Serving European customers can create contractual and legal "
                        "expectations around information security and personal data."
                    ),
                    effect_on_isms=(
                        "Applicable legal, regulatory and customer obligations should "
                        "be identified and maintained as interested-party requirements."
                    ),
                    rationale="European Union/European market is recorded.",
                )
            )
        if any(token in driver_text for token in ("customer", "contract", "tender", "client")):
            recommendations.append(
                ContextRecommendation(
                    issue_type="External",
                    category="Customer expectations",
                    title="Customer-driven security assurance",
                    description=(
                        "Customer or tender expectations are a material driver for the "
                        "ISO 27001 programme."
                    ),
                    effect_on_isms=(
                        "Customer security commitments and assurance expectations should "
                        "be reflected in scope, requirements and evidence priorities."
                    ),
                    rationale="A customer/tender certification driver is recorded.",
                )
            )
        return tuple(recommendations)

    @staticmethod
    def party_recommendations(
        profile: Mapping[str, Any],
    ) -> tuple[PartyRecommendation, ...]:
        """Build deterministic interested-party recommendations.

        Args:
            profile: Persisted organization profile.

        Returns:
            Ordered party recommendations requiring human approval.

        Raises:
            No exceptions are raised.
        """

        technologies = _as_tuple(profile, "technologies")
        markets = _as_tuple(profile, "customer_markets")
        drivers = _as_tuple(profile, "certification_drivers")
        market_text = " ".join(markets).casefold()
        driver_text = " ".join(drivers).casefold()
        recommendations: list[PartyRecommendation] = [
            PartyRecommendation(
                name="Customers",
                party_type="Customer",
                relationship_description=(
                    "Organizations or users receiving the in-scope products/services."
                ),
                needs_and_expectations=(
                    "Confidentiality, integrity, availability, reliable service, "
                    "contractual security and appropriate incident communication."
                ),
                requirements=(
                    "Protect customer information from unauthorized access or disclosure.",
                    "Maintain availability and resilience appropriate to contractual commitments.",
                    "Communicate material security incidents as required by contract or law.",
                ),
                rationale="Customers are a baseline interested party for service delivery.",
            ),
            PartyRecommendation(
                name="Employees",
                party_type="Employee",
                relationship_description=(
                    "Personnel who use or administer in-scope information and systems."
                ),
                needs_and_expectations=(
                    "Secure access, reliable systems, clear responsibilities, awareness "
                    "and protection of employee information."
                ),
                requirements=(
                    "Provide access appropriate to assigned responsibilities.",
                    "Communicate information-security responsibilities and awareness expectations.",
                ),
                rationale="Employees participate in and depend on the ISMS.",
            ),
            PartyRecommendation(
                name="Certification body",
                party_type="Certification body",
                relationship_description=("Independent body evaluating conformity of the ISMS."),
                needs_and_expectations=(
                    "Objective evidence that the ISMS conforms to applicable ISO/IEC "
                    "27001 requirements and operates as defined."
                ),
                requirements=("Maintain auditable evidence supporting the operation of the ISMS.",),
                rationale="An ISO 27001 certification programme is active.",
            ),
        ]
        provider_names = []
        for technology in technologies:
            lowered = technology.casefold()
            if any(
                token in lowered
                for token in (
                    "aws",
                    "amazon web services",
                    "azure",
                    "microsoft 365",
                    "google cloud",
                    "github",
                    "gitlab",
                )
            ):
                provider_names.append(technology)
        for provider in dict.fromkeys(provider_names):
            recommendations.append(
                PartyRecommendation(
                    name=provider,
                    party_type="Supplier",
                    relationship_description=(
                        "Technology provider supporting in-scope systems or business operations."
                    ),
                    needs_and_expectations=(
                        "Defined shared security responsibilities, service availability, "
                        "incident communication and protection of entrusted information."
                    ),
                    requirements=(
                        "Maintain supplier security obligations appropriate to the service.",
                        "Monitor material service, availability and security changes.",
                    ),
                    rationale=f"{provider} is recorded as an important technology.",
                )
            )
        if "europe" in market_text or "eu" in market_text or "regulat" in driver_text:
            recommendations.append(
                PartyRecommendation(
                    name="Applicable regulators and public authorities",
                    party_type="Regulator",
                    relationship_description=(
                        "Authorities responsible for applicable legal and regulatory obligations."
                    ),
                    needs_and_expectations=(
                        "Compliance with applicable information-security, privacy, breach "
                        "notification and record-keeping obligations."
                    ),
                    requirements=(
                        "Identify and maintain applicable legal and regulatory obligations.",
                        "Meet applicable security and incident-notification requirements.",
                    ),
                    rationale="Regulatory relevance is suggested by the customer market/driver.",
                )
            )
        return tuple(recommendations)

    @staticmethod
    def compose_scope(profile: Mapping[str, Any]) -> ScopeComposition:
        """Compose a conservative scope draft from confirmed organization facts.

        Args:
            profile: Persisted organization profile.

        Returns:
            Deterministic scope composition for human review.

        Raises:
            No exceptions are raised.
        """

        activity = str(profile.get("main_activity") or "the organization's services").strip()
        products = _as_tuple(profile, "products_and_services")
        departments = _as_tuple(profile, "departments")
        locations = _as_tuple(profile, "locations")
        technologies = _as_tuple(profile, "technologies")

        product_phrase = ", ".join(products) if products else activity
        department_phrase = (
            ", ".join(departments) if departments else "relevant organizational functions"
        )
        location_phrase = (
            ", ".join(locations) if locations else "the organization's operating locations"
        )
        technology_phrase = (
            ", ".join(technologies)
            if technologies
            else "supporting information systems and infrastructure"
        )
        statement = (
            "The Information Security Management System covers "
            f"{product_phrase}, including {department_phrase}, operated from "
            f"{location_phrase}, together with {technology_phrase} and the people, "
            "processes, information and external dependencies required to deliver "
            "those in-scope activities."
        )
        boundaries = (
            f"Organizational boundary: {department_phrase}. "
            f"Physical/operating boundary: {location_phrase}. "
            f"Technology boundary: {technology_phrase}."
        )
        assumptions: list[str] = []
        if not products:
            assumptions.append("Confirm the exact products and services included in the ISMS.")
        if not departments:
            assumptions.append("Confirm the organizational units included in the ISMS.")
        if not locations:
            assumptions.append("Confirm physical and remote-work locations in scope.")
        if not technologies:
            assumptions.append("Confirm the main technology and infrastructure boundaries.")
        assumptions.append("Confirm exclusions and external interfaces before approval.")
        return ScopeComposition(
            statement=statement,
            boundaries=boundaries,
            locations=locations,
            departments=departments,
            products_and_services=products,
            technologies=technologies,
            assumptions=tuple(assumptions),
        )
