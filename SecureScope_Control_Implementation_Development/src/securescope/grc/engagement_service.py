"""Application service for client, engagement and ISMS scope workflows."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from securescope.grc.engagement_models import (
    ClimateDeterminationDraft,
    ContextIssueDraft,
    EngagementDraft,
    GrcValidationError,
    InterestedPartyDraft,
    MilestoneDraft,
    OrganizationalUnitDraft,
    PartyRequirementDraft,
    RaciAssignmentDraft,
    ScopeDraft,
)
from securescope.persistence import grc_workspace_repository as repository
from securescope.persistence.grc_workspace_repository import (
    GrcWorkspaceRepositoryError,
)

LOGGER = logging.getLogger(__name__)


class GrcWorkspaceServiceError(RuntimeError):
    """Raised when a validated GRC workspace operation cannot complete."""


class GrcWorkspaceService:
    """Coordinate GRC repository operations for Streamlit and FastAPI.

    The service owns context selection and error translation. PostgreSQL
    repositories remain responsible for tenant filtering and transactions.

    Raises:
        GrcWorkspaceServiceError: If a domain or persistence operation fails.
    """

    @staticmethod
    def _translate(operation: str, exc: Exception) -> GrcWorkspaceServiceError:
        """Translate one known domain or repository failure.

        Args:
            operation: Short operation label for structured logs.
            exc: Known validation or repository exception.

        Returns:
            Safe application-service exception.

        Raises:
            No exceptions are raised by this helper.
        """

        if isinstance(exc, GrcValidationError):
            return GrcWorkspaceServiceError(str(exc))
        reference = uuid.uuid4().hex[:12]
        LOGGER.error(
            "GRC operation %s failed [reference %s]",
            operation,
            reference,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return GrcWorkspaceServiceError(
            f"Could not {operation.replace('_', ' ')}. "
            f"Your changes were not saved. Reference: {reference}."
        )

    def open_workspace(
        self,
        client_name: str,
        *,
        engagement_id: int | None = None,
        scope_id: int | None = None,
        actor: str = "securescope-ui",
    ) -> dict[str, Any]:
        """Resolve the persistent client → engagement → scope UI context.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Optional previously selected engagement.
            scope_id: Optional previously selected scope.
            actor: Human or service principal used by first-time bootstrap.

        Returns:
            Available engagements/scopes, selected IDs and overview metrics.

        Raises:
            GrcWorkspaceServiceError: If the workspace cannot be initialized.
        """

        try:
            foundation = repository.ensure_workspace_foundation(
                client_name,
                actor=actor,
            )
            engagements = repository.list_engagements(client_name)
            engagement_ids = {int(item["id"]) for item in engagements}
            selected_engagement_id = (
                int(engagement_id)
                if engagement_id is not None and int(engagement_id) in engagement_ids
                else int(foundation["engagement_id"])
            )
            if selected_engagement_id not in engagement_ids:
                selected_engagement_id = int(engagements[0]["id"])
            scopes = repository.list_scopes(client_name, selected_engagement_id)
            scope_ids = {int(item["id"]) for item in scopes}
            selected_scope_id = (
                int(scope_id) if scope_id is not None and int(scope_id) in scope_ids else None
            )
            if selected_scope_id is None and scopes:
                approved_scopes = [
                    item for item in scopes if item.get("current_approved_version_id") is not None
                ]
                selected_scope_id = int((approved_scopes or scopes)[0]["id"])
            overview = repository.workspace_overview(
                client_name,
                selected_engagement_id,
                selected_scope_id,
            )
            return {
                "foundation": foundation,
                "engagements": engagements,
                "scopes": scopes,
                "selected_engagement_id": selected_engagement_id,
                "selected_scope_id": selected_scope_id,
                "overview": overview,
            }
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("open_workspace", exc) from exc

    def load_registers(
        self,
        client_name: str,
        engagement_id: int,
        scope_id: int | None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Load all first-milestone registers for the selected UI context.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            scope_id: Optional selected scope identifier.

        Returns:
            Context, climate, party, unit, member, RACI and milestone rows.

        Raises:
            GrcWorkspaceServiceError: If any tenant-scoped read fails.
        """

        try:
            return {
                "context_issues": repository.list_context_issues(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "climate_determinations": (
                    repository.list_climate_determinations(
                        client_name,
                        engagement_id,
                    )
                ),
                "interested_parties": repository.list_interested_parties(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "organizational_units": repository.list_organizational_units(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "workspace_members": repository.list_workspace_members(client_name),
                "engagement_members": repository.list_engagement_members(
                    client_name,
                    engagement_id,
                ),
                "role_assignments": repository.list_role_assignments(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "milestones": repository.list_milestones(
                    client_name,
                    engagement_id,
                ),
            }
        except GrcWorkspaceRepositoryError as exc:
            raise self._translate("load_registers", exc) from exc

    def load_section(
        self,
        client_name: str,
        engagement_id: int,
        scope_id: int | None,
        section: str,
    ) -> dict[str, list[dict[str, Any]]]:
        """Load only the registers required by one visible UI section.

        This method prevents Streamlit reruns from querying every GRC register
        when the consultant is working in only one Programme Setup section.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            scope_id: Optional selected scope identifier.
            section: One of overview, discovery, engagement, context, parties, scope, or roles.

        Returns:
            Section-specific tenant-filtered register rows.

        Raises:
            GrcWorkspaceServiceError: If the section is unsupported or a
                tenant-scoped read fails.
        """

        loaders = {
            "overview": {
                "climate_determinations": lambda: (
                    repository.list_climate_determinations(
                        client_name,
                        engagement_id,
                    )
                ),
                "milestones": lambda: repository.list_milestones(
                    client_name,
                    engagement_id,
                ),
            },
            "discovery": {
                "context_issues": lambda: repository.list_context_issues(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "interested_parties": lambda: repository.list_interested_parties(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
            },
            "engagement": {
                "engagement_members": lambda: repository.list_engagement_members(
                    client_name, engagement_id
                ),
                "workspace_members": lambda: repository.list_workspace_members(client_name),
                "milestones": lambda: repository.list_milestones(
                    client_name,
                    engagement_id,
                ),
            },
            "context": {
                "context_issues": lambda: repository.list_context_issues(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
                "climate_determinations": lambda: (
                    repository.list_climate_determinations(
                        client_name,
                        engagement_id,
                    )
                ),
            },
            "parties": {
                "interested_parties": lambda: repository.list_interested_parties(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
            },
            "scope": {
                "organizational_units": lambda: (
                    repository.list_organizational_units(
                        client_name,
                        engagement_id,
                        scope_id,
                    )
                ),
            },
            "roles": {
                "workspace_members": lambda: repository.list_workspace_members(client_name),
                "engagement_members": lambda: (
                    repository.list_engagement_members(
                        client_name,
                        engagement_id,
                    )
                ),
                "role_assignments": lambda: repository.list_role_assignments(
                    client_name,
                    engagement_id,
                    scope_id,
                ),
            },
        }
        section_loaders = loaders.get(str(section).strip().lower())
        if section_loaders is None:
            raise GrcWorkspaceServiceError(f"Unsupported Programme Setup section: {section}.")
        try:
            return {name: loader() for name, loader in section_loaders.items()}
        except GrcWorkspaceRepositoryError as exc:
            raise self._translate(f"load_section:{section}", exc) from exc

    def load_party_requirements(
        self,
        client_name: str,
        engagement_id: int,
        party_id: int,
    ) -> list[dict[str, Any]]:
        """Load requirements for one tenant-owned interested party.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            party_id: Interested-party identifier.

        Returns:
            Party requirement rows.

        Raises:
            GrcWorkspaceServiceError: If ownership or persistence checks fail.
        """

        try:
            return repository.list_party_requirements(
                client_name,
                engagement_id,
                party_id,
            )
        except GrcWorkspaceRepositoryError as exc:
            raise self._translate("load_party_requirements", exc) from exc

    def create_engagement(
        self,
        client_name: str,
        draft: EngagementDraft,
        *,
        actor: str,
    ) -> dict[str, int]:
        """Create an engagement and initial draft scope.

        Args:
            client_name: Exact active client workspace name.
            draft: Engagement input to validate and persist.
            actor: Person creating the engagement.

        Returns:
            New engagement, scope and version identifiers.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_engagement(
                client_name,
                draft,
                actor=actor,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_engagement", exc) from exc

    def create_scope_version(
        self,
        client_name: str,
        engagement_id: int,
        draft: ScopeDraft,
        *,
        actor: str,
        scope_id: int | None = None,
    ) -> dict[str, int]:
        """Create a new draft ISMS scope version.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Scope content to validate and persist.
            actor: Person preparing the scope.
            scope_id: Existing scope ID, or ``None`` for a new definition.

        Returns:
            Scope, version and version-number identifiers.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_scope_version(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_scope_version", exc) from exc

    def approve_scope_version(
        self,
        client_name: str,
        engagement_id: int,
        scope_id: int,
        version_id: int,
        *,
        approver_email: str,
        comment: str,
    ) -> dict[str, Any]:
        """Approve and freeze a draft scope version.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            scope_id: Selected scope identifier.
            version_id: Scope-version identifier to approve.
            approver_email: Active Administrator or Consultant email.
            comment: Approval rationale.

        Returns:
            Approved scope-version row.

        Raises:
            GrcWorkspaceServiceError: If authorization or persistence fails.
        """

        try:
            return repository.approve_scope_version(
                client_name,
                engagement_id,
                scope_id,
                version_id,
                approver_email=approver_email,
                comment=comment,
            )
        except GrcWorkspaceRepositoryError as exc:
            raise self._translate("approve_scope_version", exc) from exc

    def create_context_issue(
        self,
        client_name: str,
        engagement_id: int,
        draft: ContextIssueDraft,
        *,
        actor: str,
        scope_id: int | None = None,
        reuse_existing: bool = False,
    ) -> int:
        """Create one context issue.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Context issue input.
            actor: Person recording the issue.
            scope_id: Optional related scope.
            reuse_existing: Reuse an already recorded Discovery suggestion.

        Returns:
            New issue identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_context_issue(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
                reuse_existing=reuse_existing,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_context_issue", exc) from exc

    def create_climate_determination(
        self,
        client_name: str,
        engagement_id: int,
        draft: ClimateDeterminationDraft,
        *,
        actor: str,
        scope_id: int | None = None,
    ) -> dict[str, int]:
        """Create a versioned climate relevance determination.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Climate determination input.
            actor: Person recording the determination.
            scope_id: Optional related scope.

        Returns:
            New determination ID and version number.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_climate_determination(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_climate_determination", exc) from exc

    def create_interested_party(
        self,
        client_name: str,
        engagement_id: int,
        draft: InterestedPartyDraft,
        *,
        actor: str,
        scope_id: int | None = None,
        reuse_existing: bool = False,
    ) -> int:
        """Create an interested-party register entry.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Interested-party input.
            actor: Person recording the party.
            scope_id: Optional related scope.
            reuse_existing: Reuse an already recorded Discovery suggestion.

        Returns:
            New interested-party identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_interested_party(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
                reuse_existing=reuse_existing,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_interested_party", exc) from exc

    def create_party_requirement(
        self,
        client_name: str,
        engagement_id: int,
        party_id: int,
        draft: PartyRequirementDraft,
        *,
        actor: str,
        scope_id: int | None = None,
        reuse_existing: bool = False,
    ) -> int:
        """Attach a requirement to an interested party.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            party_id: Parent interested-party identifier.
            draft: Requirement input.
            actor: Person recording the requirement.
            scope_id: Optional related scope.
            reuse_existing: Reuse an already recorded Discovery suggestion.

        Returns:
            New requirement identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_party_requirement(
                client_name,
                engagement_id,
                party_id,
                draft,
                actor=actor,
                scope_id=scope_id,
                reuse_existing=reuse_existing,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_party_requirement", exc) from exc

    def create_organizational_unit(
        self,
        client_name: str,
        engagement_id: int,
        draft: OrganizationalUnitDraft,
        *,
        actor: str,
        scope_id: int | None = None,
    ) -> int:
        """Create a site, department or organizational unit.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Organizational-unit input.
            actor: Person recording the unit.
            scope_id: Optional related scope.

        Returns:
            New organizational-unit identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_organizational_unit(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_organizational_unit", exc) from exc

    def assign_engagement_member(
        self,
        client_name: str,
        engagement_id: int,
        user_id: int,
        engagement_role: str,
        *,
        actor: str,
    ) -> int:
        """Assign an existing workspace member to an engagement role.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            user_id: Existing workspace member's user ID.
            engagement_role: Allowlisted engagement role.
            actor: Person recording the assignment.

        Returns:
            Engagement-membership identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.assign_engagement_member(
                client_name,
                engagement_id,
                user_id,
                engagement_role,
                actor=actor,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("assign_engagement_member", exc) from exc

    def assign_raci_role(
        self,
        client_name: str,
        engagement_id: int,
        draft: RaciAssignmentDraft,
        *,
        actor: str,
        scope_id: int | None = None,
    ) -> int:
        """Create a real user-backed ISMS RACI assignment.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: RACI assignment input.
            actor: Person recording the assignment.
            scope_id: Optional related scope.

        Returns:
            RACI assignment identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.assign_raci_role(
                client_name,
                engagement_id,
                draft,
                actor=actor,
                scope_id=scope_id,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("assign_raci_role", exc) from exc

    def create_milestone(
        self,
        client_name: str,
        engagement_id: int,
        draft: MilestoneDraft,
        *,
        actor: str,
    ) -> int:
        """Create an engagement milestone.

        Args:
            client_name: Exact active client workspace name.
            engagement_id: Selected engagement identifier.
            draft: Milestone input.
            actor: Person recording the milestone.

        Returns:
            New milestone identifier.

        Raises:
            GrcWorkspaceServiceError: If validation or persistence fails.
        """

        try:
            return repository.create_milestone(
                client_name,
                engagement_id,
                draft,
                actor=actor,
            )
        except (GrcValidationError, GrcWorkspaceRepositoryError) as exc:
            raise self._translate("create_milestone", exc) from exc
