"""Workspace-authenticated FastAPI control plane.

Streamlit remains the presentation layer. This module exposes service methods
for a future React client and independent workers without moving scanner
execution into the web process.
"""

from __future__ import annotations

import base64
from datetime import date
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, Field

from securescope import __version__
from securescope.evidence.evidence_service import (
    EvidenceServiceError,
    consultant_review,
    ingest_report,
    request_manual_evidence,
    submit_manual_evidence,
)
from securescope.evidence.models import ReviewDecision, WorkspaceRole, role_can
from securescope.evidence.tool_catalog import TOOLS
from securescope.grc.control_catalog import ISO_CONTROL_CATALOG, catalog_summary
from securescope.grc.engagement_models import (
    ClimateDeterminationDraft,
    ContextIssueDraft,
    EngagementDraft,
    InterestedPartyDraft,
    MilestoneDraft,
    OrganizationalUnitDraft,
    PartyRequirementDraft,
    RaciAssignmentDraft,
    ScopeDraft,
)
from securescope.grc.engagement_service import (
    GrcWorkspaceService,
    GrcWorkspaceServiceError,
)
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    enqueue_evidence_job,
    evidence_hub_summary,
    get_workspace_role,
    list_evidence_records,
    list_evidence_requests,
)
from securescope.reporting.auditor_package_service import (
    AuditorPackageError,
    build_auditor_package,
    build_control_matrix_pdf,
)

app = FastAPI(
    title="SecureScope control plane",
    version=__version__,
    description=(
        "Workspace-isolated evidence and GRC service API. Scanner execution is "
        "delegated to persistent workers."
    ),
)
grc_service = GrcWorkspaceService()


class WorkspaceContext(BaseModel):
    """Verified user membership in one named workspace."""

    workspace: str
    email: str
    role: WorkspaceRole


class EvidenceImportRequest(BaseModel):
    """Bounded base64 report import request."""

    tool_id: str
    filename: str
    content_base64: str
    title: str
    summary: str
    scope_description: str
    source_asset_or_system: str = ""
    owner: str
    acceptable_age_days: int = Field(default=90, ge=1, le=3650)


class ManualEvidenceRequest(BaseModel):
    """Manual governance or hybrid evidence submission."""

    control_ids: list[str]
    evidence_type: str
    title: str
    summary: str
    scope_description: str
    source_asset_or_system: str = ""
    owner: str
    acceptable_age_days: int = Field(default=365, ge=1, le=3650)


class ReviewRequest(BaseModel):
    """Consultant evidence review request."""

    decision: ReviewDecision
    comment: str
    approved_controls: list[str] = Field(default_factory=list)


class NewEvidenceRequest(BaseModel):
    """Request missing evidence from a client contributor."""

    control_id: str
    title: str
    requested_evidence: str
    assigned_to: str
    due_date: date


class ExportRequest(BaseModel):
    """Auditor export metadata."""

    assessment_scope: str
    include_raw_evidence: bool = True


class CollectionRequest(BaseModel):
    """Allowlisted defensive collector request."""

    tool_id: str
    target: str
    profile: str = ""
    timeout_seconds: int = Field(default=1800, ge=30, le=14400)


class EngagementCreateRequest(BaseModel):
    """Create one client-owned engagement and initial draft scope."""

    reference: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=250)
    engagement_type: str
    objective: str = Field(min_length=1, max_length=4_000)
    status: str = "Draft"
    target_standard: str = Field(default="ISO/IEC 27001:2022", max_length=150)
    cycle_year: int | None = Field(default=None, ge=2000, le=2200)
    planned_start_date: date | None = None
    planned_end_date: date | None = None
    certification_target_date: date | None = None
    client_sponsor: str = Field(default="", max_length=250)


class ScopeVersionCreateRequest(BaseModel):
    """Create a new draft version of an existing or new ISMS scope."""

    scope_id: int | None = Field(default=None, ge=1)
    scope_code: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=250)
    scope_statement: str = Field(min_length=1, max_length=10_000)
    boundaries: str = Field(default="", max_length=10_000)
    exclusions: str = Field(default="", max_length=10_000)
    interfaces_and_dependencies: str = Field(default="", max_length=10_000)
    locations: list[str] = Field(default_factory=list, max_length=250)
    organizational_units: list[str] = Field(default_factory=list, max_length=250)
    products_and_services: list[str] = Field(default_factory=list, max_length=250)
    technologies: list[str] = Field(default_factory=list, max_length=250)
    assumptions: list[str] = Field(default_factory=list, max_length=250)
    effective_from: date | None = None
    effective_to: date | None = None


class ScopeApprovalRequest(BaseModel):
    """Approve and freeze one scope version with a human rationale."""

    comment: str = Field(min_length=1, max_length=4_000)


class ContextIssueCreateRequest(BaseModel):
    """Create an internal or external organizational-context issue."""

    scope_id: int | None = Field(default=None, ge=1)
    issue_type: str
    category: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=250)
    description: str = Field(min_length=1, max_length=4_000)
    effect_on_isms: str = Field(min_length=1, max_length=4_000)
    relevance: str
    owner: str = Field(min_length=1, max_length=250)
    review_date: date | None = None


class ClimateDeterminationCreateRequest(BaseModel):
    """Append a climate relevance determination version."""

    scope_id: int | None = Field(default=None, ge=1)
    determination: str
    rationale: str = Field(min_length=1, max_length=4_000)
    identified_impacts: str = Field(default="", max_length=4_000)
    determined_by: str = Field(min_length=1, max_length=250)
    determination_date: date
    next_review_date: date | None = None


class InterestedPartyCreateRequest(BaseModel):
    """Create one interested-party register entry."""

    scope_id: int | None = Field(default=None, ge=1)
    name: str = Field(min_length=1, max_length=250)
    party_type: str
    relationship_description: str = Field(default="", max_length=4_000)
    needs_and_expectations: str = Field(min_length=1, max_length=4_000)
    communication_method: str = Field(default="", max_length=1_000)
    owner: str = Field(min_length=1, max_length=250)


class PartyRequirementCreateRequest(BaseModel):
    """Attach an applicable requirement to an interested party."""

    scope_id: int | None = Field(default=None, ge=1)
    requirement_type: str
    requirement: str = Field(min_length=1, max_length=4_000)
    source_reference: str = Field(default="", max_length=500)
    applicability: str = "Applicable"
    mandatory: bool = True
    owner: str = Field(min_length=1, max_length=250)
    review_date: date | None = None


class OrganizationalUnitCreateRequest(BaseModel):
    """Create a site, department or other organizational unit."""

    scope_id: int | None = Field(default=None, ge=1)
    unit_type: str
    name: str = Field(min_length=1, max_length=250)
    description: str = Field(default="", max_length=4_000)
    address: str = Field(default="", max_length=1_000)
    in_scope: bool = True
    owner: str = Field(default="", max_length=250)
    parent_unit_id: int | None = Field(default=None, ge=1)


class EngagementMemberCreateRequest(BaseModel):
    """Assign an existing workspace member to an engagement role."""

    user_id: int = Field(ge=1)
    engagement_role: str


class RaciAssignmentCreateRequest(BaseModel):
    """Create a user-backed ISMS RACI assignment."""

    scope_id: int | None = Field(default=None, ge=1)
    user_id: int = Field(ge=1)
    role_name: str = Field(min_length=1, max_length=250)
    responsibility: str = Field(min_length=1, max_length=4_000)
    raci_type: str
    authority: str = Field(default="", max_length=4_000)
    effective_from: date
    effective_to: date | None = None


class MilestoneCreateRequest(BaseModel):
    """Create one engagement or certification-cycle milestone."""

    title: str = Field(min_length=1, max_length=250)
    milestone_type: str
    description: str = Field(default="", max_length=4_000)
    due_date: date
    acceptance_criteria: str = Field(default="", max_length=4_000)
    owner_user_id: int | None = Field(default=None, ge=1)


def workspace_context(
    workspace: Annotated[str, Header(alias="X-SecureScope-Workspace")],
    email: Annotated[str, Header(alias="X-SecureScope-User")],
) -> WorkspaceContext:
    """Resolve headers to an active database-backed workspace membership."""

    try:
        role = get_workspace_role(workspace.strip(), email.strip().lower())
    except EvidenceRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active membership for this user and workspace.",
        )
    try:
        resolved_role = WorkspaceRole(role)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Unsupported workspace role.") from exc
    return WorkspaceContext(
        workspace=workspace.strip(),
        email=email.strip().lower(),
        role=resolved_role,
    )


def _require(context: WorkspaceContext, capability: str) -> None:
    """Enforce role capabilities consistently for every API mutation."""

    if not role_can(context.role, capability):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The {context.role.value} role cannot perform '{capability}'.",
        )


def _service_error(exc: Exception) -> HTTPException:
    """Convert known domain failures to safe client errors."""

    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@app.get("/health")
def health() -> dict[str, str]:
    """Return process liveness without exposing connector secrets."""

    return {"status": "ok", "version": __version__}


@app.get("/v1/catalog")
def catalog(context: Annotated[WorkspaceContext, Depends(workspace_context)]) -> dict[str, Any]:
    """Return public tool and short-control metadata for one authenticated user."""

    return {
        "workspace": context.workspace,
        "catalog_summary": catalog_summary(),
        "controls": [
            {
                "control_id": key,
                "name": value["name"],
                "family": value["family"],
                "kind": value["kind"],
                "automation_level": value["automation_level"],
                "sources": value["supported_data_sources"],
            }
            for key, value in ISO_CONTROL_CATALOG.items()
        ],
        "tools": [
            {
                "tool_id": tool.tool_id,
                "name": tool.name,
                "category": tool.category,
                "mode": tool.integration_mode.value,
                "execution_policy": tool.execution_policy.value,
                "formats": tool.report_formats,
                "controls": tool.iso_control_ids,
            }
            for tool in TOOLS
        ],
    }


@app.get("/v1/grc/workspace")
def grc_workspace_get(
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> dict[str, Any]:
    """Return the authenticated client → engagement → scope context.

    Args:
        context: Verified workspace membership injected by FastAPI.
        engagement_id: Optional selected engagement.
        scope_id: Optional selected ISMS scope.

    Returns:
        Workspace selectors, overview and first-milestone registers.

    Raises:
        HTTPException: If the context cannot be loaded safely.
    """

    _require(context, "read")
    try:
        workspace = grc_service.open_workspace(
            context.workspace,
            engagement_id=engagement_id,
            scope_id=scope_id,
            actor=context.email,
        )
        workspace["registers"] = grc_service.load_registers(
            context.workspace,
            int(workspace["selected_engagement_id"]),
            (
                int(workspace["selected_scope_id"])
                if workspace["selected_scope_id"] is not None
                else None
            ),
        )
        return workspace
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/grc/engagements", status_code=status.HTTP_201_CREATED)
def grc_engagement_create(
    request: EngagementCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a client-owned engagement and its initial draft scope."""

    _require(context, "review")
    try:
        return grc_service.create_engagement(
            context.workspace,
            EngagementDraft(
                reference=request.reference,
                name=request.name,
                engagement_type=request.engagement_type,
                objective=request.objective,
                status=request.status,
                target_standard=request.target_standard,
                cycle_year=request.cycle_year,
                planned_start_date=request.planned_start_date,
                planned_end_date=request.planned_end_date,
                certification_target_date=request.certification_target_date,
                client_sponsor=request.client_sponsor,
            ),
            actor=context.email,
        )
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/scopes",
    status_code=status.HTTP_201_CREATED,
)
def grc_scope_version_create(
    engagement_id: int,
    request: ScopeVersionCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a draft ISMS scope version without changing approved history."""

    _require(context, "review")
    try:
        return grc_service.create_scope_version(
            context.workspace,
            engagement_id,
            ScopeDraft(
                scope_code=request.scope_code,
                name=request.name,
                scope_statement=request.scope_statement,
                boundaries=request.boundaries,
                exclusions=request.exclusions,
                interfaces_and_dependencies=request.interfaces_and_dependencies,
                locations=tuple(request.locations),
                organizational_units=tuple(request.organizational_units),
                products_and_services=tuple(request.products_and_services),
                technologies=tuple(request.technologies),
                assumptions=tuple(request.assumptions),
                effective_from=request.effective_from,
                effective_to=request.effective_to,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/grc/engagements/{engagement_id}/scopes/{scope_id}/versions/" "{version_id}/approve")
def grc_scope_version_approve(
    engagement_id: int,
    scope_id: int,
    version_id: int,
    request: ScopeApprovalRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, Any]:
    """Approve and freeze a scope version as the authenticated consultant."""

    _require(context, "review")
    try:
        return grc_service.approve_scope_version(
            context.workspace,
            engagement_id,
            scope_id,
            version_id,
            approver_email=context.email,
            comment=request.comment,
        )
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/context-issues",
    status_code=status.HTTP_201_CREATED,
)
def grc_context_issue_create(
    engagement_id: int,
    request: ContextIssueCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a tenant-scoped organizational-context issue."""

    _require(context, "review")
    try:
        issue_id = grc_service.create_context_issue(
            context.workspace,
            engagement_id,
            ContextIssueDraft(
                issue_type=request.issue_type,
                category=request.category,
                title=request.title,
                description=request.description,
                effect_on_isms=request.effect_on_isms,
                relevance=request.relevance,
                owner=request.owner,
                review_date=request.review_date,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
        return {"issue_id": issue_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/climate-determinations",
    status_code=status.HTTP_201_CREATED,
)
def grc_climate_determination_create(
    engagement_id: int,
    request: ClimateDeterminationCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Append a versioned climate-change relevance determination."""

    _require(context, "review")
    try:
        return grc_service.create_climate_determination(
            context.workspace,
            engagement_id,
            ClimateDeterminationDraft(
                determination=request.determination,
                rationale=request.rationale,
                identified_impacts=request.identified_impacts,
                determined_by=request.determined_by,
                determination_date=request.determination_date,
                next_review_date=request.next_review_date,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/interested-parties",
    status_code=status.HTTP_201_CREATED,
)
def grc_interested_party_create(
    engagement_id: int,
    request: InterestedPartyCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a tenant-scoped interested-party entry."""

    _require(context, "review")
    try:
        party_id = grc_service.create_interested_party(
            context.workspace,
            engagement_id,
            InterestedPartyDraft(
                name=request.name,
                party_type=request.party_type,
                relationship_description=request.relationship_description,
                needs_and_expectations=request.needs_and_expectations,
                communication_method=request.communication_method,
                owner=request.owner,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
        return {"party_id": party_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/interested-parties/{party_id}/requirements",
    status_code=status.HTTP_201_CREATED,
)
def grc_party_requirement_create(
    engagement_id: int,
    party_id: int,
    request: PartyRequirementCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Attach an applicable requirement to a tenant-owned party."""

    _require(context, "review")
    try:
        requirement_id = grc_service.create_party_requirement(
            context.workspace,
            engagement_id,
            party_id,
            PartyRequirementDraft(
                requirement_type=request.requirement_type,
                requirement=request.requirement,
                source_reference=request.source_reference,
                applicability=request.applicability,
                mandatory=request.mandatory,
                owner=request.owner,
                review_date=request.review_date,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
        return {"requirement_id": requirement_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/organizational-units",
    status_code=status.HTTP_201_CREATED,
)
def grc_organizational_unit_create(
    engagement_id: int,
    request: OrganizationalUnitCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a tenant-scoped site or organizational unit."""

    _require(context, "review")
    try:
        unit_id = grc_service.create_organizational_unit(
            context.workspace,
            engagement_id,
            OrganizationalUnitDraft(
                unit_type=request.unit_type,
                name=request.name,
                description=request.description,
                address=request.address,
                in_scope=request.in_scope,
                owner=request.owner,
                parent_unit_id=request.parent_unit_id,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
        return {"unit_id": unit_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/members",
    status_code=status.HTTP_201_CREATED,
)
def grc_engagement_member_create(
    engagement_id: int,
    request: EngagementMemberCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Assign an active workspace user to an engagement role."""

    _require(context, "review")
    try:
        membership_id = grc_service.assign_engagement_member(
            context.workspace,
            engagement_id,
            request.user_id,
            request.engagement_role,
            actor=context.email,
        )
        return {"engagement_membership_id": membership_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/raci-assignments",
    status_code=status.HTTP_201_CREATED,
)
def grc_raci_assignment_create(
    engagement_id: int,
    request: RaciAssignmentCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a user-backed ISMS RACI assignment."""

    _require(context, "review")
    try:
        assignment_id = grc_service.assign_raci_role(
            context.workspace,
            engagement_id,
            RaciAssignmentDraft(
                user_id=request.user_id,
                role_name=request.role_name,
                responsibility=request.responsibility,
                raci_type=request.raci_type,
                authority=request.authority,
                effective_from=request.effective_from,
                effective_to=request.effective_to,
            ),
            actor=context.email,
            scope_id=request.scope_id,
        )
        return {"raci_assignment_id": assignment_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.post(
    "/v1/grc/engagements/{engagement_id}/milestones",
    status_code=status.HTTP_201_CREATED,
)
def grc_milestone_create(
    engagement_id: int,
    request: MilestoneCreateRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a certification-cycle or consulting milestone."""

    _require(context, "review")
    try:
        milestone_id = grc_service.create_milestone(
            context.workspace,
            engagement_id,
            MilestoneDraft(
                title=request.title,
                milestone_type=request.milestone_type,
                description=request.description,
                due_date=request.due_date,
                acceptance_criteria=request.acceptance_criteria,
                owner_user_id=request.owner_user_id,
            ),
            actor=context.email,
        )
        return {"milestone_id": milestone_id}
    except GrcWorkspaceServiceError as exc:
        raise _service_error(exc) from exc


@app.get("/v1/evidence")
def evidence_list(
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
    validation_status: str | None = None,
) -> dict[str, Any]:
    """List evidence strictly within the authenticated workspace."""

    try:
        return {
            "summary": evidence_hub_summary(context.workspace),
            "items": list_evidence_records(context.workspace, validation_status=validation_status),
        }
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/collection-jobs", status_code=status.HTTP_202_ACCEPTED)
def collection_job_create(
    request: CollectionRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, str]:
    """Queue a defensive collector; this API process never executes it."""

    _require(context, "collect")
    try:
        job_uuid = enqueue_evidence_job(
            context.workspace,
            tool_id=request.tool_id,
            target=request.target,
            profile=request.profile,
            requested_by=context.email,
            timeout_seconds=request.timeout_seconds,
        )
        return {"job_uuid": job_uuid, "status": "Queued"}
    except (ValueError, EvidenceRepositoryError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence/import", status_code=status.HTTP_201_CREATED)
def evidence_import(
    request: EvidenceImportRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Import a report and preserve its raw artifact and checksum."""

    _require(context, "import")
    try:
        content = base64.b64decode(request.content_base64, validate=True)
        evidence_id = ingest_report(
            context.workspace,
            role=context.role,
            tool_id=request.tool_id,
            filename=request.filename,
            content=content,
            title=request.title,
            summary=request.summary,
            scope_description=request.scope_description,
            source_asset_or_system=request.source_asset_or_system,
            owner=request.owner,
            submitted_by=context.email,
            acceptable_age_days=request.acceptable_age_days,
        )
        return {"evidence_id": evidence_id}
    except (ValueError, EvidenceServiceError, EvidenceRepositoryError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence/manual", status_code=status.HTTP_201_CREATED)
def evidence_manual(
    request: ManualEvidenceRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Submit manual evidence for a clause or Annex A control."""

    _require(context, "submit")
    try:
        evidence_id = submit_manual_evidence(
            context.workspace,
            role=context.role,
            control_ids=request.control_ids,
            evidence_type=request.evidence_type,
            title=request.title,
            summary=request.summary,
            scope_description=request.scope_description,
            source_asset_or_system=request.source_asset_or_system,
            owner=request.owner,
            submitted_by=context.email,
            acceptable_age_days=request.acceptable_age_days,
        )
        return {"evidence_id": evidence_id}
    except (ValueError, EvidenceServiceError, EvidenceRepositoryError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence/{evidence_id}/review", status_code=status.HTTP_204_NO_CONTENT)
def evidence_review(
    evidence_id: int,
    request: ReviewRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> Response:
    """Record a consultant decision without altering control assessment status."""

    _require(context, "review")
    try:
        consultant_review(
            context.workspace,
            evidence_id,
            role=context.role,
            decision=request.decision,
            validator=context.email,
            comment=request.comment,
            approved_controls=request.approved_controls,
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except (ValueError, EvidenceServiceError, EvidenceRepositoryError) as exc:
        raise _service_error(exc) from exc


@app.get("/v1/evidence-requests")
def evidence_request_list(
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> list[dict[str, Any]]:
    """List workspace-owned evidence requests."""

    try:
        return list_evidence_requests(context.workspace)
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence-requests", status_code=status.HTTP_201_CREATED)
def evidence_request_create(
    request: NewEvidenceRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict[str, int]:
    """Create a manual/hybrid evidence request."""

    _require(context, "review")
    try:
        request_id = request_manual_evidence(
            context.workspace,
            role=context.role,
            control_id=request.control_id,
            title=request.title,
            requested_evidence=request.requested_evidence,
            assigned_to=request.assigned_to,
            due_date=request.due_date,
            requested_by=context.email,
        )
        return {"request_id": request_id}
    except (ValueError, EvidenceServiceError, EvidenceRepositoryError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/exports/control-matrix.pdf")
def export_pdf(
    request: ExportRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> Response:
    """Return the printable control matrix."""

    _require(context, "export")
    try:
        content = build_control_matrix_pdf(
            context.workspace,
            prepared_by=context.email,
            assessment_scope=request.assessment_scope,
        )
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="ISO-control-matrix.pdf"'},
        )
    except (AuditorPackageError, EvidenceRepositoryError, ValueError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/exports/auditor-package.zip")
def export_package(
    request: ExportRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> Response:
    """Return the validated evidence and audit package."""

    _require(context, "export")
    try:
        content = build_auditor_package(
            context.workspace,
            prepared_by=context.email,
            assessment_scope=request.assessment_scope,
            include_raw_evidence=request.include_raw_evidence,
        )
        return Response(
            content=content,
            media_type="application/zip",
            headers={
                "Content-Disposition": ('attachment; filename="SecureScope-auditor-package.zip"')
            },
        )
    except (AuditorPackageError, EvidenceRepositoryError, ValueError) as exc:
        raise _service_error(exc) from exc


class EvidenceScheduleTarget(BaseModel):
    """Pinned approved scope/profile requirement and exact monitoring binding."""

    asset_id: int = Field(gt=0)
    binding_id: int = Field(gt=0)
    engagement_id: int = Field(gt=0)
    scope_id: int = Field(gt=0)
    scope_version_id: int = Field(gt=0)
    profile_id: int = Field(gt=0)
    requirement_id: str = Field(min_length=1, max_length=100)
    control_id: Literal["A.8.15", "A.8.16"]
    accept_health: bool = False
    health_policy: dict[str, Any] = Field(default_factory=dict)


class EvidenceScheduleRequest(BaseModel):
    """Create a disabled reviewed schedule revision; no source credentials are accepted."""

    name: str = Field(min_length=1, max_length=200)
    connector_id: str
    targets: list[EvidenceScheduleTarget] = Field(min_length=1, max_length=100)
    interval_seconds: int = Field(default=60, ge=30, le=604800)
    max_attempts: int = Field(default=3, ge=1, le=5)
    replaces: int | None = None


class ScheduleEnableRequest(BaseModel):
    """Explicit administrator enable/pause action."""

    enabled: bool


@app.get("/v1/evidence-schedules")
def evidence_schedule_list(
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict:
    """Return authorized schedule/job diagnostics and eligible target choices."""
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        return dict(
            schedules=schedules.list_schedules(context.workspace, context.email),
            targets=schedules.schedule_candidates(context.workspace, context.email),
        )
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence-schedules", status_code=status.HTTP_201_CREATED)
def evidence_schedule_create(
    request: EvidenceScheduleRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict:
    """Approve an immutable disabled revision using existing connector-admin authorization."""
    from securescope.integrations.wazuh_service import WazuhError
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        return dict(
            schedule_id=schedules.create_schedule(
                context.workspace, context.email, **request.model_dump()
            ),
            enabled=False,
        )
    except (EvidenceRepositoryError, WazuhError, ValueError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence-schedules/{schedule_id}/enabled")
def evidence_schedule_enable(
    schedule_id: int,
    request: ScheduleEnableRequest,
    context: Annotated[WorkspaceContext, Depends(workspace_context)],
) -> dict:
    """Enable or pause one owned schedule after current administrator checks."""
    from securescope.integrations.wazuh_service import WazuhError
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        schedules.set_enabled(context.workspace, context.email, schedule_id, request.enabled)
        return dict(schedule_id=schedule_id, enabled=request.enabled)
    except (EvidenceRepositoryError, WazuhError) as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence-schedules/{schedule_id}/run", status_code=status.HTTP_202_ACCEPTED)
def evidence_schedule_run(
    schedule_id: int, context: Annotated[WorkspaceContext, Depends(workspace_context)]
) -> dict:
    """Queue an explicit, audited manual occurrence without bypassing the worker lease."""
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        return dict(
            job_id=schedules.queue_now(context.workspace, context.email, schedule_id),
            status="Queued",
        )
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc


@app.post("/v1/evidence-collection-jobs/{job_id}/cancel")
def evidence_collection_cancel(
    job_id: int, context: Annotated[WorkspaceContext, Depends(workspace_context)]
) -> dict:
    """Cancel an owned collection and reject subsequent publication under its token."""
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        schedules.cancel_job(context.workspace, context.email, job_id)
        return dict(job_id=job_id, status="Cancelled")
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc


@app.get("/v1/evidence-collection-jobs/{job_id}")
def evidence_collection_history(
    job_id: int, context: Annotated[WorkspaceContext, Depends(workspace_context)]
) -> dict:
    """Return owned durable job/attempt diagnostics and evidence references without raw artifacts."""
    from securescope.persistence import evidence_schedule_repository as schedules

    try:
        return schedules.job_history(context.workspace, context.email, job_id)
    except EvidenceRepositoryError as exc:
        raise _service_error(exc) from exc
