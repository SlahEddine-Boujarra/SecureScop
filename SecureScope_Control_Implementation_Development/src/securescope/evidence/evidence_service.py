"""Business rules for collection, manual submission and consultant review."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from securescope.evidence.models import (
    CollectionMethod,
    ReviewDecision,
    WorkspaceRole,
    role_can,
)
from securescope.evidence.normalization import normalize_report
from securescope.evidence.storage import store_artifact
from securescope.evidence.tool_catalog import get_tool
from securescope.grc.control_catalog import ISO_CONTROL_CATALOG
from securescope.persistence.db_service import get_client_id
from securescope.persistence.evidence_repository import (
    create_evidence_record,
    create_evidence_request,
    review_evidence_record,
)
from securescope.persistence.exposure_repository import (
    ExposureRepositoryError,
    synchronize_findings_from_history,
)

LOGGER = logging.getLogger(__name__)


class EvidenceServiceError(RuntimeError):
    """Raised when evidence violates workflow or authorization rules."""


def _require(role: WorkspaceRole | str, capability: str) -> None:
    """Enforce a workspace capability at the service boundary."""

    if not role_can(role, capability):
        raise EvidenceServiceError(f"The {role} role cannot perform '{capability}'.")


def suggested_controls_for_tool(tool_id: str) -> tuple[str, ...]:
    """Return conservative catalog suggestions, never final mappings."""

    source = get_tool(tool_id)
    return source.iso_control_ids


def _correlate_report_findings(
    client_name: str,
    evidence_id: int,
    *,
    tool_id: str,
    normalized: Any,
    fallback_asset: str,
) -> None:
    """Feed technical observations into the existing canonical finding model."""

    findings: list[dict[str, Any]] = []
    for observation in normalized.observations:
        is_security_finding = (
            not observation.observation_id.startswith("observation-")
            or observation.severity in {"Critical", "High", "Medium", "Low"}
            or bool(observation.references)
        )
        if not is_security_finding:
            continue
        asset = observation.asset or fallback_asset
        if not asset:
            continue
        payload = dict(observation.attributes)
        payload.update(
            {
                "observation_id": observation.observation_id,
                "id": observation.observation_id,
                "title": observation.title,
                "severity": observation.severity,
                "host": asset,
                "description": observation.description,
                "references": list(observation.references),
                "scanner_engine": tool_id,
            }
        )
        findings.append(payload)
    if not findings:
        return
    history = [
        {
            "report_id": f"evidence-{evidence_id}",
            "scanner_engine": tool_id,
            "scanned_at": normalized.parsed_at.isoformat(),
            "asset_ip": fallback_asset,
            "findings": findings,
        }
    ]
    try:
        synchronize_findings_from_history(client_name, history)
    except (ExposureRepositoryError, ValueError) as exc:
        # Evidence remains valid even if exposure correlation is temporarily unavailable.
        LOGGER.warning(
            "Evidence %s stored but finding correlation was unavailable: %s",
            evidence_id,
            exc,
        )


def ingest_report(
    client_name: str,
    *,
    role: WorkspaceRole | str,
    tool_id: str,
    filename: str,
    content: bytes,
    title: str,
    summary: str,
    scope_description: str,
    source_asset_or_system: str,
    owner: str,
    submitted_by: str,
    collected_at: datetime | None = None,
    acceptable_age_days: int = 90,
    confidence: str = "Medium",
    format_hint: str | None = None,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> int:
    """Normalize, store and queue an imported report for consultant review."""

    _require(role, "import")
    if acceptable_age_days <= 0 or acceptable_age_days > 3_650:
        raise EvidenceServiceError("Evidence age must be between 1 and 3650 days.")
    source = get_tool(tool_id)
    normalized = normalize_report(
        source.tool_id,
        filename,
        content,
        format_hint=format_hint,
    )
    client_id = get_client_id(client_name, create=False)
    artifact = store_artifact(client_id, filename, content)
    timestamp = collected_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    evidence_id = create_evidence_record(
        client_name,
        engagement_id=engagement_id,
        scope_id=scope_id,
        tool_id=source.tool_id,
        collection_method=CollectionMethod.REPORT_IMPORT.value,
        evidence_type="Technical report",
        title=title,
        summary=summary,
        scope_description=scope_description,
        source_asset_or_system=source_asset_or_system,
        owner=owner,
        submitted_by=submitted_by,
        collected_at=timestamp,
        expires_at=timestamp + timedelta(days=acceptable_age_days),
        confidence=confidence,
        normalized=normalized,
        suggested_controls=suggested_controls_for_tool(source.tool_id),
        artifact=artifact,
    )
    _correlate_report_findings(
        client_name,
        evidence_id,
        tool_id=source.tool_id,
        normalized=normalized,
        fallback_asset=source_asset_or_system,
    )
    return evidence_id


def ingest_collector_output(
    client_name: str,
    *,
    tool_id: str,
    filename: str,
    content: bytes,
    requested_by: str,
    target: str,
    acceptable_age_days: int = 90,
    format_hint: str | None = None,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> int:
    """Persist generic defensive collection output pending human validation.

    Optional engagement and scope identifiers retain the requesting member's
    context through the canonical repository. They must be supplied together.
    This path does not grant system verification or consultant approval.
    """

    from securescope.persistence.evidence_repository import get_workspace_role

    membership = get_workspace_role(client_name, requested_by)
    if not membership or not role_can(WorkspaceRole(membership), "submit"):
        raise EvidenceServiceError("Collector ingestion requires an authorized requesting member.")
    source = get_tool(tool_id)
    if source.execution_policy.value != "defensive_only":
        raise EvidenceServiceError(f"{source.name} is not a defensive worker collector.")
    normalized = normalize_report(tool_id, filename, content, format_hint=format_hint)
    client_id = get_client_id(client_name, create=False)
    artifact = store_artifact(client_id, filename, content)
    timestamp = datetime.now(timezone.utc)
    evidence_id = create_evidence_record(
        client_name,
        tool_id=tool_id,
        collection_method=CollectionMethod.DEFENSIVE_CLI.value,
        evidence_type="Automated technical evidence",
        title=f"{source.name} defensive collection",
        summary=(
            f"Automated {source.name} report collected for the authorized target. "
            "Consultant validation is required before assessment use."
        ),
        scope_description=f"Authorized collector target: {target}",
        source_asset_or_system=target,
        owner=requested_by,
        submitted_by=requested_by,
        collected_at=timestamp,
        expires_at=timestamp + timedelta(days=acceptable_age_days),
        confidence="Medium",
        normalized=normalized,
        suggested_controls=suggested_controls_for_tool(tool_id),
        artifact=artifact,
        engagement_id=engagement_id,
        scope_id=scope_id,
    )
    _correlate_report_findings(
        client_name,
        evidence_id,
        tool_id=tool_id,
        normalized=normalized,
        fallback_asset=target,
    )
    return evidence_id


def submit_manual_evidence(
    client_name: str,
    *,
    role: WorkspaceRole | str,
    control_ids: Sequence[str],
    evidence_type: str,
    title: str,
    summary: str,
    scope_description: str,
    source_asset_or_system: str,
    owner: str,
    submitted_by: str,
    collected_at: datetime | None = None,
    acceptable_age_days: int = 365,
    attachment_filename: str | None = None,
    attachment_content: bytes | None = None,
    engagement_id: int | None = None,
    scope_id: int | None = None,
) -> int:
    """Submit document, interview, observation or record evidence manually."""

    _require(role, "submit")
    controls = tuple(sorted(set(str(item).strip() for item in control_ids if str(item).strip())))
    invalid = [item for item in controls if item not in ISO_CONTROL_CATALOG]
    if not controls or invalid:
        raise EvidenceServiceError(
            "Manual evidence requires valid ISO clause/control identifiers"
            + (f": {', '.join(invalid)}" if invalid else ".")
        )
    if acceptable_age_days <= 0 or acceptable_age_days > 3_650:
        raise EvidenceServiceError("Evidence age must be between 1 and 3650 days.")
    artifact = None
    if attachment_filename or attachment_content:
        if not attachment_filename or not attachment_content:
            raise EvidenceServiceError("Manual attachment requires both a filename and content.")
        client_id = get_client_id(client_name, create=False)
        artifact = store_artifact(client_id, attachment_filename, attachment_content)
    timestamp = collected_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    normalized: Mapping[str, Any] = {
        "tool_id": "manual",
        "format_name": "manual",
        "source_filename": attachment_filename or "",
        "parsed_at": datetime.now(timezone.utc).isoformat(),
        "observations": [],
        "metadata": {
            "evidence_type": evidence_type,
            "consultant_validation_required": True,
        },
    }
    return create_evidence_record(
        client_name,
        engagement_id=engagement_id,
        scope_id=scope_id,
        tool_id="manual",
        collection_method=CollectionMethod.MANUAL.value,
        evidence_type=evidence_type,
        title=title,
        summary=summary,
        scope_description=scope_description,
        source_asset_or_system=source_asset_or_system,
        owner=owner,
        submitted_by=submitted_by,
        collected_at=timestamp,
        expires_at=timestamp + timedelta(days=acceptable_age_days),
        confidence="Medium",
        normalized=normalized,
        suggested_controls=controls,
        artifact=artifact,
    )


def consultant_review(
    client_name: str,
    evidence_id: int,
    *,
    role: WorkspaceRole | str,
    decision: ReviewDecision | str,
    validator: str,
    comment: str,
    approved_controls: Sequence[str],
) -> None:
    """Approve/reject evidence without changing a final control assessment."""

    _require(role, "review")
    resolved_role = role if isinstance(role, WorkspaceRole) else WorkspaceRole(str(role))
    if resolved_role not in {WorkspaceRole.CONSULTANT, WorkspaceRole.ADMINISTRATOR}:
        raise EvidenceServiceError("Only a Consultant or Administrator may validate evidence.")
    invalid = [item for item in approved_controls if item not in ISO_CONTROL_CATALOG]
    if invalid:
        raise EvidenceServiceError(f"Unsupported control mappings: {', '.join(invalid)}")
    review_evidence_record(
        client_name,
        evidence_id,
        decision=decision,
        validator=validator,
        comment=comment,
        approved_controls=approved_controls,
    )


def request_manual_evidence(
    client_name: str,
    *,
    role: WorkspaceRole | str,
    control_id: str,
    title: str,
    requested_evidence: str,
    assigned_to: str,
    due_date: date,
    requested_by: str,
) -> int:
    """Request missing manual or hybrid evidence from a client contributor."""

    _require(role, "review")
    if control_id not in ISO_CONTROL_CATALOG:
        raise EvidenceServiceError(f"Unsupported control: {control_id}")
    return create_evidence_request(
        client_name,
        control_id=control_id,
        title=title,
        requested_evidence=requested_evidence,
        assigned_to=assigned_to,
        due_date=due_date,
        requested_by=requested_by,
    )


def ingest_nuclei_scan_output(
    client_name: str,
    *,
    job_uuid: str,
    attempt_number: int,
    report_id: str,
    asset_ip: str,
    profile: str,
    collected_at: datetime,
    content: bytes,
    successful: bool,
) -> int:
    """Ingest existing successful worker JSONL once; never execute a scanner.

    Args:
        client_name: Job workspace.
        job_uuid: Persistent Nuclei job identity.
        attempt_number: Persistent attempt, stable across finalization retries.
        report_id: Existing scanner report identity.
        asset_ip: Canonical job asset address.
        profile: Executed scan profile.
        collected_at: Successful completion timestamp with timezone.
        content: Original JSONL bytes, including valid empty output.
        successful: Worker completion result; failures are rejected.
    Returns:
        Canonical evidence ID (the existing ID on a finalization retry).
    Raises:
        EvidenceServiceError: Incomplete, malformed or unidentifiable collection.
        EvidenceRepositoryError: Missing job/asset or persistence failure.
        EvidenceStorageError: Artifact storage failure.
    """
    from securescope.evidence.automated_checks import SCAN_COMPLETED, classify_nuclei
    from securescope.persistence.evidence_repository import resolve_nuclei_asset
    from securescope.reporting.nuclei_report import parse_nuclei_jsonl

    if not successful or not job_uuid or attempt_number < 1 or collected_at.tzinfo is None:
        raise EvidenceServiceError("A successful identifiable Nuclei collection is required.")
    findings, summary = parse_nuclei_jsonl(content, report_id=report_id, asset_ip=asset_ip)
    if summary["invalid_jsonl_lines"]:
        raise EvidenceServiceError(
            "Nuclei output has invalid JSONL lines; collection cannot be verified."
        )
    asset = resolve_nuclei_asset(client_name, asset_ip)
    asset_id = int(asset["id"])
    checks = {SCAN_COMPLETED.check_id: SCAN_COMPLETED.to_dict()}
    observations = []
    for index, finding in enumerate(findings):
        matches = classify_nuclei(finding["Template ID"], finding["Tags"])
        for check in matches:
            checks[check.check_id] = check.to_dict()
        observations.append(
            dict(
                observation_id=f"{report_id}:{index}",
                title=finding["Finding"],
                severity=finding["Severity"],
                asset=asset_ip,
                description=finding["Description"],
                attributes={
                    "template_id": finding["Template ID"],
                    "tags": finding["Tags"],
                    "automated_checks": [c.to_dict() for c in matches],
                },
            )
        )
    source = dict(
        job_uuid=job_uuid,
        attempt_number=attempt_number,
        report_id=report_id,
        asset_id=asset_id,
        asset_tag=asset.get("asset_tag"),
        profile=profile,
        checks=list(checks.values()),
    )
    normalized = dict(
        tool_id="nuclei",
        format_name="jsonl",
        source_filename="findings.jsonl",
        parsed_at=collected_at.isoformat(),
        observations=observations,
        metadata={
            "assurance": {"complete": True, "asset_ids": [asset_id], "asset_ips": [asset_ip]},
            "provenance": source,
            "automated_checks": list(checks.values()),
        },
    )

    def persist_artifact(client_id: int):
        """Store raw output once after repository provenance and identity checks.

        Args:
            client_id: Verified tenant identifier from the repository transaction.
        Returns:
            StoredArtifact for the canonical evidence record.
        Raises:
            EvidenceStorageError: If artifact storage fails.
        """
        return store_artifact(client_id, "findings.jsonl", content, allow_empty=True)

    return create_evidence_record(
        client_name,
        tool_id="nuclei",
        collection_method="Existing worker",
        evidence_type="Automated technical evidence",
        title=f"Nuclei Scan — {asset.get('asset_tag') or asset_ip}",
        summary=(
            f"Completed vulnerability assessment; {len(observations)} observations. "
            "Collection is not a compliance conclusion."
        ),
        scope_description="Scopes resolved from configured control requirement assets.",
        source_asset_or_system=asset_ip,
        owner="system:nuclei-worker",
        submitted_by="system:nuclei-worker",
        collected_at=collected_at,
        expires_at=collected_at + timedelta(days=90),
        confidence="Medium",
        normalized=normalized,
        suggested_controls=sorted(
            {control for c in checks.values() for control in c["mapped_controls"]}
        ),
        artifact_factory=persist_artifact,
        system_source=source,
    )
