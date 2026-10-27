"""Evidence-based evaluation of existing Control Profiles; no second control model."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from securescope.core.gap_assessment_domain import ASSURANCE_DIMENSIONS
from securescope.evidence.automated_checks import usable_evidence
from securescope.evidence.freshness import evidence_freshness

ENGINE_VERSION = 1
POSITIVE = {"Implemented and effective", "Target achieved"}


def input_fingerprint(bundle: Mapping[str, Any]) -> str:
    """Fingerprint the saved records used for a decision.

    Args:
        bundle: Client-scoped repository inputs.
    Returns:
        Deterministic SHA-256 digest.
    Raises:
        TypeError: If input keys cannot be serialized.
    """
    return hashlib.sha256(json.dumps(bundle, sort_keys=True, default=str).encode()).hexdigest()


def as_datetime(value: Any) -> datetime | None:
    """Normalize persisted timestamps without treating invalid dates as current.

    Args:
        value: ISO timestamp, date, datetime or null.
    Returns:
        A timezone-aware datetime, or None.
    Raises:
        No exceptions are raised for invalid dates.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def reference_tokens(value: Any) -> set[str]:
    """Split reference lists using the existing assessment editor convention.

    Args:
        value: A semicolon-separated reference string.
    Returns:
        Exact nonempty references; substring matches are never used.
    Raises:
        No exceptions are raised.
    """
    return {part.strip() for part in str(value or "").split(";") if part.strip()}


def evaluate_implementation(bundle: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Explain implementation from versioned records and current evidence.

    Args:
        bundle: Trusted profile, scope, assessment, document and evidence records.
        now: Explicit timezone-aware evaluation time.
    Returns:
        Conservative status, reasons, timestamp, engine version and fingerprint.
    Raises:
        ValueError: If evaluation time has no timezone.
        KeyError: If the repository omits the required profile.
    """
    if now.tzinfo is None:
        raise ValueError("Evaluation time requires a timezone.")
    checks = []

    def check(name: str, passed: bool, reason: str) -> None:
        """Append an explainable gate.

        Args:
            name: Visible check label.
            passed: Whether saved inputs satisfy the check.
            reason: Human-readable requirement.
        Returns:
            None.
        Raises:
            No exceptions are raised.
        """
        checks.append(dict(name=name, passed=bool(passed), explanation=reason))

    def result(status: str) -> dict:
        """Construct the evaluation result without mutating source records.

        Args:
            status: Conservative implementation conclusion.
        Returns:
            Versioned result and explanations.
        Raises:
            TypeError: If input serialization fails.
        """
        return dict(
            status=status,
            checks=checks,
            engine_version=ENGINE_VERSION,
            evaluated_at=now.isoformat(),
            input_fingerprint=input_fingerprint(bundle),
            verification="Manual evidence evaluation; future scripts are not required",
        )

    profile = bundle["profile"]
    config = (profile.get("assessment_scope") or {}).get("implementation_requirements") or {}
    assessment = bundle.get("assessment") or {}
    soa = bundle.get("soa") or {}
    if (
        profile["control_id"].startswith("A.")
        and soa.get("applicability") == "Not applicable"
        and soa.get("approved") is True
        and str(soa.get("exclusion_justification") or "").strip()
    ):
        check("Applicability", True, "An approved justified SoA exclusion is recorded.")
        return result("Not Applicable")
    if (
        profile.get("applicability") == "Not applicable"
        or soa.get("applicability") == "Not applicable"
    ):
        check("Applicability", False, "Exclusion requires an approved justified SoA decision.")
        return result("Verification Pending")
    check(
        "Requirements",
        config.get("reviewed") is True,
        "Review and save implementation criteria and document requirements for this profile.",
    )
    check(
        "Owner",
        bool(str(profile.get("control_owner") or "").strip()),
        "Record an accountable control owner.",
    )
    scope = bundle.get("scope") or {}
    check(
        "Scope version",
        bool(scope)
        and scope.get("status") == "Approved"
        and scope.get("id") == config.get("scope_version_id"),
        "Requirements must reference the current approved ISMS scope version.",
    )
    if not assessment:
        check("Assessment", False, "No assessment exists for this profile version.")
        return result("Not Assessed")
    target = bundle.get("target") or {}
    check(
        "Target version",
        bool(target) and assessment.get("target_id") == target.get("id"),
        "The assessment must use the latest approved target for this profile.",
    )
    check(
        "Authorized validation",
        assessment.get("validation_status") == "Validated"
        and bool(bundle.get("validator_authorized")),
        "Requires saved validation by an active authorized reviewer.",
    )
    days = config.get("review_days", 90)
    if type(days) is not int or not 1 <= days <= 3650:
        days = 90
    cutoff = now - timedelta(days=days)
    assessed_at = as_datetime(assessment.get("created_at"))
    check(
        "Assessment currency",
        assessed_at is not None and cutoff <= assessed_at <= now,
        f"Assessment and evidence observations must be within {days} days.",
    )
    usable = []
    for evidence in bundle.get("evidence", []):
        currency = evidence_freshness(
            dict(
                evidence,
                collected_at=evidence.get("collection_date"),
                expires_at=evidence.get("expiration_date"),
            ),
            days,
            now,
        )
        if evidence.get("validation_status") == "Validated" and currency in {
            "Current",
            "Expiring Soon",
        }:
            usable.append(evidence)
    refs = {ref for e in usable for ref in reference_tokens(e.get("raw_evidence_reference"))}
    check(
        "Current evidence",
        bool(refs),
        "Requires current validated evidence attached to this assessment and traceable references.",
    )
    for linked in bundle.get("linked_evidence", []):
        check(
            f"Evidence hub #{linked['id']}",
            usable_evidence(linked, {str(linked.get("tool_id") or "").lower()})
            and evidence_freshness(linked, days, now) in {"Current", "Expiring Soon"},
            "Linked evidence must still exist, be approved for this control and remain current.",
        )
    documents = {d["policy_id"]: d for d in bundle.get("documents", [])}
    document_gap = False
    for kind in ("policy", "procedure"):
        links = config.get(kind + "_links", [])
        check(
            kind.title() + " requirements",
            bool(links) or bool(str(config.get(kind + "_rationale") or "").strip()),
            "Link required documents or explain why a separate document is unnecessary.",
        )
        for link in links:
            doc = documents.get(link["id"], {})
            review_date = as_datetime(doc.get("review_date"))
            valid = (
                doc.get("status") == "Approved"
                and doc.get("policy_version") == link["version"]
                and profile["control_id"] in (doc.get("controls") or [])
                and (
                    not doc.get("review_date") or (review_date and review_date.date() >= now.date())
                )
            )
            document_gap |= not valid
            check(
                f"{kind.title()}: {doc.get('title') or link['id']}",
                valid,
                "Requires the linked approved version, control mapping and current review date.",
            )
    criteria = [c for c in bundle.get("criteria", []) if c.get("required", True)]
    declared = config.get("criteria", [])
    descriptions = [str(c.get("description") or "").strip() for c in criteria]
    check(
        "Declared criteria",
        bool(declared)
        and set(declared).issubset(descriptions)
        and len(descriptions) == len(set(descriptions)),
        "Every declared criterion must be assessed without duplicate results.",
    )
    evidenced = [
        c
        for c in criteria
        if c.get("validation_status") == "Validated"
        and reference_tokens(c.get("evidence_reference"))
        and reference_tokens(c.get("evidence_reference")).issubset(refs)
    ]
    check(
        "Criterion evidence",
        bool(criteria) and len(evidenced) == len(criteria),
        "Every required criterion needs validated results citing this "
        "assessment's current evidence.",
    )
    if any(not c["passed"] and not c["name"].startswith(("Policy:", "Procedure:")) for c in checks):
        return result("Verification Pending")
    outcomes = [c.get("result") for c in evidenced]
    if any(value not in {"Pass", "Partial", "Fail"} for value in outcomes):
        check(
            "Criterion conclusions", False, "Resolve unassessed or unexplained excluded criteria."
        )
        return result("Verification Pending")
    if all(value == "Fail" for value in outcomes):
        check("Implementation criteria", False, "All required criteria have evidenced failures.")
        return result("Not Implemented")
    if document_gap or any(value != "Pass" for value in outcomes):
        check("Implementation criteria", False, "Evidence demonstrates incomplete requirements.")
        return result("Partially Implemented")
    dimensions = {d["dimension"]: d for d in bundle.get("dimensions", [])}
    for name in ASSURANCE_DIMENSIONS:
        dimension = dimensions.get(name, {})
        check(
            name,
            dimension.get("status") in POSITIVE
            and dimension.get("validation_status") == "Validated",
            "Requires a validated positive conclusion for this assurance dimension.",
        )
    if any(
        d.get("validation_status") == "Validated"
        and d.get("status") in {"Not implemented", "Partially implemented", "Gap identified"}
        for d in dimensions.values()
    ):
        return result("Partially Implemented")
    latest = max(
        bundle.get("tests", []),
        key=lambda t: (str(t.get("test_date") or ""), t.get("id", 0)),
        default={},
    )
    tested_at = as_datetime(latest.get("test_date"))
    current_test = (
        tested_at is not None
        and cutoff.date() <= tested_at.date() <= now.date()
        and bool(reference_tokens(latest.get("evidence_reference")))
        and reference_tokens(latest.get("evidence_reference")).issubset(refs)
    )
    if current_test and latest.get("result") in {"Failed", "Partially successful"}:
        check("Operating test", False, "The latest evidenced test reports an operating gap.")
        return result("Partially Implemented")
    check(
        "Operating test",
        current_test
        and latest.get("result") == "Successful"
        and not latest.get("retest_required")
        and not str(latest.get("exceptions") or "").strip(),
        "Requires a current successful test without unresolved exceptions or required retesting.",
    )
    check(
        "Assessment conclusion",
        assessment.get("assessment_status") in POSITIVE,
        "The authorized assessment must agree with its supporting implementation evidence.",
    )
    return result("Implemented" if all(c["passed"] for c in checks) else "Verification Pending")
