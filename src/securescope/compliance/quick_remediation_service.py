"""Deterministic, low-effort vulnerability remediation preparation.

Scanner text is used only as advisory input. This module never returns an
executable command and never changes a finding lifecycle state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from securescope.core.finding_domain import finding_value, normalize_severity, severity_rank

EXECUTION_LEVELS = (
    "Guided manual",
    "Prepared automation",
    "Approved execution",
)
REMEDIATION_EXECUTION_STATUSES = (
    "Draft",
    "Ready",
    "Awaiting approval",
    "Approved",
    "Running",
    "Pending restart",
    "Pending verification",
    "Verified",
    "Failed",
    "Rolled back",
    "Risk accepted",
)
PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
INFORMATIONAL_SEVERITIES = frozenset({"Info", "Informational"})


class QuickRemediationError(ValueError):
    """Raised when deterministic remediation input is unsafe or incomplete."""


@dataclass(frozen=True)
class RemediationPriority:
    """Transparent risk-based remediation priority.

    Args:
        label: Critical, High, Medium, or Low.
        score: Bounded score from 0 to 100.
        reasons: Human-readable factors used in the calculation.
        sla_days: Suggested completion SLA.

    Returns:
        Immutable priority result.

    Raises:
        QuickRemediationError: If the calculated result is inconsistent.
    """

    label: str
    score: float
    reasons: tuple[str, ...]
    sla_days: int

    def __post_init__(self) -> None:
        """Validate the priority result.

        Returns:
            None.

        Raises:
            QuickRemediationError: If label, score, or SLA is invalid.
        """

        if self.label not in PRIORITY_LABELS:
            raise QuickRemediationError(f"Unsupported priority: {self.label}")
        if not 0 <= float(self.score) <= 100 or int(self.sla_days) <= 0:
            raise QuickRemediationError("Priority score or SLA is invalid.")


@dataclass(frozen=True)
class RemediationCandidate:
    """One grouped remediation candidate preserving every finding and asset.

    Args:
        group_key: Stable hash of vulnerability identity and normalized action.
        title: Human-readable finding or group title.
        vulnerability_identity: Canonical CVE, NVT, or template identity.
        finding_ids: Canonical finding identifiers retained in the group.
        assets: Affected asset identities retained in the group.
        priority: Risk-based deterministic priority.
        recommended_action: Non-executable recommended change.
        validation_method: Required post-change validation.
        expected_evidence: Evidence required before closure.
        execution_level: Safest available execution level.
        recipe_id: Optional matched allow-listed recipe.
        kev: Known-exploited state, or ``None`` when not enriched.
        epss: Highest EPSS value, or ``None`` when not enriched.
        due_date: Suggested due date.

    Returns:
        Immutable candidate consumed by the Streamlit UI.

    Raises:
        QuickRemediationError: If required identities or linkage are missing.
    """

    group_key: str
    title: str
    vulnerability_identity: str
    finding_ids: tuple[int, ...]
    assets: tuple[str, ...]
    priority: RemediationPriority
    recommended_action: str
    validation_method: str
    expected_evidence: tuple[str, ...]
    execution_level: str
    recipe_id: str | None
    kev: bool | None
    epss: float | None
    due_date: date

    def __post_init__(self) -> None:
        """Validate candidate scope and safe execution metadata.

        Returns:
            None.

        Raises:
            QuickRemediationError: If identities, findings, assets, or level are invalid.
        """

        if not self.group_key or not self.vulnerability_identity:
            raise QuickRemediationError("A candidate requires stable identity.")
        if not self.finding_ids or not self.assets:
            raise QuickRemediationError("A candidate requires at least one finding and one asset.")
        if self.execution_level not in EXECUTION_LEVELS:
            raise QuickRemediationError(f"Unsupported execution level: {self.execution_level}")

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-safe candidate representation.

        Returns:
            Candidate fields suitable for tables and audit records.

        Raises:
            ValueError: Never raised for a validated candidate.
        """

        return {
            "group_key": self.group_key,
            "title": self.title,
            "vulnerability_identity": self.vulnerability_identity,
            "finding_ids": list(self.finding_ids),
            "assets": list(self.assets),
            "priority": self.priority.label,
            "priority_score": self.priority.score,
            "priority_reasons": list(self.priority.reasons),
            "recommended_action": self.recommended_action,
            "validation_method": self.validation_method,
            "expected_evidence": list(self.expected_evidence),
            "execution_level": self.execution_level,
            "recipe_id": self.recipe_id,
            "kev": self.kev,
            "epss": self.epss,
            "due_date": self.due_date.isoformat(),
        }


def _optional_float(value: Any) -> float | None:
    """Convert a value to float without inventing unavailable data.

    Args:
        value: Optional numeric value.

    Returns:
        Float or ``None`` when the value is absent or invalid.

    Raises:
        ValueError: Never raised for normal values.
    """

    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _age_days(value: Any, now: datetime | None = None) -> int:
    """Calculate non-negative finding age from an ISO/datetime value.

    Args:
        value: First-seen timestamp.
        now: Optional UTC comparison time for deterministic tests.

    Returns:
        Age in whole days, or zero when the timestamp is unavailable.

    Raises:
        ValueError: Never raised for malformed scanner timestamps.
    """

    if not value:
        return 0
    try:
        observed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except (TypeError, ValueError):
        return 0
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0, (reference - observed.astimezone(timezone.utc)).days)


def severity_default_priority(severity: Any) -> str:
    """Map scanner severity to a conservative default remediation priority.

    Args:
        severity: Scanner or canonical severity.

    Returns:
        Critical, High, Medium, or Low.

    Raises:
        ValueError: Never raised for normal values.
    """

    normalized = normalize_severity(severity)
    return {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Low",
        "Unknown": "Low",
    }.get(normalized, "Low")


def calculate_remediation_priority(
    finding: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> RemediationPriority:
    """Calculate transparent risk priority without severity inflation.

    Args:
        finding: Canonical finding and optional threat/asset context.
        now: Optional UTC time used for deterministic age calculations.

    Returns:
        Priority, score, reasons, and suggested SLA.

    Raises:
        QuickRemediationError: If ``finding`` is not a mapping.
    """

    if not isinstance(finding, Mapping):
        raise QuickRemediationError("Finding priority input must be a mapping.")
    severity = normalize_severity(finding.get("severity"))
    cvss = _optional_float(finding.get("cvss"))
    epss = _optional_float(finding.get("epss_score"))
    kev_value = finding.get("kev_known_exploited")
    kev = kev_value is True
    criticality = str(finding.get("asset_criticality") or finding.get("criticality") or "").strip()
    exposed = finding.get("externally_exposed") is True
    age = _age_days(finding.get("first_seen"), now)

    severity_points = {
        "Critical": 48,
        "High": 38,
        "Medium": 25,
        "Low": 12,
        "Info": 2,
        "Unknown": 5,
    }.get(severity, 5)
    score = float(severity_points)
    reasons = [f"Severity {severity}"]
    if cvss is not None:
        score += max(0.0, min(10.0, cvss)) * 1.8
        reasons.append(f"CVSS {cvss:.1f}")
    if kev:
        score += 32
        reasons.append("CISA KEV")
    if epss is not None:
        score += max(0.0, min(1.0, epss)) * 22
        reasons.append(f"EPSS {epss:.1%}")
    if criticality in {"Critical", "High"}:
        score += 8 if criticality == "Critical" else 5
        reasons.append(f"{criticality} asset criticality")
    if exposed:
        score += 8
        reasons.append("Externally exposed")
    if age >= 90:
        score += 6
        reasons.append("Older than 90 days")
    elif age >= 30:
        score += 3
        reasons.append("Older than 30 days")
    score = round(min(100.0, score), 1)

    # A Low/Info finding is never promoted to Critical from score alone. Only
    # confirmed KEV context can justify that escalation.
    if kev or (severity == "Critical" and score >= 78):
        label, sla_days = "Critical", 7
    elif score >= 62 or severity == "High":
        label, sla_days = "High", 14
    elif score >= 34 or severity == "Medium":
        label, sla_days = "Medium", 30
    else:
        label, sla_days = "Low", 90
    return RemediationPriority(label, score, tuple(reasons), sla_days)


def scanner_recommended_action(finding: Mapping[str, Any]) -> str:
    """Extract non-executable OpenVAS/Nuclei remediation guidance.

    Args:
        finding: Canonical finding with ``most_recent_evidence`` when available.

    Returns:
        Scanner/vendor guidance or a deterministic safe fallback.

    Raises:
        QuickRemediationError: If the finding is not a mapping.
    """

    if not isinstance(finding, Mapping):
        raise QuickRemediationError("Remediation input must be a mapping.")
    evidence = finding.get("most_recent_evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    action = finding_value(
        evidence,
        "solution",
        "remediation",
        "recommended_action",
        "fix",
    )
    if action:
        return " ".join(str(action).split())[:4000]
    identity = str(finding.get("vulnerability_identity") or "the identified vulnerability")
    component = str(finding.get("component") or "affected component")
    return (
        f"Apply the vendor-supported security update, upgrade, configuration "
        f"change, or isolation guidance for {identity} on {component}. Do not "
        "execute scanner text directly; validate the exact product and version first."
    )


def _action_signature(value: str) -> str:
    """Return a stable grouping signature for advisory remediation text.

    Args:
        value: Recommended remediation action.

    Returns:
        Normalized hash component.

    Raises:
        ValueError: Never raised for normal text.
    """

    normalized = re.sub(r"\s+", " ", str(value or "").strip().casefold())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]


def group_remediation_candidates(
    findings: Iterable[Mapping[str, Any]],
    *,
    recipe_matcher: Any | None = None,
    today: date | None = None,
) -> list[RemediationCandidate]:
    """Group matching findings while preserving each asset/finding link.

    Args:
        findings: Workspace-scoped canonical finding rows.
        recipe_matcher: Optional callable returning a recipe object or ``None``.
        today: Optional comparison date for deterministic tests.

    Returns:
        Ordered remediation groups. Informational findings are excluded.

    Raises:
        QuickRemediationError: If a row lacks a valid identifier.
    """

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    actions: dict[str, str] = {}
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        if severity in INFORMATIONAL_SEVERITIES:
            continue
        finding_id = finding.get("id")
        identity = str(finding.get("vulnerability_identity") or "").strip()
        asset = str(finding.get("asset_identity") or "").strip()
        if not identity or not asset or finding_id in (None, ""):
            raise QuickRemediationError(
                "Canonical finding lacks ID, vulnerability identity, or asset."
            )
        action = scanner_recommended_action(finding)
        key_material = f"{identity.casefold()}|{_action_signature(action)}"
        group_key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        grouped.setdefault(group_key, []).append(finding)
        actions[group_key] = action

    candidates: list[RemediationCandidate] = []
    current_date = today or date.today()
    for group_key, rows in grouped.items():
        highest = max(rows, key=lambda row: severity_rank(row.get("severity")))
        context = dict(highest)
        context["kev_known_exploited"] = (
            True
            if any(row.get("kev_known_exploited") is True for row in rows)
            else False if all(row.get("kev_known_exploited") is False for row in rows) else None
        )
        epss_values = [
            value
            for value in (_optional_float(row.get("epss_score")) for row in rows)
            if value is not None
        ]
        context["epss_score"] = max(epss_values) if epss_values else None
        priority = calculate_remediation_priority(context)
        recipe = recipe_matcher(highest) if recipe_matcher else None
        recipe_id = getattr(recipe, "recipe_id", None) if recipe else None
        execution_level = (
            getattr(recipe, "execution_level", "Prepared automation") if recipe else "Guided manual"
        )
        candidates.append(
            RemediationCandidate(
                group_key=group_key,
                title=str(highest.get("title") or highest["vulnerability_identity"]),
                vulnerability_identity=str(highest["vulnerability_identity"]),
                finding_ids=tuple(sorted({int(row["id"]) for row in rows})),
                assets=tuple(sorted({str(row["asset_identity"]) for row in rows})),
                priority=priority,
                recommended_action=actions[group_key],
                validation_method=(
                    "Run a targeted Nuclei or OpenVAS verification scan and confirm "
                    "the original canonical identity is absent from fresh evidence."
                ),
                expected_evidence=(
                    "Approved change or patch record",
                    "Pre-check and post-check result",
                    "Fresh targeted verification scan",
                    "Authorized analyst validation",
                ),
                execution_level=execution_level,
                recipe_id=recipe_id,
                kev=context["kev_known_exploited"],
                epss=context["epss_score"],
                due_date=current_date + timedelta(days=priority.sla_days),
            )
        )
    return sorted(
        candidates,
        key=lambda item: (item.priority.score, len(item.finding_ids)),
        reverse=True,
    )


def proposal_from_candidates(
    candidates: Sequence[RemediationCandidate],
) -> dict[str, Any]:
    """Build compact plan defaults from selected remediation candidates.

    Args:
        candidates: One or more selected candidate groups.

    Returns:
        Deterministic plan fields consumed by the compact UI.

    Raises:
        QuickRemediationError: If no candidate is selected.
    """

    if not candidates:
        raise QuickRemediationError("Select at least one remediation candidate.")
    highest = max(candidates, key=lambda item: item.priority.score)
    finding_ids = sorted({finding_id for item in candidates for finding_id in item.finding_ids})
    actions = list(dict.fromkeys(item.recommended_action for item in candidates))
    validation = list(dict.fromkeys(item.validation_method for item in candidates))
    evidence = list(
        dict.fromkeys(
            evidence_item for item in candidates for evidence_item in item.expected_evidence
        )
    )
    return {
        "title": (
            highest.title
            if len(candidates) == 1
            else f"Remediate {len(candidates)} prioritized vulnerability groups"
        ),
        "finding_ids": finding_ids,
        "priority": highest.priority.label,
        "priority_reasons": list(highest.priority.reasons),
        "recommended_action": "\n\n".join(actions),
        "owner": "",
        "due_date": min(item.due_date for item in candidates),
        "sla_days": highest.priority.sla_days,
        "validation_method": "\n".join(validation),
        "expected_evidence": evidence,
        "initial_task": "Implement the reviewed remediation action",
        "verification_scan": "Nuclei targeted verification",
    }


def candidate_payload_checksum(candidate: RemediationCandidate) -> str:
    """Calculate an audit checksum for one prepared candidate.

    Args:
        candidate: Validated remediation candidate.

    Returns:
        SHA-256 digest of canonical JSON candidate data.

    Raises:
        ValueError: Never raised for a validated candidate.
    """

    payload = json.dumps(candidate.as_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
