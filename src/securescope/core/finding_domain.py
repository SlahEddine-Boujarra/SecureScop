"""Canonical vulnerability identity and lifecycle rules for SecureScope.

The module is deliberately independent from Streamlit and PostgreSQL. Scanner
workers keep their provider-specific observations, while this domain layer
groups those observations into one workspace-scoped logical finding.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

FINDING_STATUSES = (
    "New",
    "Triaged",
    "Planned",
    "In progress",
    "Mitigated",
    "Ready for verification",
    "Closed",
    "Accepted risk",
    "False positive",
    "Reopened",
)

ACTIVE_FINDING_STATUSES = frozenset(
    {
        "New",
        "Triaged",
        "Planned",
        "In progress",
        "Mitigated",
        "Ready for verification",
        "Reopened",
    }
)

TREATMENT_DECISIONS = (
    "Remediate",
    "Mitigate",
    "Accept",
    "Avoid",
    "False positive",
)

VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "New": frozenset({"Triaged", "Planned", "In progress", "Accepted risk", "False positive"}),
    "Triaged": frozenset({"Planned", "In progress", "Accepted risk", "False positive"}),
    "Planned": frozenset({"In progress", "Mitigated", "Accepted risk", "False positive"}),
    "In progress": frozenset(
        {"Mitigated", "Ready for verification", "Accepted risk", "False positive"}
    ),
    "Mitigated": frozenset({"Ready for verification", "Reopened"}),
    "Ready for verification": frozenset({"Closed", "Reopened", "In progress"}),
    "Closed": frozenset({"Reopened"}),
    "Accepted risk": frozenset({"Reopened", "In progress"}),
    "False positive": frozenset({"Reopened"}),
    "Reopened": frozenset({"Triaged", "Planned", "In progress", "Accepted risk", "False positive"}),
}

SEVERITY_ORDER = {
    "Unknown": -1,
    "Info": 0,
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_SPACE_PATTERN = re.compile(r"\s+")
_NON_ID_PATTERN = re.compile(r"[^a-z0-9._:+/-]+")


class FindingDomainError(ValueError):
    """Base exception for invalid vulnerability domain operations."""


class InvalidFindingTransitionError(FindingDomainError):
    """Raised when a finding lifecycle transition is not allowed."""


class FindingVerificationRequiredError(FindingDomainError):
    """Raised when closure lacks required evidence or authorization."""


@dataclass(frozen=True)
class FindingObservation:
    """Normalized provider observation used for canonical deduplication.

    Args:
        client_id: Owning SecureScope workspace identifier.
        fingerprint: Stable logical finding fingerprint.
        observation_key: Idempotent provider/report observation identifier.
        asset_identity: Canonical identity of the affected asset.
        vulnerability_identity: Canonical CVE or scanner vulnerability identity.
        scanner: Normalized scanner name.
        report_id: Provider report identifier when available.
        observed_at: Observation timestamp in UTC-compatible text form.
        severity: Normalized vulnerability severity.
        title: Human-readable finding title.
        port: Normalized affected port.
        protocol: Normalized transport or application protocol.
        component: Normalized affected service or component.
        raw: Original observation payload.

    Returns:
        Immutable normalized observation.

    Raises:
        FindingDomainError: If a required identity field is empty.
    """

    client_id: int
    fingerprint: str
    observation_key: str
    asset_identity: str
    vulnerability_identity: str
    scanner: str
    report_id: str
    observed_at: str
    severity: str
    title: str
    port: str
    protocol: str
    component: str
    raw: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        """Validate required immutable observation fields.

        Returns:
            None.

        Raises:
            FindingDomainError: If an identity value is missing.
        """

        required_values = {
            "fingerprint": self.fingerprint,
            "observation_key": self.observation_key,
            "asset_identity": self.asset_identity,
            "vulnerability_identity": self.vulnerability_identity,
        }
        missing = [name for name, value in required_values.items() if not value]
        if missing:
            raise FindingDomainError("Finding observation is missing: " + ", ".join(missing))


@dataclass
class CanonicalFinding:
    """One logical vulnerability with one or more scanner observations.

    Args:
        fingerprint: Stable workspace-scoped finding fingerprint.
        client_id: Owning workspace identifier.
        asset_identity: Canonical affected asset identity.
        vulnerability_identity: Canonical vulnerability identity.
        title: Preferred finding title.
        severity: Highest normalized observed severity.
        first_seen: Earliest observation timestamp.
        last_seen: Latest observation timestamp.
        observations: Provider observations grouped into this finding.
        scanners: Scanner engines that observed this finding.
        status: Current finding lifecycle status.

    Returns:
        Mutable aggregate used by dashboard and persistence synchronization.

    Raises:
        FindingDomainError: If the initial aggregate is inconsistent.
    """

    fingerprint: str
    client_id: int
    asset_identity: str
    vulnerability_identity: str
    title: str
    severity: str
    first_seen: str
    last_seen: str
    observations: list[FindingObservation] = field(default_factory=list)
    scanners: set[str] = field(default_factory=set)
    status: str = "New"

    def __post_init__(self) -> None:
        """Validate aggregate identity and status.

        Returns:
            None.

        Raises:
            FindingDomainError: If identity or lifecycle state is invalid.
        """

        if not self.fingerprint or not self.asset_identity:
            raise FindingDomainError("A canonical finding requires stable identity.")
        if self.status not in FINDING_STATUSES:
            raise FindingDomainError(f"Unknown finding status: {self.status}")

    def add_observation(self, observation: FindingObservation) -> None:
        """Add a unique observation and refresh aggregate values.

        Args:
            observation: Normalized scanner observation.

        Returns:
            None.

        Raises:
            FindingDomainError: If the observation belongs to another finding.
        """

        if observation.fingerprint != self.fingerprint:
            raise FindingDomainError("Observation fingerprint does not match finding.")
        if any(item.observation_key == observation.observation_key for item in self.observations):
            return
        self.observations.append(observation)
        self.scanners.add(observation.scanner)
        self.first_seen = min(self.first_seen, observation.observed_at)
        self.last_seen = max(self.last_seen, observation.observed_at)
        if severity_rank(observation.severity) > severity_rank(self.severity):
            self.severity = observation.severity


def normalize_identity_part(value: Any, fallback: str = "unknown") -> str:
    """Normalize an arbitrary value for deterministic identity generation.

    Args:
        value: Source value.
        fallback: Value returned when the source is empty.

    Returns:
        Lower-case normalized identity fragment.

    Raises:
        ValueError: If ``fallback`` is empty.
    """

    if not fallback:
        raise ValueError("Identity fallback cannot be empty.")
    text = _SPACE_PATTERN.sub(" ", str(value or "").strip().lower())
    text = _NON_ID_PATTERN.sub("-", text).strip("-")
    return text or fallback


def finding_value(finding: Mapping[str, Any], *keys: str) -> Any:
    """Read a scanner value using case- and separator-insensitive keys.

    OpenVAS, Greenbone and Nuclei exports do not use one common key style.  This
    accessor treats ``NVT OID``, ``nvt_oid`` and ``nvt-oid`` as equivalent while
    preserving the original raw observation.

    Args:
        finding: Raw or normalized scanner mapping.
        *keys: Candidate semantic keys in preference order.

    Returns:
        First non-empty matching value, or ``None`` when no value is present.

    Raises:
        TypeError: If ``finding`` is not a mapping.
    """

    if not isinstance(finding, Mapping):
        raise TypeError("finding must be a mapping.")
    normalized_values = {
        re.sub(r"[^a-z0-9]", "", str(key).lower()): value for key, value in finding.items()
    }
    for key in keys:
        direct = finding.get(key)
        if direct not in (None, "", [], (), {}):
            return direct
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        value = normalized_values.get(normalized)
        if value not in (None, "", [], (), {}):
            return value
    return None


def normalize_scanner(value: Any) -> str:
    """Return one stable scanner alias.

    Args:
        value: Provider or engine label.

    Returns:
        ``openvas``, ``nuclei``, ``zap`` or a normalized provider alias.

    Raises:
        ValueError: Never raised for normal stringable input.
    """

    normalized = normalize_identity_part(value, "unknown-scanner")
    if "greenbone" in normalized or "openvas" in normalized or "gvm" in normalized:
        return "openvas"
    if "nuclei" in normalized or "projectdiscovery" in normalized:
        return "nuclei"
    if normalized in {"owasp-zap", "zap"} or "zed-attack-proxy" in normalized:
        return "zap"
    return normalized


def normalize_port(value: Any) -> str:
    """Normalize a port representation without inventing a port.

    Args:
        value: Numeric port or scanner-specific port text.

    Returns:
        Numeric port text, a normalized named port, or an empty string.

    Raises:
        ValueError: Never raised for normal stringable input.
    """

    text = str(value or "").strip().lower()
    match = re.search(r"\b(\d{1,5})\b", text)
    if match and 0 <= int(match.group(1)) <= 65535:
        return match.group(1)
    return _NON_ID_PATTERN.sub("-", text).strip("-") if text else ""


def normalize_protocol(value: Any) -> str:
    """Normalize a finding protocol.

    Args:
        value: Protocol value from a scanner observation.

    Returns:
        Normalized protocol, defaulting to ``unknown``.

    Raises:
        ValueError: Never raised for normal stringable input.
    """

    normalized = normalize_identity_part(value, "unknown")
    aliases = {
        "transmission-control-protocol": "tcp",
        "user-datagram-protocol": "udp",
        "http": "tcp",
        "https": "tcp",
        "ssl": "tcp",
        "tls": "tcp",
        "websocket": "tcp",
    }
    return aliases.get(normalized, normalized)


def normalize_severity(value: Any) -> str:
    """Normalize severity text or a numeric CVSS-like value.

    Args:
        value: Scanner severity label or numeric value.

    Returns:
        Critical, High, Medium, Low, Info or Unknown.

    Raises:
        ValueError: Never raised; malformed values become Unknown.
    """

    text = str(value or "").strip().lower()
    labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    if text in labels:
        return labels[text]
    try:
        score = float(text)
    except (TypeError, ValueError):
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info" if score == 0 else "Unknown"


def severity_rank(value: Any) -> int:
    """Return the ordering rank for a severity value.

    Args:
        value: Severity label or numeric value.

    Returns:
        Integer ordering rank.

    Raises:
        ValueError: Never raised for normal input.
    """

    return SEVERITY_ORDER.get(normalize_severity(value), -1)


def canonical_asset_identity(asset: Mapping[str, Any] | str) -> str:
    """Build a stable asset identity within one workspace.

    Args:
        asset: Asset mapping or IP/identifier string.

    Returns:
        Prefixed normalized UUID, database ID, IP, asset tag, or fallback.

    Raises:
        FindingDomainError: If no usable identity is available.
    """

    if isinstance(asset, str):
        data: Mapping[str, Any] = {"ip": asset}
    else:
        data = asset
    for key, prefix in (
        ("asset_uuid", "uuid"),
        ("asset_id", "id"),
        ("id", "id"),
    ):
        value = str(finding_value(data, key) or "").strip()
        if value:
            return f"{prefix}:{normalize_identity_part(value)}"
    ip_value = str(finding_value(data, "asset_ip", "ip") or "").strip()
    if ip_value:
        try:
            return f"ip:{ipaddress.ip_address(ip_value).compressed.lower()}"
        except ValueError:
            return f"host:{normalize_identity_part(ip_value)}"
    asset_tag = str(finding_value(data, "asset_tag") or "").strip()
    if asset_tag:
        return f"tag:{normalize_identity_part(asset_tag)}"
    hostname = str(finding_value(data, "hostname", "host") or "").strip()
    if hostname:
        return f"host:{normalize_identity_part(hostname)}"
    raise FindingDomainError("Finding observation has no canonical asset identity.")


def extract_cves(finding: Mapping[str, Any]) -> list[str]:
    """Extract sorted unique CVE identifiers from a finding payload.

    Args:
        finding: Provider-normalized or raw finding mapping.

    Returns:
        Sorted uppercase CVE identifiers.

    Raises:
        ValueError: Never raised for mapping values.
    """

    source_parts: list[str] = []
    for key in ("cve", "cves", "references", "reference", "tags"):
        value = finding_value(finding, key)
        if isinstance(value, (list, tuple, set)):
            source_parts.extend(str(item) for item in value)
        elif value is not None:
            source_parts.append(str(value))
    matches = _CVE_PATTERN.findall(" ".join(source_parts))
    return sorted({match.upper() for match in matches})


def canonical_vulnerability_identity(finding: Mapping[str, Any]) -> str:
    """Return the strongest stable identity available for a vulnerability.

    Args:
        finding: Scanner finding mapping.

    Returns:
        CVE, standardized identifier, scanner-specific identifier, or a
        controlled title/component fallback.

    Raises:
        FindingDomainError: If the finding has no usable identity.
    """

    cves = extract_cves(finding)
    if cves:
        return "cve:" + "+".join(cves)
    for key in (
        "cwe",
        "ghsa",
        "osv_id",
        "standard_id",
        "template_id",
        "nvt_oid",
        "oid",
        "plugin_id",
        "vulnerability_id",
        "id",
    ):
        value = str(finding_value(finding, key) or "").strip()
        if value:
            return f"{key}:{normalize_identity_part(value)}"
    title = str(finding_value(finding, "title", "name", "finding") or "").strip()
    component = str(finding_value(finding, "component", "service", "product") or "").strip()
    if not title:
        raise FindingDomainError("Finding has no canonical vulnerability identity.")
    return "fallback:" + normalize_identity_part(f"{title}|{component}")


def build_finding_fingerprint(
    client_id: int,
    asset: Mapping[str, Any] | str,
    finding: Mapping[str, Any],
) -> str:
    """Build a deterministic SHA-256 finding fingerprint.

    Args:
        client_id: Owning workspace identifier.
        asset: Asset identity mapping or IP string.
        finding: Scanner finding mapping.

    Returns:
        Hexadecimal SHA-256 fingerprint.

    Raises:
        FindingDomainError: If asset or vulnerability identity is unavailable.
        ValueError: If ``client_id`` is not positive.
    """

    if int(client_id) <= 0:
        raise ValueError("client_id must be a positive integer.")
    asset_identity = canonical_asset_identity(asset)
    vulnerability_identity = canonical_vulnerability_identity(finding)
    raw_port = finding_value(finding, "port")
    port = normalize_port(raw_port)
    inferred_protocol = ""
    port_text = str(raw_port or "").lower()
    if "/tcp" in port_text:
        inferred_protocol = "tcp"
    elif "/udp" in port_text:
        inferred_protocol = "udp"
    protocol = normalize_protocol(
        finding_value(finding, "protocol", "transport") or inferred_protocol
    )
    component = normalize_identity_part(
        finding_value(finding, "component", "service", "product"),
        "unknown-component",
    )
    material = "|".join(
        (
            str(int(client_id)),
            asset_identity,
            vulnerability_identity,
            port,
            protocol,
            component,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_observation_key(
    fingerprint: str,
    scanner: str,
    report_id: str,
    provider_observation_id: str,
) -> str:
    """Build an idempotent scanner observation key.

    Args:
        fingerprint: Canonical finding fingerprint.
        scanner: Provider name.
        report_id: Scan/report identifier.
        provider_observation_id: Provider result ID or deterministic row index.

    Returns:
        Hexadecimal SHA-256 observation key.

    Raises:
        FindingDomainError: If ``fingerprint`` is empty.
    """

    if not fingerprint:
        raise FindingDomainError("Observation requires a finding fingerprint.")
    material = "|".join(
        (
            fingerprint,
            normalize_scanner(scanner),
            normalize_identity_part(report_id, "unknown-report"),
            normalize_identity_part(provider_observation_id, "unknown-observation"),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalize_observation(
    client_id: int,
    scan_record: Mapping[str, Any],
    finding: Mapping[str, Any],
    index: int,
) -> FindingObservation:
    """Normalize one scanner result into a canonical observation.

    Args:
        client_id: Owning workspace identifier.
        scan_record: Parent scan-history record.
        finding: Provider finding mapping.
        index: Stable finding position within the parent report.

    Returns:
        Normalized immutable observation.

    Raises:
        FindingDomainError: If canonical identity cannot be produced.
        ValueError: If the workspace identifier or row index is invalid.
    """

    if index < 0:
        raise ValueError("Observation index cannot be negative.")
    parent_asset = finding_value(scan_record, "asset")
    if not isinstance(parent_asset, Mapping):
        parent_asset = {}
    asset = {
        "asset_uuid": (
            finding_value(finding, "asset_uuid")
            or finding_value(scan_record, "asset_uuid")
            or finding_value(parent_asset, "asset_uuid")
        ),
        "asset_id": (
            finding_value(finding, "asset_id")
            or finding_value(scan_record, "asset_id")
            or finding_value(parent_asset, "asset_id")
        ),
        "asset_tag": (
            finding_value(finding, "asset_tag")
            or finding_value(scan_record, "asset_tag")
            or finding_value(parent_asset, "asset_tag")
        ),
        "asset_ip": (
            finding_value(finding, "asset_ip", "ip", "host")
            or finding_value(scan_record, "asset_ip", "ip", "host")
            or finding_value(parent_asset, "ip", "asset_ip")
        ),
        "hostname": (
            finding_value(finding, "hostname")
            or finding_value(scan_record, "hostname")
            or finding_value(parent_asset, "hostname")
        ),
    }
    fingerprint = build_finding_fingerprint(client_id, asset, finding)
    scanner = normalize_scanner(
        finding_value(finding, "scanner_engine", "scanner")
        or finding_value(scan_record, "scanner_engine", "scanner")
    )
    report_id = str(
        finding_value(scan_record, "report_id", "launch_report_id", "job_uuid") or "unknown-report"
    )
    provider_observation_id = str(
        finding_value(
            finding,
            "observation_id",
            "result_id",
            "matched_at",
            "nvt_oid",
        )
        or index
    )
    observed_at = str(
        finding_value(finding, "observed_at", "detected_at")
        or finding_value(scan_record, "scanned_at", "completed_at", "timestamp")
        or datetime.now(timezone.utc).isoformat()
    )
    title = str(
        finding_value(finding, "title", "name", "finding")
        or canonical_vulnerability_identity(finding)
    ).strip()
    component = normalize_identity_part(
        finding_value(finding, "component", "service", "product"),
        "unknown-component",
    )
    raw_port = finding_value(finding, "port")
    inferred_protocol = ""
    port_text = str(raw_port or "").lower()
    if "/tcp" in port_text:
        inferred_protocol = "tcp"
    elif "/udp" in port_text:
        inferred_protocol = "udp"
    return FindingObservation(
        client_id=int(client_id),
        fingerprint=fingerprint,
        observation_key=build_observation_key(
            fingerprint,
            scanner,
            report_id,
            provider_observation_id,
        ),
        asset_identity=canonical_asset_identity(asset),
        vulnerability_identity=canonical_vulnerability_identity(finding),
        scanner=scanner,
        report_id=report_id,
        observed_at=observed_at,
        severity=normalize_severity(finding_value(finding, "severity", "cvss", "score")),
        title=title,
        port=normalize_port(raw_port),
        protocol=normalize_protocol(
            finding_value(finding, "protocol", "transport") or inferred_protocol
        ),
        component=component,
        raw=dict(finding),
    )


def deduplicate_scan_history(
    client_id: int,
    scan_history: Iterable[Mapping[str, Any]],
) -> list[CanonicalFinding]:
    """Deduplicate all scan observations for one workspace.

    Args:
        client_id: Owning workspace identifier.
        scan_history: Existing OpenVAS/Nuclei normalized history records.

    Returns:
        Canonical findings ordered by severity then most recent observation.

    Raises:
        FindingDomainError: If a supplied finding cannot be identified.
        ValueError: If ``client_id`` is invalid.
    """

    if int(client_id) <= 0:
        raise ValueError("client_id must be a positive integer.")
    aggregates: dict[str, CanonicalFinding] = {}
    for scan_record in scan_history:
        findings = finding_value(scan_record, "findings") or []
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
            continue
        for index, raw_finding in enumerate(findings):
            if not isinstance(raw_finding, Mapping):
                continue
            observation = normalize_observation(
                int(client_id),
                scan_record,
                raw_finding,
                index,
            )
            aggregate = aggregates.get(observation.fingerprint)
            if aggregate is None:
                aggregate = CanonicalFinding(
                    fingerprint=observation.fingerprint,
                    client_id=int(client_id),
                    asset_identity=observation.asset_identity,
                    vulnerability_identity=observation.vulnerability_identity,
                    title=observation.title,
                    severity=observation.severity,
                    first_seen=observation.observed_at,
                    last_seen=observation.observed_at,
                )
                aggregates[observation.fingerprint] = aggregate
            aggregate.add_observation(observation)
    return sorted(
        aggregates.values(),
        key=lambda item: (severity_rank(item.severity), item.last_seen),
        reverse=True,
    )


def validate_finding_transition(
    current_status: str,
    target_status: str,
    *,
    verification_evidence: bool = False,
    analyst_authorized: bool = False,
    false_positive_approved: bool = False,
    risk_acceptance_approved: bool = False,
) -> None:
    """Validate one lifecycle transition without mutating persistence.

    Args:
        current_status: Existing finding status.
        target_status: Requested finding status.
        verification_evidence: Whether technical verification evidence exists.
        analyst_authorized: Whether an authorized analyst validated closure.
        false_positive_approved: Whether a false-positive decision is approved.
        risk_acceptance_approved: Whether residual-risk acceptance is approved.

    Returns:
        None when the transition is valid.

    Raises:
        InvalidFindingTransitionError: If the status or transition is invalid.
        FindingVerificationRequiredError: If closure lacks required evidence.
    """

    if current_status not in FINDING_STATUSES:
        raise InvalidFindingTransitionError(f"Unknown current finding status: {current_status}")
    if target_status not in FINDING_STATUSES:
        raise InvalidFindingTransitionError(f"Unknown target finding status: {target_status}")
    if target_status == current_status:
        return
    if target_status not in VALID_TRANSITIONS[current_status]:
        raise InvalidFindingTransitionError(
            f"Invalid finding transition: {current_status} -> {target_status}"
        )
    if target_status == "Closed" and not (
        verification_evidence
        or analyst_authorized
        or false_positive_approved
        or risk_acceptance_approved
    ):
        raise FindingVerificationRequiredError(
            "Closing a finding requires verification evidence or an authorized decision."
        )
    if target_status == "False positive" and not false_positive_approved:
        raise FindingVerificationRequiredError(
            "False-positive status requires an approved analyst decision."
        )
    if target_status == "Accepted risk" and not risk_acceptance_approved:
        raise FindingVerificationRequiredError(
            "Accepted-risk status requires a valid approved risk acceptance."
        )


def status_after_new_observation(current_status: str) -> str:
    """Return the lifecycle state after a vulnerability is detected again.

    Args:
        current_status: Existing finding lifecycle status.

    Returns:
        Reopened for previously resolved decisions, otherwise the same status.

    Raises:
        InvalidFindingTransitionError: If the status is unknown.
    """

    if current_status not in FINDING_STATUSES:
        raise InvalidFindingTransitionError(f"Unknown finding status: {current_status}")
    if current_status in {"Closed", "Mitigated", "False positive"}:
        return "Reopened"
    return current_status


def finding_dashboard_summary(
    findings: Iterable[CanonicalFinding | Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate unique active findings for an executive workspace overview.

    Args:
        findings: Canonical finding objects or repository rows.

    Returns:
        Counts by severity, lifecycle and scanner with one total per finding.

    Raises:
        ValueError: Never raised for mapping-like rows.
    """

    severity_names = ("Critical", "High", "Medium", "Low", "Info", "Unknown")
    severity_counts = {name: 0 for name in severity_names}
    status_counts = {status: 0 for status in FINDING_STATUSES}
    scanner_counts: dict[str, int] = {}
    active_total = 0
    all_rows = list(findings)
    for finding in all_rows:
        if isinstance(finding, CanonicalFinding):
            status = finding.status
            severity = finding.severity
            scanners = finding.scanners
        else:
            status = str(finding.get("status") or "New")
            severity = normalize_severity(finding.get("severity"))
            raw_scanners = finding.get("scanners") or []
            scanners = (
                {normalize_scanner(raw_scanners)}
                if isinstance(raw_scanners, str)
                else {normalize_scanner(item) for item in raw_scanners}
            )
        status_counts[status] = status_counts.get(status, 0) + 1
        if status not in ACTIVE_FINDING_STATUSES:
            continue
        active_total += 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        for scanner in scanners:
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
    return {
        "unique_findings": len(all_rows),
        "unique_active_findings": active_total,
        "severity": severity_counts,
        "lifecycle": status_counts,
        "scanners": scanner_counts,
    }
