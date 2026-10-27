"""Deterministic Nuclei observations shared by reporting and canonical evidence."""

import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AutomatedCheck:
    """Catalogue entry; control mappings describe facts, never compliance.

    Attributes:
        check_id: Stable rule identifier.
        display_name: User-facing check name.
        effect: supports, gap or informational.
        mapped_controls: Canonical control references.
        mapped_requirements: Supported requirement rule names.
        explanation: Limited meaning of the collected fact.
        template_ids: Exact allowlisted template identifiers.
        prefixes: Retained serialization field; never authorizes a mapping.
        tags: Retained discovery metadata; never authorizes a mapping.
        provider: Producing scanner identifier.
        rule_version: Version of the deterministic mapping contract.
    """

    check_id: str
    display_name: str
    effect: str
    mapped_controls: tuple[str, ...]
    mapped_requirements: tuple[str, ...]
    explanation: str
    template_ids: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    provider: str = "nuclei"
    rule_version: int = 3

    def to_dict(self) -> dict:
        """Return serializable catalogue data; raises no expected exceptions."""
        return asdict(self)


SCAN_COMPLETED = AutomatedCheck(
    "nuclei.scan.completed",
    "Nuclei vulnerability assessment completed",
    "supports",
    ("A.8.8",),
    ("Recent vulnerability scan",),
    "A vulnerability assessment completed for this asset. This proves collection, "
    "not absence of vulnerabilities or remediation effectiveness.",
)
CHECKS = (
    AutomatedCheck(
        "nuclei.web.configuration",
        "Web Security Configuration",
        "gap",
        ("A.8.9",),
        ("Secure web configuration baseline",),
        "The template reports a web security configuration weakness.",
        (
            "http-missing-security-headers",
            "weak-content-security-policy",
            "weak-csp",
            "missing-x-frame-options",
            "cookies-without-httponly",
        ),
    ),
    AutomatedCheck(
        "nuclei.tls.configuration",
        "Cryptographic Configuration",
        "gap",
        ("A.8.24",),
        ("Transport encryption configuration",),
        "The template reports a TLS or certificate condition; validate the approved trust model.",
        ("ssl-expired", "ssl-mismatched", "ssl-self-signed", "ssl-weak-cipher", "ssh-weak-algo"),
    ),
    AutomatedCheck(
        "nuclei.authentication",
        "Secure Authentication",
        "gap",
        ("A.8.5",),
        ("No default credentials on in-scope services",),
        "The template reports a default credential or authentication weakness.",
        template_ids=("grafana-default-login", "tomcat-default-login"),
    ),
    AutomatedCheck(
        "nuclei.vulnerability",
        "Technical Vulnerability Observation",
        "gap",
        ("A.8.8",),
        (),
        "A known vulnerability template matched; remediation still requires verification.",
        tags=("cve",),
    ),
)
CONTROL_NAMES = {
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.24": "Use of cryptography",
    "A.8.5": "Secure authentication",
}


def classify_nuclei(template_id: str, tags=()) -> tuple[AutomatedCheck, ...]:
    """Match reviewed exact IDs or a CVE identity; tags never authorize an ISO mapping.

    Args:
        template_id: Nuclei template identifier, never its free-text description.
        tags: Iterable of scanner tags or a comma-separated tag string.
    Returns:
        Matching checks at the first matching priority, possibly empty.
    Raises:
        No expected exceptions for a string identity; tags are ignored.
    """
    identity = str(template_id).lower().strip()
    exact = tuple(c for c in CHECKS if identity in c.template_ids)
    if exact:
        return exact
    if re.fullmatch(r"cve-\d{4}-\d{4,}", identity):
        return (CHECKS[-1],)
    return ()


def usable_evidence(evidence: dict, allowed_providers: set[str]) -> bool:
    """Accept reviewed evidence or persisted trusted Nuclei provenance.

    Args:
        evidence: Canonical repository row, not a user-supplied report payload.
        allowed_providers: Providers supported by the consuming requirement.
    Returns:
        Whether validation and mapping provenance permit requirement use.
    Raises:
        No expected exceptions for dictionary inputs.
    """
    if evidence.get("validation_status") != "Validated":
        return False
    provider = str(evidence.get("tool_id") or "").lower()
    if provider not in allowed_providers:
        return False
    if evidence.get("source_verification_current") is False:
        return False
    if provider == "wazuh" and evidence.get("verification_origin") == "System collector":
        metadata = (evidence.get("normalized_payload") or {}).get("metadata", {})
        if any(
            c.get("check_id") in {"wazuh.monitoring.coverage", "wazuh.logging.coverage"}
            for c in metadata.get("automated_checks", [])
        ):
            from securescope.integrations.wazuh_monitoring import evaluate_monitoring

            snapshot = metadata.get("monitoring_snapshot") or {}
            if snapshot.get("telemetry", {}).get(
                "kind"
            ) == "collection_health" and not snapshot.get("m2_collection"):
                return False
            if (
                metadata.get("monitoring_contract_version") != 2
                or evaluate_monitoring(metadata.get("monitoring_snapshot") or {})[
                    "monitoring_state"
                ]
                != "verified"
            ):
                return False
    if evidence.get("mapping_approved") or evidence.get("consultant_approved"):
        return True
    trusted = {
        "nuclei": ("Existing worker", "system:nuclei-worker"),
        "wazuh": ("Authenticated API", "system:wazuh-connector"),
    }
    method, actor = trusted.get(provider, (None, None))
    return bool(
        method
        and evidence.get("verification_origin") == "System collector"
        and evidence.get("mapping_origin") == "Automated check"
        and evidence.get("collection_method") == method
        and evidence.get("validator") == actor
        and str(evidence.get("source_key") or "").startswith(provider + ":")
    )
