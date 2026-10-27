"""Conservative ISO/IEC 27001:2022 assessment catalog.

The catalog intentionally stores control identifiers, short labels and
SecureScope assessment metadata. It does not reproduce the copyrighted ISO
standard text. Organizations must use a licensed copy of the standard when
interpreting requirements or preparing for certification.

Technical sources provide supporting evidence only. Every control remains
subject to consultant validation and no catalog entry is fully automated.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

FRAMEWORK_REFERENCE = "ISO/IEC 27001:2022 + Amd 1:2024"
CATALOG_NOTICE = (
    "Short labels and assessment guidance only; consult a licensed copy of "
    "ISO/IEC 27001:2022 and Amendment 1:2024."
)


CLAUSE_LABELS: tuple[tuple[str, str], ...] = (
    ("4.1", "Understanding the organization and its context"),
    ("4.2", "Needs and expectations of interested parties"),
    ("4.3", "Determining the scope of the ISMS"),
    ("4.4", "Information security management system"),
    ("5.1", "Leadership and commitment"),
    ("5.2", "Information security policy"),
    ("5.3", "Organizational roles, responsibilities and authorities"),
    ("6.1.1", "Actions to address risks and opportunities - general"),
    ("6.1.2", "Information security risk assessment"),
    ("6.1.3", "Information security risk treatment"),
    ("6.2", "Information security objectives and planning"),
    ("6.3", "Planning of changes"),
    ("7.1", "Resources"),
    ("7.2", "Competence"),
    ("7.3", "Awareness"),
    ("7.4", "Communication"),
    ("7.5.1", "Documented information - general"),
    ("7.5.2", "Creating and updating documented information"),
    ("7.5.3", "Control of documented information"),
    ("8.1", "Operational planning and control"),
    ("8.2", "Information security risk assessment during operation"),
    ("8.3", "Information security risk treatment during operation"),
    ("9.1", "Monitoring, measurement, analysis and evaluation"),
    ("9.2.1", "Internal audit - general"),
    ("9.2.2", "Internal audit programme"),
    ("9.3.1", "Management review - general"),
    ("9.3.2", "Management review inputs"),
    ("9.3.3", "Management review results"),
    ("10.1", "Continual improvement"),
    ("10.2", "Nonconformity and corrective action"),
)


ANNEX_A_LABELS: tuple[tuple[str, str], ...] = (
    ("A.5.1", "Policies for information security"),
    ("A.5.2", "Information security roles and responsibilities"),
    ("A.5.3", "Segregation of duties"),
    ("A.5.4", "Management responsibilities"),
    ("A.5.5", "Contact with authorities"),
    ("A.5.6", "Contact with special interest groups"),
    ("A.5.7", "Threat intelligence"),
    ("A.5.8", "Information security in project management"),
    ("A.5.9", "Inventory of information and associated assets"),
    ("A.5.10", "Acceptable use of information and associated assets"),
    ("A.5.11", "Return of assets"),
    ("A.5.12", "Classification of information"),
    ("A.5.13", "Labelling of information"),
    ("A.5.14", "Information transfer"),
    ("A.5.15", "Access control"),
    ("A.5.16", "Identity management"),
    ("A.5.17", "Authentication information"),
    ("A.5.18", "Access rights"),
    ("A.5.19", "Information security in supplier relationships"),
    ("A.5.20", "Information security within supplier agreements"),
    ("A.5.21", "Managing information security in the ICT supply chain"),
    ("A.5.22", "Monitoring and change management of supplier services"),
    ("A.5.23", "Information security for use of cloud services"),
    ("A.5.24", "Information security incident management planning"),
    ("A.5.25", "Assessment and decision on information security events"),
    ("A.5.26", "Response to information security incidents"),
    ("A.5.27", "Learning from information security incidents"),
    ("A.5.28", "Collection of evidence"),
    ("A.5.29", "Information security during disruption"),
    ("A.5.30", "ICT readiness for business continuity"),
    ("A.5.31", "Legal, statutory, regulatory and contractual requirements"),
    ("A.5.32", "Intellectual property rights"),
    ("A.5.33", "Protection of records"),
    ("A.5.34", "Privacy and protection of personal information"),
    ("A.5.35", "Independent review of information security"),
    ("A.5.36", "Compliance with policies, rules and standards"),
    ("A.5.37", "Documented operating procedures"),
    ("A.6.1", "Screening"),
    ("A.6.2", "Terms and conditions of employment"),
    ("A.6.3", "Information security awareness, education and training"),
    ("A.6.4", "Disciplinary process"),
    ("A.6.5", "Responsibilities after termination or change of employment"),
    ("A.6.6", "Confidentiality or non-disclosure agreements"),
    ("A.6.7", "Remote working"),
    ("A.6.8", "Information security event reporting"),
    ("A.7.1", "Physical security perimeters"),
    ("A.7.2", "Physical entry"),
    ("A.7.3", "Securing offices, rooms and facilities"),
    ("A.7.4", "Physical security monitoring"),
    ("A.7.5", "Protecting against physical and environmental threats"),
    ("A.7.6", "Working in secure areas"),
    ("A.7.7", "Clear desk and clear screen"),
    ("A.7.8", "Equipment siting and protection"),
    ("A.7.9", "Security of assets off-premises"),
    ("A.7.10", "Storage media"),
    ("A.7.11", "Supporting utilities"),
    ("A.7.12", "Cabling security"),
    ("A.7.13", "Equipment maintenance"),
    ("A.7.14", "Secure disposal or re-use of equipment"),
    ("A.8.1", "User endpoint devices"),
    ("A.8.2", "Privileged access rights"),
    ("A.8.3", "Information access restriction"),
    ("A.8.4", "Access to source code"),
    ("A.8.5", "Secure authentication"),
    ("A.8.6", "Capacity management"),
    ("A.8.7", "Protection against malware"),
    ("A.8.8", "Management of technical vulnerabilities"),
    ("A.8.9", "Configuration management"),
    ("A.8.10", "Information deletion"),
    ("A.8.11", "Data masking"),
    ("A.8.12", "Data leakage prevention"),
    ("A.8.13", "Information backup"),
    ("A.8.14", "Redundancy of information processing facilities"),
    ("A.8.15", "Logging"),
    ("A.8.16", "Monitoring activities"),
    ("A.8.17", "Clock synchronization"),
    ("A.8.18", "Use of privileged utility programs"),
    ("A.8.19", "Installation of software on operational systems"),
    ("A.8.20", "Network security"),
    ("A.8.21", "Security of network services"),
    ("A.8.22", "Segregation of networks"),
    ("A.8.23", "Web filtering"),
    ("A.8.24", "Use of cryptography"),
    ("A.8.25", "Secure development life cycle"),
    ("A.8.26", "Application security requirements"),
    ("A.8.27", "Secure system architecture and engineering principles"),
    ("A.8.28", "Secure coding"),
    ("A.8.29", "Security testing in development and acceptance"),
    ("A.8.30", "Outsourced development"),
    ("A.8.31", "Separation of development, test and production"),
    ("A.8.32", "Change management"),
    ("A.8.33", "Test information"),
    ("A.8.34", "Protection during audit testing"),
)


TECHNICAL_SOURCES: Mapping[str, tuple[str, ...]] = {
    "A.5.7": ("amass", "theharvester", "dnsrecon", "wazuh"),
    "A.5.9": ("nmap", "amass", "theharvester", "dnsrecon", "wazuh"),
    "A.5.15": ("wazuh", "prowler", "scoutsuite", "ciso-assistant"),
    "A.5.16": ("wazuh", "prowler", "scoutsuite", "ciso-assistant"),
    "A.5.17": ("openvas", "nuclei", "zap", "prowler", "scoutsuite"),
    "A.5.18": ("wazuh", "prowler", "scoutsuite", "ciso-assistant"),
    "A.5.23": ("prowler", "scoutsuite", "trivy"),
    "A.5.24": ("wazuh", "redmine", "glpi", "gitlab-ce"),
    "A.5.25": ("wazuh", "metasploit", "atomic-red-team"),
    "A.5.26": ("wazuh", "redmine", "glpi", "gitlab-ce"),
    "A.5.27": ("wazuh", "redmine", "glpi", "gitlab-ce"),
    "A.5.28": ("wazuh", "metasploit", "atomic-red-team"),
    "A.5.30": ("wazuh", "ciso-assistant"),
    "A.5.36": ("lynis", "openscap", "ciso-assistant"),
    "A.6.8": ("wazuh", "redmine", "glpi", "gitlab-ce"),
    "A.7.4": ("wazuh",),
    "A.8.1": ("wazuh", "lynis", "openscap"),
    "A.8.2": ("wazuh", "prowler", "scoutsuite", "openscap"),
    "A.8.3": ("prowler", "scoutsuite", "openscap"),
    "A.8.4": ("gitlab-ce", "sonarqube-community"),
    "A.8.5": ("openvas", "nuclei", "zap", "prowler", "scoutsuite"),
    "A.8.6": ("wazuh",),
    "A.8.7": ("wazuh", "openvas", "nuclei", "lynis", "openscap"),
    "A.8.8": (
        "openvas",
        "nuclei",
        "zap",
        "nikto",
        "wapiti",
        "droopescan",
        "trivy",
        "grype",
        "osv-scanner",
    ),
    "A.8.9": ("nmap", "openvas", "nuclei", "wazuh", "lynis", "openscap"),
    "A.8.13": ("wazuh", "lynis", "openscap"),
    "A.8.15": ("wazuh", "ciso-assistant"),
    "A.8.16": ("wazuh", "openvas", "nuclei", "zap"),
    "A.8.17": ("wazuh", "ntp-evidence"),
    "A.8.18": ("wazuh", "lynis", "openscap"),
    "A.8.19": ("wazuh", "lynis", "openscap"),
    "A.8.20": ("nmap", "openvas", "nuclei", "wazuh", "prowler", "scoutsuite"),
    "A.8.21": ("nmap", "openvas", "nuclei", "wazuh"),
    "A.8.22": ("nmap", "prowler", "scoutsuite"),
    "A.8.23": ("zap", "nikto", "wapiti", "droopescan"),
    "A.8.24": ("openvas", "nuclei", "zap", "prowler", "scoutsuite"),
    "A.8.25": (
        "semgrep-ce",
        "bandit",
        "sonarqube-community",
        "gitlab-ce",
    ),
    "A.8.26": ("zap", "semgrep-ce", "bandit", "sonarqube-community"),
    "A.8.27": ("semgrep-ce", "sonarqube-community", "prowler", "scoutsuite"),
    "A.8.28": ("semgrep-ce", "bandit", "sonarqube-community"),
    "A.8.29": (
        "openvas",
        "nuclei",
        "zap",
        "nikto",
        "wapiti",
        "droopescan",
        "semgrep-ce",
        "bandit",
        "sonarqube-community",
        "atomic-red-team",
    ),
    "A.8.31": ("gitlab-ce", "prowler", "scoutsuite"),
    "A.8.32": ("gitlab-ce", "redmine", "glpi", "sonarqube-community"),
    "A.8.34": ("metasploit", "beef", "atomic-red-team"),
}


def _family_for(control_id: str) -> str:
    """Return the reporting family for a control identifier.

    Args:
        control_id: Clause or Annex A identifier.

    Returns:
        Human-readable framework family.

    Raises:
        ValueError: If the identifier is empty.
    """

    value = control_id.strip()
    if not value:
        raise ValueError("Control identifier cannot be empty.")
    if value.startswith("A.5."):
        return "Organizational"
    if value.startswith("A.6."):
        return "People"
    if value.startswith("A.7."):
        return "Physical"
    if value.startswith("A.8."):
        return "Technological"
    return f"ISMS clause {value.split('.', maxsplit=1)[0]}"


def _manual_evidence_requirements(control_id: str) -> list[str]:
    """Build minimum manual evidence requirements by control family.

    Args:
        control_id: Clause or Annex A identifier.

    Returns:
        Evidence requirement descriptions.

    Raises:
        ValueError: If the identifier is empty.
    """

    family = _family_for(control_id)
    if family.startswith("ISMS clause"):
        return [
            "Approved ISMS document or record applicable to the assessment scope",
            "Named owner, approval, version and review date",
            "Interview or observation confirming implementation",
            "Operating record demonstrating effectiveness during the assessment period",
        ]
    if family == "Organizational":
        return [
            "Approved policy, procedure or governance record",
            "Assigned owner and applicable organizational scope",
            "Operating records, review minutes or sampled transactions",
            "Consultant validation of design, implementation and effectiveness",
        ]
    if family == "People":
        return [
            "Approved people-security policy or HR procedure",
            "Anonymized personnel records or sampled acknowledgements",
            "Training, screening or event records applicable to the control",
            "Consultant interview and effectiveness conclusion",
        ]
    if family == "Physical":
        return [
            "Physical security policy, site plan or operating procedure",
            "Inspection, access, maintenance or monitoring records",
            "Sample evidence covering the assessed sites and period",
            "Consultant observation and effectiveness conclusion",
        ]
    return [
        "Approved technical policy, standard or operating procedure",
        "Configuration or inventory evidence for the approved scope",
        "Logs, tests or repeated records demonstrating operation",
        "Consultant validation of coverage and effectiveness",
    ]


def _catalog_entry(control_id: str, name: str, *, kind: str) -> dict[str, Any]:
    """Build one immutable-style control catalog dictionary.

    Args:
        control_id: Clause or Annex A identifier.
        name: Short public control label.
        kind: ``clause`` or ``annex_a``.

    Returns:
        Profile seeding and Evidence Hub metadata.

    Raises:
        ValueError: If the kind or identifier is invalid.
    """

    if kind not in {"clause", "annex_a"}:
        raise ValueError(f"Unsupported control kind: {kind}")
    sources = list(TECHNICAL_SOURCES.get(control_id, ()))
    automation_level = "Hybrid" if sources else "Manual"
    return {
        "control_id": control_id,
        "name": name,
        "description": (
            f"Assess the design, implementation, scope coverage and operating "
            f"effectiveness of {control_id} - {name}."
        ),
        "family": _family_for(control_id),
        "kind": kind,
        "automation_level": automation_level,
        "supported_data_sources": sources,
        "evidence_requirements": _manual_evidence_requirements(control_id),
        "acceptable_evidence_age_days": 365 if not sources else 90,
        "consultant_validation_required": True,
        "standard_reference": FRAMEWORK_REFERENCE,
    }


ISO_CLAUSE_CATALOG: dict[str, dict[str, Any]] = {
    control_id: _catalog_entry(control_id, name, kind="clause")
    for control_id, name in CLAUSE_LABELS
}

ISO_ANNEX_A_CATALOG: dict[str, dict[str, Any]] = {
    control_id: _catalog_entry(control_id, name, kind="annex_a")
    for control_id, name in ANNEX_A_LABELS
}

ISO_CONTROL_CATALOG: dict[str, dict[str, Any]] = {
    **ISO_CLAUSE_CATALOG,
    **ISO_ANNEX_A_CATALOG,
}


def catalog_summary() -> dict[str, int]:
    """Return catalog counts used by validation and the UI.

    Returns:
        Counts for clauses, Annex A controls and collection modes.

    Raises:
        ValueError: Never raised.
    """

    manual = sum(
        1 for entry in ISO_CONTROL_CATALOG.values() if entry["automation_level"] == "Manual"
    )
    hybrid = len(ISO_CONTROL_CATALOG) - manual
    return {
        "clauses": len(ISO_CLAUSE_CATALOG),
        "annex_a_controls": len(ISO_ANNEX_A_CATALOG),
        "manual": manual,
        "hybrid": hybrid,
        "total": len(ISO_CONTROL_CATALOG),
    }


def validate_control_catalog() -> None:
    """Validate the expected ISO control inventory and safety invariants.

    Returns:
        None.

    Raises:
        ValueError: If identifiers, counts or automation boundaries are invalid.
    """

    if len(ISO_ANNEX_A_CATALOG) != 93:
        raise ValueError("The Annex A catalog must contain exactly 93 controls.")
    if len(ISO_CLAUSE_CATALOG) != len(CLAUSE_LABELS):
        raise ValueError("The ISMS clause catalog contains duplicate identifiers.")
    for control_id, entry in ISO_CONTROL_CATALOG.items():
        if entry["control_id"] != control_id:
            raise ValueError(f"Mismatched control identity: {control_id}")
        if entry["automation_level"] not in {"Manual", "Hybrid"}:
            raise ValueError(
                "SecureScope cannot mark an ISO control as fully automated: " f"{control_id}"
            )
        if not entry["consultant_validation_required"]:
            raise ValueError(f"Consultant validation is mandatory for {control_id}.")


validate_control_catalog()
