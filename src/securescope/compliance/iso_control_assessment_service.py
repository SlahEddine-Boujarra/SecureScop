"""
ISO/IEC 27001:2022 Annex A.8 implementation assessment service for SecureScope.

The engine combines:
- Nmap asset inventory and exposed services
- OpenVAS / Nuclei scan coverage and findings
- Wazuh endpoint monitoring coverage
- Analyst-entered organizational evidence

Important:
Technical scanners can provide evidence and identify gaps, but they cannot prove
all organizational, legal, process, development, access-review, backup, deletion,
DLP, or supplier controls. Therefore the engine uses cautious statuses:

- Likely implemented
- Partially implemented
- Gap detected
- Insufficient evidence

A final "Implemented" status requires analyst validation and evidence.
"""

from __future__ import annotations

import os
import re
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import init_database

AUTO_STATUSES = [
    "Likely implemented",
    "Partially implemented",
    "Gap detected",
    "Insufficient evidence",
]

VALIDATED_STATUSES = [
    "Not reviewed",
    "Implemented",
    "Partially implemented",
    "Not implemented",
    "Not applicable",
]

APPLICABILITY_OPTIONS = [
    "Not reviewed",
    "Applicable",
    "Not applicable",
]

ACTION_STATUSES = [
    "Open",
    "In progress",
    "Blocked",
    "Ready for verification",
    "Closed",
    "Accepted risk",
]

ACTION_PRIORITIES = ["Critical", "High", "Medium", "Low"]


ISO_A8_CONTROLS: Dict[str, Dict[str, str]] = {
    "A.8.1": {
        "name": "User end point devices",
        "description": (
            "Protect endpoint devices such as laptops, desktops and mobile "
            "devices using endpoint security, encryption and secure "
            "configuration."
        ),
        "automatic_scope": (
            "Nmap endpoint inventory, OS identification, Wazuh agent coverage "
            "and endpoint-related OpenVAS / Nuclei findings."
        ),
    },
    "A.8.2": {
        "name": "Privileged access rights",
        "description": (
            "Grant, manage, review and monitor privileged access rights to " "prevent misuse."
        ),
        "automatic_scope": (
            "Exposed administrative services and "
            "authentication/privilege-related OpenVAS / Nuclei findings. RBAC "
            "and access reviews require manual evidence."
        ),
    },
    "A.8.3": {
        "name": "Information access restriction",
        "description": (
            "Restrict access to information according to business and " "need-to-know requirements."
        ),
        "automatic_scope": (
            "Exposed services and access-control findings. Authorization "
            "matrices and periodic reviews require manual evidence."
        ),
    },
    "A.8.4": {
        "name": "Access to source code",
        "description": (
            "Control read and write access to source code, development tools "
            "and software libraries."
        ),
        "automatic_scope": (
            "Not reliably assessable by Nmap/OpenVAS / Nuclei. Repository "
            "permissions and branch protections require manual or API "
            "evidence."
        ),
    },
    "A.8.5": {
        "name": "Secure authentication",
        "description": (
            "Use secure authentication technologies and procedures, including "
            "strong credentials and MFA where appropriate."
        ),
        "automatic_scope": (
            "Authentication, weak credential, TLS and exposed login service "
            "findings. MFA configuration requires manual evidence."
        ),
    },
    "A.8.6": {
        "name": "Capacity management",
        "description": (
            "Monitor and manage resource capacity to maintain required "
            "performance and availability."
        ),
        "automatic_scope": (
            "Limited Wazuh/system telemetry evidence. Capacity thresholds, "
            "forecasts and plans require operational evidence."
        ),
    },
    "A.8.7": {
        "name": "Protection against malware",
        "description": (
            "Implement malware prevention, detection, response and user " "awareness measures."
        ),
        "automatic_scope": (
            "Wazuh endpoint monitoring coverage and malware-related findings. "
            "Antivirus policy and response testing require manual evidence."
        ),
    },
    "A.8.8": {
        "name": "Management of technical vulnerabilities",
        "description": (
            "Identify, evaluate, prioritize, remediate and verify technical "
            "vulnerabilities in a timely manner."
        ),
        "automatic_scope": (
            "Strong technical coverage from OpenVAS / Nuclei reports, CVSS/CVE"
            " data, asset coverage, findings and re-scan history."
        ),
    },
    "A.8.9": {
        "name": "Configuration management",
        "description": "Establish, document, implement, monitor and review secure configurations.",
        "automatic_scope": (
            "Nmap service inventory, OpenVAS / Nuclei configuration findings "
            "and Wazuh monitoring. Approved baselines and change authorization"
            " require manual evidence."
        ),
    },
    "A.8.10": {
        "name": "Information deletion",
        "description": "Delete information securely when no longer required.",
        "automatic_scope": (
            "Not reliably assessable by network/vulnerability scanning. "
            "Retention schedules and deletion evidence are required."
        ),
    },
    "A.8.11": {
        "name": "Data masking",
        "description": "Mask sensitive data according to access-control and business requirements.",
        "automatic_scope": (
            "Not reliably assessable by Nmap/OpenVAS / Nuclei. Application, "
            "database and test-data evidence is required."
        ),
    },
    "A.8.12": {
        "name": "Data leakage prevention",
        "description": (
            "Apply measures to detect and prevent unauthorized disclosure or "
            "extraction of information."
        ),
        "automatic_scope": (
            "Network exposure can indicate risk, but DLP policies, channels "
            "and alerts require dedicated/manual evidence."
        ),
    },
    "A.8.13": {
        "name": "Information backup",
        "description": (
            "Maintain and test backups of information, software and systems " "according to policy."
        ),
        "automatic_scope": (
            "Backup-related findings can indicate gaps. Backup schedules, "
            "restore tests and retention require manual evidence."
        ),
    },
    "A.8.14": {
        "name": "Redundancy of information processing facilities",
        "description": "Provide sufficient redundancy to meet availability requirements.",
        "automatic_scope": (
            "Limited network visibility only. Architecture, failover and "
            "recovery-test evidence are required."
        ),
    },
    "A.8.15": {
        "name": "Logging",
        "description": (
            "Produce, store, protect and analyze logs of activities, "
            "exceptions, faults and relevant events."
        ),
        "automatic_scope": (
            "Wazuh monitoring coverage, timestamps, alert evidence and "
            "SecureScope scan/report history."
        ),
    },
    "A.8.16": {
        "name": "Monitoring activities",
        "description": (
            "Monitor networks, systems and applications for anomalous behavior"
            " and potential incidents."
        ),
        "automatic_scope": (
            "Strong evidence from active Wazuh agents, alerts, asset coverage "
            "and repeated security scans."
        ),
    },
    "A.8.17": {
        "name": "Clock synchronization",
        "description": "Synchronize system clocks with approved time sources.",
        "automatic_scope": (
            "Wazuh endpoint time-service state, source, offset, manager/agent "
            "delta and evidence freshness; direct NTP server tests remain "
            "supporting evidence only."
        ),
    },
    "A.8.18": {
        "name": "Use of privileged utility programs",
        "description": (
            "Restrict and control utility programs capable of overriding "
            "system and application controls."
        ),
        "automatic_scope": (
            "Not reliably assessable by Nmap/OpenVAS / Nuclei. Application "
            "allowlisting, execution logs and approvals are required."
        ),
    },
    "A.8.19": {
        "name": "Installation of software on operational systems",
        "description": (
            "Control software installation on operational systems to prevent "
            "unauthorized or vulnerable software."
        ),
        "automatic_scope": (
            "Service/software inventory and obsolete-software findings provide"
            " partial evidence. Approval workflows require manual evidence."
        ),
    },
    "A.8.20": {
        "name": "Networks security",
        "description": (
            "Secure, manage and control networks and network devices to "
            "protect information and systems."
        ),
        "automatic_scope": (
            "Nmap exposure inventory, OpenVAS / Nuclei network findings and "
            "Wazuh monitoring provide meaningful technical evidence."
        ),
    },
    "A.8.21": {
        "name": "Security of network services",
        "description": (
            "Identify and manage security mechanisms, service levels and "
            "requirements for network services."
        ),
        "automatic_scope": (
            "Nmap service/version inventory and OpenVAS / Nuclei service "
            "findings provide strong technical evidence."
        ),
    },
    "A.8.22": {
        "name": "Segregation of networks",
        "description": (
            "Separate user, system and service groups in networks based on "
            "risk and business needs."
        ),
        "automatic_scope": (
            "VLAN/subnet inventory and exposure evidence provide partial "
            "evidence. Firewall rules and architecture require validation."
        ),
    },
    "A.8.23": {
        "name": "Web filtering",
        "description": (
            "Manage access to external websites to reduce exposure to " "malicious content."
        ),
        "automatic_scope": (
            "Not reliably assessable by Nmap/OpenVAS / Nuclei. Secure web "
            "gateway, DNS filtering and policy evidence are required."
        ),
    },
    "A.8.24": {
        "name": "Use of cryptography",
        "description": (
            "Define and implement rules for effective use and management of "
            "cryptography and keys."
        ),
        "automatic_scope": (
            "OpenVAS / Nuclei TLS/certificate/cipher findings provide "
            "technical evidence. Key-management governance requires manual "
            "evidence."
        ),
    },
    "A.8.25": {
        "name": "Secure development life cycle",
        "description": (
            "Integrate security activities into each phase of the system and "
            "software development life cycle."
        ),
        "automatic_scope": (
            "Security scan evidence can support the SDLC, but process gates, "
            "roles and lifecycle records require manual evidence."
        ),
    },
    "A.8.26": {
        "name": "Application security requirements",
        "description": (
            "Identify, approve and apply information security requirements "
            "when developing or acquiring applications."
        ),
        "automatic_scope": (
            "Application findings help identify requirements. Approved "
            "requirement specifications require manual evidence."
        ),
    },
    "A.8.27": {
        "name": "Secure system architecture and engineering principles",
        "description": (
            "Establish and apply secure architecture and engineering "
            "principles throughout system lifecycles."
        ),
        "automatic_scope": (
            "Technical exposure can identify architectural weaknesses, but "
            "design principles and reviews require manual evidence."
        ),
    },
    "A.8.28": {
        "name": "Secure coding",
        "description": "Apply secure coding principles, standards, reviews and tooling.",
        "automatic_scope": (
            "Network/OpenVAS / Nuclei findings cannot prove secure coding. "
            "SAST, code review and coding-standard evidence are required."
        ),
    },
    "A.8.29": {
        "name": "Security testing in development and acceptance",
        "description": "Define and perform security testing during development and acceptance.",
        "automatic_scope": (
            "OpenVAS / Nuclei testing and repeated reports provide technical "
            "test evidence. Environment and acceptance linkage require "
            "validation."
        ),
    },
    "A.8.30": {
        "name": "Outsourced development",
        "description": (
            "Direct, monitor and review outsourced development activities and "
            "security obligations."
        ),
        "automatic_scope": (
            "Not assessable by Nmap/OpenVAS / Nuclei. Contracts, supplier "
            "reviews and delivery evidence are required."
        ),
    },
    "A.8.31": {
        "name": "Separation of development, test and production environments",
        "description": "Separate and secure development, test and production environments.",
        "automatic_scope": (
            "VLAN/subnet and asset labels may provide partial evidence. "
            "Architecture and access restrictions require validation."
        ),
    },
    "A.8.32": {
        "name": "Change management",
        "description": (
            "Subject changes to systems and information-processing facilities "
            "to controlled change procedures."
        ),
        "automatic_scope": (
            "Scanner deltas may show technical changes, but approvals, testing"
            " and rollback evidence are required."
        ),
    },
    "A.8.33": {
        "name": "Test information",
        "description": "Select, protect and manage test information appropriately.",
        "automatic_scope": (
            "Not reliably assessable by network/vulnerability scanning. Data "
            "selection, masking and access evidence are required."
        ),
    },
    "A.8.34": {
        "name": "Protection of information systems during audit testing",
        "description": (
            "Plan and control audit tests to protect operational systems, "
            "information and availability."
        ),
        "automatic_scope": (
            "SecureScope records authorized targets and scan evidence, but "
            "approvals, windows, safeguards and confidentiality require "
            "validation."
        ),
    },
}


UNKNOWN_VALUES = {
    None,
    "",
    "unknown",
    "not inspected",
    "n/a",
    "unassigned",
    "none",
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _known(value: Any) -> bool:
    return _norm(value) not in UNKNOWN_VALUES


def _pct(part: int, total: int) -> float:
    return round((part / total) * 100, 1) if total else 0.0


def _flatten_findings(scan_history: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for record in scan_history:
        for finding in record.get("findings") or []:
            row = dict(finding)
            row["_asset_ip"] = record.get("asset_ip") or (record.get("asset") or {}).get("ip")
            row["_report_id"] = record.get("report_id")
            row["_scanned_at"] = record.get("scanned_at")
            findings.append(row)
    return findings


def _finding_blob(finding: Dict[str, Any]) -> str:
    keys = [
        "Finding",
        "Name",
        "Description",
        "Solution",
        "CVE",
        "Port",
        "Severity",
    ]
    return " ".join(str(finding.get(key) or "") for key in keys).lower()


def _count_findings(findings: Iterable[Dict[str, Any]], keywords: Iterable[str]) -> int:
    words = [word.lower() for word in keywords]
    return sum(1 for finding in findings if any(word in _finding_blob(finding) for word in words))


def _severity_count(findings: Iterable[Dict[str, Any]], levels: Iterable[str]) -> int:
    accepted = {level.lower() for level in levels}
    return sum(1 for finding in findings if _norm(finding.get("Severity")) in accepted)


def _ports_from_asset(asset: Dict[str, Any]) -> set[int]:
    value = asset.get("open_ports")
    if isinstance(value, list):
        result = set()
        for port in value:
            if isinstance(port, dict):
                raw = port.get("port")
            else:
                raw = port
            try:
                result.add(int(str(raw).split("/")[0]))
            except (TypeError, ValueError):
                continue
        return result

    return {
        int(match)
        for match in re.findall(r"(?<!\d)(\d{1,5})(?=/|\\b)", str(value or ""))
        if 0 < int(match) <= 65535
    }


def _assessment(
    control_id: str,
    status: str,
    confidence: str,
    evidence: List[str],
    gaps: List[str],
    sources: List[str],
    score: int,
) -> Dict[str, Any]:
    catalog = ISO_A8_CONTROLS[control_id]
    return {
        "control_id": control_id,
        "control_name": catalog["name"],
        "description": catalog["description"],
        "automatic_scope": catalog["automatic_scope"],
        "automated_status": status,
        "confidence": confidence,
        "score": max(0, min(100, int(score))),
        "evidence": evidence,
        "gaps": gaps,
        "sources": sources,
    }


def build_environment_metrics(
    assets: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    wazuh_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    asset_ips = {str(asset.get("ip")) for asset in assets if _known(asset.get("ip"))}

    completed_records = [
        record
        for record in scan_history
        if _norm(record.get("final_status")) in {"done", "completed"}
    ]
    scanned_ips = {
        str(record.get("asset_ip") or (record.get("asset") or {}).get("ip"))
        for record in completed_records
        if _known(record.get("asset_ip") or (record.get("asset") or {}).get("ip"))
    }

    scans_per_ip: Dict[str, int] = {}
    for record in completed_records:
        ip = str(record.get("asset_ip") or (record.get("asset") or {}).get("ip") or "")
        if ip:
            scans_per_ip[ip] = scans_per_ip.get(ip, 0) + 1

    findings = _flatten_findings(scan_history)

    from securescope.integrations.wazuh_monitoring import evaluate_monitoring

    monitored_rows = [
        row
        for row in wazuh_rows
        if _known(row.get("asset_ip"))
        and evaluate_monitoring(row)["monitoring_state"] == "verified"
    ]
    wazuh_asset_ips = {str(row.get("asset_ip")) for row in monitored_rows}

    logging_ips = {
        str(row["asset_ip"])
        for row in monitored_rows
        if (row.get("telemetry") or {}).get("kind") == "security_event"
    }

    known_os = sum(1 for asset in assets if _known(asset.get("operating_system")))
    known_services = sum(1 for asset in assets if _known(asset.get("open_ports")))
    known_vlan = sum(
        1 for asset in assets if _known(asset.get("vlan_id")) or _known(asset.get("vlan_name"))
    )
    unique_vlans = {
        str(asset.get("vlan_id") or asset.get("vlan_name"))
        for asset in assets
        if _known(asset.get("vlan_id")) or _known(asset.get("vlan_name"))
    }

    all_ports = set()
    for asset in assets:
        all_ports.update(_ports_from_asset(asset))

    clock_evidence_assets = [
        asset
        for asset in assets
        if _known(asset.get("clock_evidence_source"))
        and _norm(asset.get("clock_sync_status")) not in {"", "unknown", "no evidence"}
    ]
    clock_synchronized_assets = [
        asset
        for asset in clock_evidence_assets
        if _norm(asset.get("clock_sync_status")) == "synchronized"
    ]
    clock_gap_assets = [
        asset
        for asset in clock_evidence_assets
        if _norm(asset.get("clock_sync_status")) in {"not synchronized", "out of tolerance"}
    ]
    clock_sources = {
        str(asset.get("clock_source") or "").strip()
        for asset in clock_evidence_assets
        if _known(asset.get("clock_source"))
    }
    ntp_server_assets = [asset for asset in assets if bool(asset.get("ntp_server_detected"))]

    endpoint_assets = [
        asset
        for asset in assets
        if any(
            token
            in _norm(
                " ".join(
                    [
                        str(asset.get("device_type") or ""),
                        str(asset.get("operating_system") or ""),
                    ]
                )
            )
            for token in (
                "windows",
                "linux",
                "ubuntu",
                "desktop",
                "laptop",
                "workstation",
                "endpoint",
                "macos",
            )
        )
    ]

    return {
        "assets_total": len(assets),
        "asset_ips": asset_ips,
        "completed_records": completed_records,
        "completed_scans": len(completed_records),
        "scanned_ips": scanned_ips,
        "scan_coverage": _pct(len(scanned_ips & asset_ips), len(asset_ips)),
        "retested_assets": sum(1 for value in scans_per_ip.values() if value > 1),
        "findings": findings,
        "findings_total": len(findings),
        "critical_findings": _severity_count(findings, ["Critical"]),
        "high_findings": _severity_count(findings, ["High"]),
        "critical_high_findings": _severity_count(findings, ["Critical", "High"]),
        "wazuh_rows": wazuh_rows,
        "wazuh_monitored_assets": len(wazuh_asset_ips & asset_ips),
        "wazuh_coverage": _pct(len(wazuh_asset_ips & asset_ips), len(asset_ips)),
        "wazuh_logging_coverage": _pct(len(logging_ips & asset_ips), len(asset_ips)),
        "known_os": known_os,
        "os_coverage": _pct(known_os, len(assets)),
        "known_services": known_services,
        "service_coverage": _pct(known_services, len(assets)),
        "known_vlan": known_vlan,
        "vlan_coverage": _pct(known_vlan, len(assets)),
        "unique_vlans": unique_vlans,
        "all_ports": all_ports,
        "endpoint_assets": endpoint_assets,
        "endpoint_count": len(endpoint_assets),
        "clock_evidence_assets": len(clock_evidence_assets),
        "clock_synchronized_assets": len(clock_synchronized_assets),
        "clock_gap_assets": len(clock_gap_assets),
        "clock_sources": clock_sources,
        "ntp_server_assets": len(ntp_server_assets),
        "clock_evidence_coverage": _pct(
            len(clock_evidence_assets),
            len(assets),
        ),
        "auth_findings": _count_findings(
            findings,
            [
                "authentication",
                "password",
                "credential",
                "login",
                "brute force",
                "anonymous",
                "default account",
                "mfa",
            ],
        ),
        "privilege_findings": _count_findings(
            findings,
            [
                "privilege",
                "administrator",
                "admin access",
                "root",
                "sudo",
                "remote desktop",
                "ssh",
                "winrm",
            ],
        ),
        "malware_findings": _count_findings(
            findings,
            ["malware", "trojan", "virus", "ransomware", "backdoor"],
        ),
        "configuration_findings": _count_findings(
            findings,
            [
                "configuration",
                "misconfiguration",
                "default",
                "hardening",
                "insecure setting",
                "unnecessary service",
            ],
        ),
        "backup_findings": _count_findings(
            findings,
            ["backup", "restore", "snapshot"],
        ),
        "capacity_findings": _count_findings(
            findings,
            ["capacity", "resource exhaustion", "denial of service", "dos"],
        ),
        "software_findings": _count_findings(
            findings,
            [
                "obsolete",
                "unsupported",
                "end of life",
                "outdated",
                "version",
                "patch",
            ],
        ),
        "network_findings": _count_findings(
            findings,
            [
                "network",
                "firewall",
                "service",
                "port",
                "remote",
                "snmp",
                "telnet",
                "ftp",
            ],
        ),
        "crypto_findings": _count_findings(
            findings,
            [
                "ssl",
                "tls",
                "certificate",
                "cipher",
                "cryptograph",
                "encryption",
                "key length",
            ],
        ),
        "time_findings": _count_findings(
            findings,
            ["ntp", "clock", "time synchronization", "timestamp"],
        ),
        "web_findings": _count_findings(
            findings,
            [
                "http",
                "https",
                "web application",
                "cookie",
                "header",
                "cross-site",
                "sql injection",
            ],
        ),
        "admin_ports": all_ports & {22, 23, 445, 3389, 5900, 5985, 5986},
        "database_ports": all_ports & {1433, 1521, 3306, 5432, 6379, 27017},
        "tls_ports": all_ports & {443, 465, 636, 853, 993, 995, 8443},
        "ntp_present": 123 in all_ports,
    }


def evaluate_a8_controls(
    assets: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    wazuh_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Evaluate all Annex A.8 controls using available technical evidence."""
    wazuh_rows = wazuh_rows or []
    m = build_environment_metrics(assets, scan_history, wazuh_rows)
    result: Dict[str, Dict[str, Any]] = {}

    def put(
        control_id: str,
        status: str,
        confidence: str,
        evidence: List[str],
        gaps: List[str],
        sources: List[str],
        score: int,
    ) -> None:
        result[control_id] = _assessment(
            control_id,
            status,
            confidence,
            evidence,
            gaps,
            sources,
            score,
        )

    # A.8.1
    if not m["assets_total"]:
        put(
            "A.8.1",
            "Insufficient evidence",
            "Low",
            [],
            ["No endpoint inventory exists."],
            ["Nmap", "Wazuh"],
            0,
        )
    elif m["wazuh_coverage"] >= 90 and m["os_coverage"] >= 80:
        put(
            "A.8.1",
            "Partially implemented",
            "Medium",
            [
                f"{m['assets_total']} assets inventoried.",
                f"Operating system identified on {m['os_coverage']}% of assets.",
                f"Verified Wazuh monitoring coverage is {m['wazuh_coverage']}%.",
            ],
            [
                (
                    "Disk encryption, endpoint hardening baseline, screen-lock and "
                    "mobile-device controls require direct evidence."
                ),
            ],
            ["Nmap", "Wazuh", "OpenVAS / Nuclei"],
            72,
        )
    elif m["wazuh_coverage"] > 0:
        put(
            "A.8.1",
            "Partially implemented",
            "Medium",
            [f"Verified Wazuh coverage is {m['wazuh_coverage']}%."],
            [
                "Not all inventoried endpoints are actively monitored.",
                "Encryption and secure configuration are not verified.",
            ],
            ["Nmap", "Wazuh"],
            50,
        )
    else:
        put(
            "A.8.1",
            "Gap detected",
            "Medium",
            [f"{m['assets_total']} assets inventoried."],
            [
                "No active Wazuh endpoint coverage was found.",
                "Endpoint encryption and hardening are not verified.",
            ],
            ["Nmap", "Wazuh"],
            25,
        )

    # A.8.2
    if m["privilege_findings"] or m["admin_ports"]:
        status = "Gap detected" if m["privilege_findings"] else "Partially implemented"
        put(
            "A.8.2",
            status,
            "Medium",
            [
                f"Administrative ports observed: {sorted(m['admin_ports']) or 'none'}.",
                f"Privilege/admin-related findings: {m['privilege_findings']}.",
            ],
            [
                (
                    "Role assignments, approvals, access reviews and privileged "
                    "session monitoring require manual/IAM evidence."
                ),
            ],
            ["Nmap", "OpenVAS / Nuclei"],
            35 if status == "Gap detected" else 55,
        )
    else:
        put(
            "A.8.2",
            "Insufficient evidence",
            "Low",
            ["No obvious privilege-related technical finding was detected."],
            ["Absence of findings does not verify privileged-access governance or reviews."],
            ["OpenVAS / Nuclei"],
            30,
        )

    # A.8.3
    access_risk = m["auth_findings"] + len(m["database_ports"])
    if access_risk:
        put(
            "A.8.3",
            "Gap detected" if m["auth_findings"] else "Partially implemented",
            "Medium",
            [
                f"Authentication/access findings: {m['auth_findings']}.",
                f"Exposed database ports: {sorted(m['database_ports']) or 'none'}.",
            ],
            [
                (
                    "Need-to-know rules, application permissions and periodic access "
                    "reviews are not verified."
                )
            ],
            ["Nmap", "OpenVAS / Nuclei"],
            38 if m["auth_findings"] else 55,
        )
    else:
        put(
            "A.8.3",
            "Insufficient evidence",
            "Low",
            ["No clear access-control gap was identified by the available scans."],
            ["Authorization matrices and access reviews require manual evidence."],
            ["OpenVAS / Nuclei"],
            30,
        )

    # A.8.4 manual
    put(
        "A.8.4",
        "Insufficient evidence",
        "Low",
        [],
        ["Repository permissions, branch protection and code-access reviews are required."],
        ["Manual evidence", "Source-control API"],
        10,
    )

    # A.8.5
    if m["auth_findings"] > 0:
        put(
            "A.8.5",
            "Gap detected",
            "High",
            [f"{m['auth_findings']} authentication-related findings were detected."],
            ["MFA coverage and identity-provider configuration still require validation."],
            ["OpenVAS / Nuclei", "Nmap"],
            30,
        )
    elif m["completed_scans"] > 0:
        put(
            "A.8.5",
            "Partially implemented",
            "Medium",
            [
                (
                    "Authentication-relevant services were included in completed "
                    "OpenVAS / Nuclei scans."
                ),
                "No matching authentication finding was detected in stored reports.",
            ],
            [
                (
                    "MFA, password policy, account lockout and lifecycle are not "
                    "verified by network scanning."
                )
            ],
            ["OpenVAS / Nuclei"],
            60,
        )
    else:
        put(
            "A.8.5",
            "Insufficient evidence",
            "Low",
            [],
            [
                "No completed OpenVAS / Nuclei report is available.",
                "MFA and identity controls require manual evidence.",
            ],
            ["OpenVAS / Nuclei", "Manual evidence"],
            10,
        )

    # A.8.6
    if m["wazuh_coverage"] > 0:
        put(
            "A.8.6",
            "Partially implemented",
            "Low",
            [
                f"Wazuh monitoring covers {m['wazuh_coverage']}% of inventoried assets.",
                f"Capacity/DoS-related findings: {m['capacity_findings']}.",
            ],
            [
                (
                    "Resource thresholds, trends, forecasts and capacity plans are not"
                    " available in current evidence."
                )
            ],
            ["Wazuh", "OpenVAS / Nuclei", "Manual evidence"],
            45,
        )
    else:
        put(
            "A.8.6",
            "Insufficient evidence",
            "Low",
            [],
            ["No resource-monitoring/capacity evidence is available."],
            ["Manual evidence", "Monitoring platform"],
            10,
        )

    # A.8.7
    if m["malware_findings"] > 0:
        put(
            "A.8.7",
            "Gap detected",
            "High",
            [f"{m['malware_findings']} malware-related findings were detected."],
            ["Confirm containment, endpoint protection and remediation."],
            ["OpenVAS / Nuclei", "Wazuh"],
            25,
        )
    elif m["wazuh_coverage"] >= 90:
        put(
            "A.8.7",
            "Partially implemented",
            "Medium",
            [f"Verified Wazuh monitoring coverage is {m['wazuh_coverage']}%."],
            [
                (
                    "Antivirus/EDR policy, signature health, quarantine and response "
                    "tests require evidence."
                )
            ],
            ["Wazuh", "Manual evidence"],
            68,
        )
    elif m["wazuh_coverage"] > 0:
        put(
            "A.8.7",
            "Partially implemented",
            "Medium",
            [f"Partial Wazuh monitoring coverage: {m['wazuh_coverage']}%."],
            ["Not all assets are monitored for malware-related activity."],
            ["Wazuh"],
            45,
        )
    else:
        put(
            "A.8.7",
            "Insufficient evidence",
            "Low",
            [],
            ["No endpoint malware-protection evidence is available."],
            ["Wazuh", "Manual evidence"],
            10,
        )

    # A.8.8
    if not m["completed_scans"]:
        put(
            "A.8.8",
            "Gap detected",
            "High",
            [],
            ["No completed OpenVAS / Nuclei vulnerability scan is stored."],
            ["OpenVAS / Nuclei"],
            10,
        )
    elif m["scan_coverage"] < 80:
        put(
            "A.8.8",
            "Partially implemented",
            "High",
            [
                f"{m['completed_scans']} completed OpenVAS / Nuclei report(s).",
                f"Asset scan coverage is {m['scan_coverage']}%.",
            ],
            [
                "Scan coverage is incomplete.",
                f"Critical/high findings still recorded: {m['critical_high_findings']}.",
                "Remediation SLA and closure evidence require validation.",
            ],
            ["Nmap", "OpenVAS / Nuclei"],
            55,
        )
    elif m["critical_high_findings"] > 0:
        put(
            "A.8.8",
            "Gap detected",
            "High",
            [
                f"Asset scan coverage is {m['scan_coverage']}%.",
                f"{m['critical_findings']} critical and {m['high_findings']}"
                f" high findings are recorded.",
                f"{m['retested_assets']} asset(s) have repeated scans.",
            ],
            ["Critical/high vulnerabilities require treatment and verified closure."],
            ["Nmap", "OpenVAS / Nuclei"],
            45,
        )
    elif m["retested_assets"] > 0:
        put(
            "A.8.8",
            "Likely implemented",
            "High",
            [
                f"Asset scan coverage is {m['scan_coverage']}%.",
                "No stored critical/high finding remains in the available reports.",
                f"{m['retested_assets']} asset(s) have repeated scan evidence.",
            ],
            [
                (
                    "Validate remediation SLA, ownership, exceptions and patch "
                    "governance before final approval."
                )
            ],
            ["Nmap", "OpenVAS / Nuclei"],
            85,
        )
    else:
        put(
            "A.8.8",
            "Partially implemented",
            "High",
            [
                f"Asset scan coverage is {m['scan_coverage']}%.",
                "No stored critical/high finding remains in the available reports.",
            ],
            ["No re-test evidence is available.", "Remediation governance requires validation."],
            ["Nmap", "OpenVAS / Nuclei"],
            72,
        )

    # A.8.9
    if m["configuration_findings"] > 0:
        put(
            "A.8.9",
            "Gap detected",
            "High",
            [f"{m['configuration_findings']} configuration/hardening findings were detected."],
            ["Approved secure baselines and change control require validation."],
            ["OpenVAS / Nuclei", "Nmap"],
            35,
        )
    elif m["service_coverage"] >= 80 and m["completed_scans"]:
        put(
            "A.8.9",
            "Partially implemented",
            "Medium",
            [
                f"Service inventory coverage is {m['service_coverage']}%.",
                "OpenVAS / Nuclei configuration checks are available.",
            ],
            ["Baseline documents, drift monitoring and authorized-change evidence are missing."],
            ["Nmap", "OpenVAS / Nuclei", "Wazuh"],
            62,
        )
    else:
        put(
            "A.8.9",
            "Insufficient evidence",
            "Low",
            [],
            [
                "Insufficient service/configuration coverage.",
                "Secure baseline evidence is required.",
            ],
            ["Nmap", "OpenVAS / Nuclei", "Manual evidence"],
            20,
        )

    # A.8.10-14 mostly manual
    put(
        "A.8.10",
        "Insufficient evidence",
        "Low",
        [],
        ["Retention rules, deletion procedures and deletion records are required."],
        ["Manual evidence"],
        5,
    )
    put(
        "A.8.11",
        "Insufficient evidence",
        "Low",
        [],
        ["Masking rules, application/database configuration and test evidence are required."],
        ["Manual evidence", "Application evidence"],
        5,
    )
    put(
        "A.8.12",
        "Insufficient evidence",
        "Low",
        [
            (
                f"Network exposure inventory exists for {m['assets_total']} asset(s)."
                if m["assets_total"]
                else ""
            )
        ],
        ["DLP policy, channel coverage, alerting and incident records are required."],
        ["Manual evidence", "DLP platform"],
        15 if m["assets_total"] else 5,
    )

    if m["backup_findings"] > 0:
        put(
            "A.8.13",
            "Gap detected",
            "Medium",
            [f"{m['backup_findings']} backup-related findings were detected."],
            ["Provide backup schedules, successful jobs and restore-test evidence."],
            ["OpenVAS / Nuclei", "Manual evidence"],
            30,
        )
    else:
        put(
            "A.8.13",
            "Insufficient evidence",
            "Low",
            [],
            ["Backup frequency, encryption, retention and restore tests are not verified."],
            ["Manual evidence", "Backup platform"],
            10,
        )

    put(
        "A.8.14",
        "Insufficient evidence",
        "Low",
        [],
        ["Redundancy architecture, failover tests and recovery objectives are required."],
        ["Architecture evidence", "Manual evidence"],
        5,
    )

    # These are factual inventory coverage summaries, never ISO conclusions.
    for control_id, coverage, label, review in (
        (
            "A.8.15",
            m["wazuh_logging_coverage"],
            "security log",
            "Validate retention, integrity protection, access restrictions and review procedures.",
        ),
        (
            "A.8.16",
            m["wazuh_coverage"],
            "monitoring",
            "Validate alert triage, response ownership, monitoring use cases and review frequency.",
        ),
    ):
        put(
            control_id,
            (
                "Current evidence"
                if coverage == 100
                else "Partial coverage" if coverage else "Not verified"
            ),
            "High" if coverage else "Low",
            [f"Current verified Wazuh {label} coverage: {coverage}% of inventory assets."],
            [
                review,
                "Approved scope membership and a human assessment are required "
                "for an ISO conclusion.",
            ],
            ["Wazuh"],
            0,
        )
        result[control_id].update(
            score=None, coverage_percentage=coverage, assessment_basis="Source coverage"
        )

    # A.8.17
    if m["time_findings"] > 0 or m["clock_gap_assets"] > 0:
        put(
            "A.8.17",
            "Gap detected",
            "High" if m["clock_gap_assets"] else "Medium",
            [
                f"{m['time_findings']} time/NTP-related finding(s) were detected.",
                f"{m['clock_gap_assets']} endpoint(s) are unsynchronized or outside tolerance.",
                f"{m['ntp_server_assets']} internal NTP server response(s) were detected.",
            ],
            [
                "Correct endpoint time-source configuration and verify offset after remediation.",
                "Confirm the approved authoritative time hierarchy.",
            ],
            ["Wazuh", "NTP audit", "OpenVAS / Nuclei"],
            25,
        )
    elif (
        m["assets_total"] > 0
        and m["clock_evidence_assets"] == m["assets_total"]
        and m["clock_synchronized_assets"] == m["assets_total"]
        and len(m["clock_sources"]) == 1
    ):
        put(
            "A.8.17",
            "Likely implemented",
            "High",
            [
                f"Endpoint clock evidence covers all {m['assets_total']} asset(s).",
                "All endpoints report synchronized status within the configured tolerance.",
                f"One common time source is reported: {next(iter(m['clock_sources']))}.",
                f"{m['ntp_server_assets']}"
                f" internal NTP server response(s) were independently detected.",
            ],
            [
                (
                    "Validate source approval, redundancy, authentication and periodic"
                    " review before final approval."
                ),
            ],
            ["Wazuh", "NTP audit", "SecureScope"],
            88,
        )
    elif m["clock_evidence_assets"] > 0:
        put(
            "A.8.17",
            "Partially implemented",
            "Medium",
            [
                f"Endpoint clock evidence coverage is {m['clock_evidence_coverage']}%.",
                f"{m['clock_synchronized_assets']} endpoint(s) report synchronized status.",
                f"{len(m['clock_sources'])} time source(s) are reported.",
                f"{m['ntp_server_assets']} internal NTP server response(s) were detected.",
            ],
            [
                "Collect endpoint evidence for every asset.",
                "Verify that the approved source hierarchy is consistent.",
            ],
            ["Wazuh", "NTP audit", "SecureScope"],
            62,
        )
    elif m["ntp_server_assets"] > 0 or m["ntp_present"]:
        put(
            "A.8.17",
            "Partially implemented",
            "Low",
            [
                f"{m['ntp_server_assets']} NTP server response(s) were detected.",
            ],
            [
                "A server response does not prove endpoint synchronization.",
                "Collect source, sync-state and offset evidence from every endpoint.",
            ],
            ["NTP audit", "Nmap", "Wazuh"],
            45,
        )
    else:
        put(
            "A.8.17",
            "Insufficient evidence",
            "Low",
            [],
            [
                "No NTP server or endpoint clock-synchronization evidence is available.",
            ],
            ["Wazuh", "NTP configuration", "Manual evidence"],
            5,
        )

    put(
        "A.8.18",
        "Insufficient evidence",
        "Low",
        [],
        ["Privileged utility inventory, restrictions, execution logs and approvals are required."],
        ["Manual evidence", "Application control"],
        5,
    )

    # A.8.19
    if m["software_findings"] > 0:
        put(
            "A.8.19",
            "Gap detected",
            "Medium",
            [f"{m['software_findings']} obsolete/version/patch-related findings were detected."],
            ["Software approval and installation-control workflow require validation."],
            ["Nmap", "OpenVAS / Nuclei"],
            35,
        )
    elif m["service_coverage"] > 0:
        put(
            "A.8.19",
            "Partially implemented",
            "Medium",
            [f"Service/software inventory coverage is {m['service_coverage']}%."],
            ["Authorized software list and installation approvals are not verified."],
            ["Nmap", "OpenVAS / Nuclei"],
            55,
        )
    else:
        put(
            "A.8.19",
            "Insufficient evidence",
            "Low",
            [],
            ["No software inventory evidence is available."],
            ["Manual evidence", "Software inventory"],
            10,
        )

    # A.8.20
    if not m["assets_total"]:
        put(
            "A.8.20",
            "Insufficient evidence",
            "Low",
            [],
            ["No network asset inventory is available."],
            ["Nmap", "OpenVAS / Nuclei"],
            0,
        )
    elif m["critical_high_findings"] > 0 and m["network_findings"] > 0:
        put(
            "A.8.20",
            "Gap detected",
            "High",
            [
                f"{m['assets_total']} networked assets inventoried.",
                f"{m['network_findings']} network-related findings.",
                f"{m['critical_high_findings']} critical/high findings overall.",
            ],
            ["Review firewalling, exposed services, IDS/IPS and device hardening."],
            ["Nmap", "OpenVAS / Nuclei", "Wazuh"],
            38,
        )
    elif m["service_coverage"] >= 80 and m["scan_coverage"] >= 80:
        put(
            "A.8.20",
            "Partially implemented",
            "High",
            [
                f"Service inventory coverage: {m['service_coverage']}%.",
                f"OpenVAS / Nuclei scan coverage: {m['scan_coverage']}%.",
            ],
            [
                (
                    "Firewall rules, IDS/IPS effectiveness and network-device "
                    "configuration require validation."
                )
            ],
            ["Nmap", "OpenVAS / Nuclei", "Wazuh"],
            70,
        )
    else:
        put(
            "A.8.20",
            "Partially implemented",
            "Medium",
            [f"{m['assets_total']} assets inventoried."],
            ["Network-service and vulnerability coverage is incomplete."],
            ["Nmap", "OpenVAS / Nuclei"],
            45,
        )

    # A.8.21
    if m["service_coverage"] < 50:
        put(
            "A.8.21",
            "Insufficient evidence",
            "Medium",
            [f"Service inventory coverage is only {m['service_coverage']}%."],
            ["Run service/version detection and OpenVAS / Nuclei on more assets."],
            ["Nmap", "OpenVAS / Nuclei"],
            25,
        )
    elif m["network_findings"] > 0:
        put(
            "A.8.21",
            "Gap detected",
            "High",
            [
                f"Service inventory coverage is {m['service_coverage']}%.",
                f"{m['network_findings']} network-service findings were detected.",
            ],
            ["Treat insecure/obsolete services and validate service security requirements."],
            ["Nmap", "OpenVAS / Nuclei"],
            42,
        )
    elif m["scan_coverage"] >= 80:
        put(
            "A.8.21",
            "Likely implemented",
            "High",
            [
                f"Service inventory coverage is {m['service_coverage']}%.",
                f"OpenVAS / Nuclei scan coverage is {m['scan_coverage']}%.",
                "No matching network-service finding is stored.",
            ],
            ["Validate service-owner requirements, SLAs and provider agreements."],
            ["Nmap", "OpenVAS / Nuclei"],
            80,
        )
    else:
        put(
            "A.8.21",
            "Partially implemented",
            "Medium",
            [f"Service inventory coverage is {m['service_coverage']}%."],
            ["OpenVAS / Nuclei coverage or service governance evidence is incomplete."],
            ["Nmap", "OpenVAS / Nuclei"],
            58,
        )

    # A.8.22
    if len(m["unique_vlans"]) >= 2 and m["vlan_coverage"] >= 80:
        put(
            "A.8.22",
            "Partially implemented",
            "Medium",
            [
                f"{len(m['unique_vlans'])} VLAN/network segment identifiers are recorded.",
                f"VLAN metadata coverage is {m['vlan_coverage']}%.",
            ],
            [
                (
                    "Inter-segment firewall rules, trust boundaries and traffic tests "
                    "require validation."
                )
            ],
            ["Asset Management", "Nmap", "Manual evidence"],
            68,
        )
    elif m["vlan_coverage"] > 0:
        put(
            "A.8.22",
            "Partially implemented",
            "Low",
            [f"VLAN metadata coverage is {m['vlan_coverage']}%."],
            ["Segmentation evidence is incomplete or only one segment is represented."],
            ["Asset Management"],
            42,
        )
    else:
        put(
            "A.8.22",
            "Insufficient evidence",
            "Low",
            [],
            ["No VLAN/segment metadata is available in Asset Management."],
            ["Asset Management", "Network architecture"],
            5,
        )

    put(
        "A.8.23",
        "Insufficient evidence",
        "Low",
        [],
        [
            (
                "Web/DNS filtering policy, platform configuration and "
                "blocked-event evidence are required."
            )
        ],
        ["Secure web gateway", "DNS filtering", "Manual evidence"],
        5,
    )

    # A.8.24
    if m["crypto_findings"] > 0:
        put(
            "A.8.24",
            "Gap detected",
            "High",
            [
                f"{m['crypto_findings']}"
                f" TLS/certificate/cipher/cryptography findings were detected.",
                f"TLS-related ports detected: {sorted(m['tls_ports']) or 'none'}.",
            ],
            ["Remediate weak protocols/ciphers/certificates and validate key management."],
            ["Nmap", "OpenVAS / Nuclei"],
            35,
        )
    elif m["tls_ports"] and m["completed_scans"]:
        put(
            "A.8.24",
            "Partially implemented",
            "Medium",
            [
                f"TLS-related ports detected: {sorted(m['tls_ports'])}.",
                "Stored OpenVAS / Nuclei reports contain no matching crypto finding.",
            ],
            ["Key lifecycle, ownership, rotation and cryptographic policy require validation."],
            ["Nmap", "OpenVAS / Nuclei"],
            65,
        )
    else:
        put(
            "A.8.24",
            "Insufficient evidence",
            "Low",
            [],
            ["No sufficient cryptographic service evidence is available."],
            ["OpenVAS / Nuclei", "Manual evidence"],
            15,
        )

    # A.8.25-34
    if m["completed_scans"] and m["retested_assets"] > 0:
        put(
            "A.8.25",
            "Partially implemented",
            "Medium",
            [
                f"{m['completed_scans']} security scan report(s).",
                f"{m['retested_assets']} asset(s) have repeated testing evidence.",
            ],
            [
                (
                    "SDLC security gates, roles, threat modeling and release criteria "
                    "require validation."
                )
            ],
            ["OpenVAS / Nuclei", "SecureScope", "Manual evidence"],
            58,
        )
    elif m["completed_scans"]:
        put(
            "A.8.25",
            "Partially implemented",
            "Low",
            [f"{m['completed_scans']} security scan report(s) exist."],
            ["No proof that testing is integrated throughout the SDLC."],
            ["OpenVAS / Nuclei", "Manual evidence"],
            40,
        )
    else:
        put(
            "A.8.25",
            "Insufficient evidence",
            "Low",
            [],
            ["No technical security-testing evidence is available."],
            ["Manual evidence"],
            5,
        )

    if m["web_findings"] > 0:
        put(
            "A.8.26",
            "Partially implemented",
            "Medium",
            [
                f"{m['web_findings']}"
                f" web/application-related findings provide security requirement input."
            ],
            ["Approved application security requirements and traceability are required."],
            ["OpenVAS / Nuclei", "Manual evidence"],
            50,
        )
    else:
        put(
            "A.8.26",
            "Insufficient evidence",
            "Low",
            [],
            ["Application security requirements and approval records are required."],
            ["Manual evidence"],
            10,
        )

    put(
        "A.8.27",
        "Insufficient evidence",
        "Low",
        [
            (
                f"Network exposure and vulnerability data exists for {m['assets_total']} asset(s)."
                if m["assets_total"]
                else ""
            )
        ],
        ["Secure architecture principles, threat models and design reviews are required."],
        ["Architecture evidence", "Manual evidence"],
        15 if m["assets_total"] else 5,
    )
    put(
        "A.8.28",
        "Insufficient evidence",
        "Low",
        [],
        ["Secure coding standard, developer training, SAST and code-review evidence are required."],
        ["Source-control/SAST evidence", "Manual evidence"],
        5,
    )

    if m["completed_scans"] and m["retested_assets"] > 0:
        put(
            "A.8.29",
            "Likely implemented",
            "Medium",
            [
                f"{m['completed_scans']} completed OpenVAS / Nuclei report(s).",
                f"{m['retested_assets']} asset(s) have repeated test evidence.",
            ],
            [
                (
                    "Confirm that tests are performed in development/acceptance "
                    "environments with approved criteria."
                )
            ],
            ["OpenVAS / Nuclei", "SecureScope"],
            78,
        )
    elif m["completed_scans"]:
        put(
            "A.8.29",
            "Partially implemented",
            "Medium",
            [f"{m['completed_scans']} completed OpenVAS / Nuclei report(s)."],
            ["No repeated testing or development/acceptance linkage is available."],
            ["OpenVAS / Nuclei"],
            58,
        )
    else:
        put(
            "A.8.29",
            "Gap detected",
            "Medium",
            [],
            ["No completed security test report is available."],
            ["OpenVAS / Nuclei"],
            15,
        )

    put(
        "A.8.30",
        "Insufficient evidence",
        "Low",
        [],
        [
            (
                "Supplier contracts, security requirements, monitoring and "
                "acceptance records are required."
            )
        ],
        ["Supplier evidence", "Manual evidence"],
        5,
    )

    if len(m["unique_vlans"]) >= 3 and m["vlan_coverage"] >= 80:
        put(
            "A.8.31",
            "Partially implemented",
            "Low",
            [f"{len(m['unique_vlans'])} network segment identifiers are recorded."],
            [
                "Segments are not explicitly identified as development, test and production.",
                "Access restrictions require validation.",
            ],
            ["Asset Management", "Network architecture"],
            50,
        )
    else:
        put(
            "A.8.31",
            "Insufficient evidence",
            "Low",
            [],
            [
                (
                    "Development/test/production environment labels and segregation "
                    "evidence are required."
                )
            ],
            ["Manual evidence", "Network architecture"],
            5,
        )

    put(
        "A.8.32",
        "Insufficient evidence",
        "Low",
        [
            (
                f"{m['retested_assets']} asset(s) have repeated scan evidence."
                if m["retested_assets"]
                else ""
            )
        ],
        [
            (
                "Change requests, approvals, testing, rollback and "
                "emergency-change records are required."
            )
        ],
        ["Change-management evidence", "SecureScope"],
        15 if m["retested_assets"] else 5,
    )
    put(
        "A.8.33",
        "Insufficient evidence",
        "Low",
        [],
        ["Test-data selection, masking, access and disposal evidence are required."],
        ["Manual evidence"],
        5,
    )
    put(
        "A.8.34",
        "Partially implemented" if m["completed_scans"] else "Insufficient evidence",
        "Low",
        [
            (
                f"{m['completed_scans']} authorized scan report(s) are recorded."
                if m["completed_scans"]
                else ""
            )
        ],
        [
            (
                "Audit authorization, testing window, safeguards, scope approval "
                "and confidentiality evidence are required."
            )
        ],
        ["SecureScope", "Manual evidence"],
        35 if m["completed_scans"] else 5,
    )

    # Ensure exactly all 34 controls and preserve numeric order.
    return [
        result[control_id]
        for control_id in sorted(
            ISO_A8_CONTROLS,
            key=lambda value: int(value.split(".")[-1]),
        )
    ]


# ---------------------------------------------------------------------------
# PostgreSQL persistence for analyst reviews and assessment snapshots
# ---------------------------------------------------------------------------

_ISO_INITIALIZED = False
_ISO_INIT_LOCK = threading.Lock()
_ISO_DDL_LOCK_KEY = 74109004


class IsoAssessmentDatabaseError(RuntimeError):
    pass


def _database_url() -> str:
    url = os.getenv("SECURESCOPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise IsoAssessmentDatabaseError("Missing SECURESCOPE_DATABASE_URL or DATABASE_URL in .env")
    return url


@contextmanager
def _connect() -> Iterator[Any]:
    conn = None
    try:
        conn = psycopg2.connect(_database_url())
        yield conn
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        raise IsoAssessmentDatabaseError(str(exc)) from exc
    finally:
        if conn is not None:
            conn.close()


def init_iso_assessment_tables() -> None:
    """Create ISO assessment tables once with cross-process DDL locking."""
    global _ISO_INITIALIZED
    if _ISO_INITIALIZED:
        return

    with _ISO_INIT_LOCK:
        if _ISO_INITIALIZED:
            return

        init_database()
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(%s);",
                    (_ISO_DDL_LOCK_KEY,),
                )
                cur.execute(
                    (
                        "\n                    CREATE TABLE IF NOT EXISTS "
                        "securescope_iso_control_reviews (\n                        "
                        "id BIGSERIAL PRIMARY KEY,\n                        client_id "
                        "BIGINT NOT NULL REFERENCES securescope_clients(id) ON "
                        "DELETE CASCADE,\n                        control_id TEXT NOT "
                        "NULL,\n                        applicability TEXT NOT NULL "
                        "DEFAULT 'Not reviewed',\n                        "
                        "validated_status TEXT NOT NULL DEFAULT 'Not reviewed',\n     "
                        "                   owner TEXT,\n                        "
                        "reviewed_by TEXT,\n                        review_date "
                        "DATE,\n                        evidence_notes TEXT,\n         "
                        "               updated_at TIMESTAMPTZ NOT NULL DEFAULT "
                        "NOW(),\n                        UNIQUE(client_id, "
                        "control_id)\n                    );\n                    "
                    )
                )
                cur.execute(
                    (
                        "\n                    CREATE TABLE IF NOT EXISTS "
                        "securescope_iso_assessment_snapshots (\n                     "
                        "   id BIGSERIAL PRIMARY KEY,\n                        "
                        "client_id BIGINT NOT NULL REFERENCES "
                        "securescope_clients(id) ON DELETE CASCADE,\n                 "
                        "       payload JSONB NOT NULL,\n                        "
                        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n              "
                        "      );\n                    "
                    )
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS securescope_iso_corrective_actions (
                        id BIGSERIAL PRIMARY KEY,
                        action_uuid UUID NOT NULL UNIQUE,
                        client_id BIGINT NOT NULL
                            REFERENCES securescope_clients(id) ON DELETE CASCADE,
                        control_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        priority TEXT NOT NULL DEFAULT 'Medium',
                        status TEXT NOT NULL DEFAULT 'Open',
                        owner TEXT,
                        due_date DATE,
                        source TEXT NOT NULL DEFAULT 'Automated assessment',
                        evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        closed_at TIMESTAMPTZ,
                        UNIQUE(client_id, control_id, title)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_iso_actions_client_status
                    ON securescope_iso_corrective_actions (
                        client_id,
                        status,
                        priority,
                        updated_at DESC
                    );
                    """
                )

        _ISO_INITIALIZED = True


def _client_id(cur: Any, client_name: str) -> int:
    name = (client_name or "Default Client").strip() or "Default Client"
    cur.execute(
        """
        INSERT INTO securescope_clients (name)
        VALUES (%s)
        ON CONFLICT (name) DO UPDATE SET updated_at = NOW()
        RETURNING id;
        """,
        (name,),
    )
    row = cur.fetchone()
    if not row:
        raise IsoAssessmentDatabaseError("Could not resolve client workspace.")
    return int(row[0])


def load_iso_control_reviews(client_name: str) -> Dict[str, Dict[str, Any]]:
    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT
                    control_id,
                    applicability,
                    validated_status,
                    owner,
                    reviewed_by,
                    review_date::text AS review_date,
                    evidence_notes,
                    updated_at::text AS updated_at
                FROM securescope_iso_control_reviews
                WHERE client_id = %s;
                """,
                (client_id,),
            )
            return {str(row["control_id"]): dict(row) for row in cur.fetchall()}


def save_iso_control_review(
    client_name: str,
    control_id: str,
    applicability: str,
    validated_status: str,
    owner: str,
    reviewed_by: str,
    review_date: Optional[str],
    evidence_notes: str,
) -> None:
    if control_id not in ISO_A8_CONTROLS:
        raise ValueError(f"Unknown ISO control: {control_id}")
    if applicability not in APPLICABILITY_OPTIONS:
        raise ValueError(f"Invalid applicability: {applicability}")
    if validated_status not in VALIDATED_STATUSES:
        raise ValueError(f"Invalid validated status: {validated_status}")

    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                INSERT INTO securescope_iso_control_reviews (
                    client_id,
                    control_id,
                    applicability,
                    validated_status,
                    owner,
                    reviewed_by,
                    review_date,
                    evidence_notes,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (client_id, control_id)
                DO UPDATE SET
                    applicability = EXCLUDED.applicability,
                    validated_status = EXCLUDED.validated_status,
                    owner = EXCLUDED.owner,
                    reviewed_by = EXCLUDED.reviewed_by,
                    review_date = EXCLUDED.review_date,
                    evidence_notes = EXCLUDED.evidence_notes,
                    updated_at = NOW();
                """,
                (
                    client_id,
                    control_id,
                    applicability,
                    validated_status,
                    owner.strip(),
                    reviewed_by.strip(),
                    review_date or None,
                    evidence_notes.strip(),
                ),
            )


def merge_reviews(
    assessments: List[Dict[str, Any]],
    reviews: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    merged = []
    for assessment in assessments:
        item = dict(assessment)
        review = reviews.get(item["control_id"], {})
        item["applicability"] = review.get("applicability", "Not reviewed")
        item["validated_status"] = review.get("validated_status", "Not reviewed")
        item["owner"] = review.get("owner") or ""
        item["reviewed_by"] = review.get("reviewed_by") or ""
        item["review_date"] = review.get("review_date") or ""
        item["evidence_notes"] = review.get("evidence_notes") or ""
        item["review_updated_at"] = review.get("updated_at") or ""

        if item["applicability"] == "Not applicable":
            item["final_status"] = "Not applicable"
        elif item["validated_status"] != "Not reviewed":
            item["final_status"] = item["validated_status"]
        else:
            item["final_status"] = f"Pending validation — {item['automated_status']}"

        merged.append(item)
    return merged


def save_iso_assessment_snapshot(
    client_name: str,
    assessments: List[Dict[str, Any]],
) -> int:
    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                INSERT INTO securescope_iso_assessment_snapshots (client_id, payload)
                VALUES (%s, %s)
                RETURNING id;
                """,
                (client_id, Json(assessments)),
            )
            row = cur.fetchone()
            return int(row[0])


def latest_iso_assessment_snapshot(client_name: str) -> Optional[Dict[str, Any]]:
    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT id, payload, created_at::text AS created_at
                FROM securescope_iso_assessment_snapshots
                WHERE client_id = %s
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (client_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


# ---------------------------------------------------------------------------
# Continuous-assurance summaries and corrective actions
# ---------------------------------------------------------------------------


def maturity_level(score: Any) -> tuple[int, str]:
    """Map a 0-100 evidence score to a transparent maturity level."""
    try:
        value = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        value = 0.0
    if value >= 90:
        return 5, "Optimized"
    if value >= 75:
        return 4, "Measured"
    if value >= 55:
        return 3, "Defined"
    if value >= 35:
        return 2, "Managed"
    if value > 0:
        return 1, "Initial"
    return 0, "Non-existent"


def add_maturity(assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach maturity and stable display aliases to assessment rows.

    The assessment engine uses normalized snake_case keys.  The Streamlit UI
    and exported evidence files use human-readable aliases.  Keeping both
    prevents presentation changes from altering the evidence model.
    """
    output = []
    for assessment in assessments:
        item = dict(assessment)
        coverage_only = item.get("assessment_basis") == "Source coverage"
        level, label = (
            (None, "Human assessment required")
            if coverage_only
            else maturity_level(item.get("score") or item.get("Score"))
        )
        item["maturity_level"] = level
        item["maturity_label"] = label
        item["Maturity"] = label if coverage_only else f"{level} — {label}"
        item["Control"] = str(item.get("control_id") or item.get("Control") or "")
        item["Control name"] = str(item.get("control_name") or item.get("Control name") or "")
        item["Automatic status"] = str(
            item.get("automated_status") or item.get("Automatic status") or "Insufficient evidence"
        )
        item["Confidence"] = str(item.get("confidence") or item.get("Confidence") or "Low")
        item["Score"] = (
            None if coverage_only else float(item.get("score") or item.get("Score") or 0)
        )
        item["Evidence"] = item.get("evidence") or item.get("Evidence") or []
        item["Gaps"] = item.get("gaps") or item.get("Gaps") or []
        item["Sources"] = item.get("sources") or item.get("Sources") or []
        output.append(item)
    return output


def assessment_summary(assessments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate dashboard metrics from an assessment result set."""
    rows = add_maturity(assessments)
    total = len(rows)
    statuses: Dict[str, int] = {}
    scores: List[float] = []
    for row in rows:
        status = str(
            row.get("final_status")
            or row.get("automated_status")
            or row.get("Automatic status")
            or "Unknown"
        )
        statuses[status] = statuses.get(status, 0) + 1
        if row.get("assessment_basis") == "Source coverage":
            continue
        try:
            scores.append(float(row.get("score") or row.get("Score") or 0))
        except (TypeError, ValueError):
            scores.append(0.0)
    readiness = round(sum(scores) / len(scores), 1) if scores else 0.0
    maturity, maturity_label_value = maturity_level(readiness)
    return {
        "controls_total": total,
        "readiness_score": readiness,
        "maturity_level": maturity,
        "maturity_label": maturity_label_value,
        "status_counts": statuses,
        "gap_controls": sum(
            count
            for status, count in statuses.items()
            if "gap" in status.lower() or "not implemented" in status.lower()
        ),
        "partial_controls": sum(
            count for status, count in statuses.items() if "partial" in status.lower()
        ),
        "insufficient_evidence": sum(
            count for status, count in statuses.items() if "insufficient" in status.lower()
        ),
    }


def _action_priority(assessment: Dict[str, Any]) -> str:
    status = str(
        assessment.get("automated_status") or assessment.get("Automatic status") or ""
    ).lower()
    confidence = str(assessment.get("confidence") or assessment.get("Confidence") or "").lower()
    try:
        score = float(assessment.get("score") or assessment.get("Score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    if "gap" in status and confidence == "high":
        return "Critical"
    if "gap" in status or score < 25:
        return "High"
    if "partial" in status or score < 55:
        return "Medium"
    return "Low"


def synchronize_corrective_actions(
    client_name: str,
    assessments: List[Dict[str, Any]],
) -> int:
    """Create/update one actionable record for each current technical gap.

    Existing analyst workflow state and owner are preserved. When a control is
    no longer a gap, an open automated action is moved to ``Ready for
    verification`` rather than silently closed.
    """
    init_iso_assessment_tables()
    actionable = []
    healthy_controls = set()
    for assessment in assessments:
        control_id = str(assessment.get("control_id") or assessment.get("Control") or "")
        status = str(assessment.get("automated_status") or assessment.get("Automatic status") or "")
        if status in {"Gap detected", "Partially implemented"}:
            gaps = assessment.get("gaps") or assessment.get("Gaps") or []
            if isinstance(gaps, str):
                gaps = [gaps]
            actionable.append(
                (assessment, control_id, status, [str(g) for g in gaps if str(g).strip()])
            )
        else:
            healthy_controls.add(control_id)

    with _connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            for assessment, control_id, status, gaps in actionable:
                catalog = ISO_A8_CONTROLS.get(control_id, {})
                title = f"{control_id} — {catalog.get('name', 'ISO technical control')}"
                description = "\n".join(gaps) or (
                    f"SecureScope assessed this control as {status}. "
                    "Review the evidence and define a remediation plan."
                )
                priority = _action_priority(assessment)
                cur.execute(
                    """
                    INSERT INTO securescope_iso_corrective_actions (
                        action_uuid,
                        client_id,
                        control_id,
                        title,
                        description,
                        priority,
                        status,
                        source,
                        evidence
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 'Open',
                            'Automated ISO assessment', %s)
                    ON CONFLICT (client_id, control_id, title)
                    DO UPDATE SET
                        description = EXCLUDED.description,
                        priority = EXCLUDED.priority,
                        evidence = EXCLUDED.evidence,
                        updated_at = NOW();
                    """,
                    (
                        str(uuid.uuid4()),
                        client_id,
                        control_id,
                        title,
                        description,
                        priority,
                        Json(assessment),
                    ),
                )

            if healthy_controls:
                cur.execute(
                    """
                    UPDATE securescope_iso_corrective_actions
                    SET status = 'Ready for verification', updated_at = NOW()
                    WHERE client_id = %s
                      AND source = 'Automated ISO assessment'
                      AND control_id = ANY(%s)
                      AND status IN ('Open', 'In progress', 'Blocked');
                    """,
                    (client_id, sorted(healthy_controls)),
                )
    return len(actionable)


def list_corrective_actions(client_name: str) -> List[Dict[str, Any]]:
    """List corrective actions for one client workspace."""
    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                SELECT
                    id,
                    action_uuid::text AS action_uuid,
                    control_id,
                    title,
                    description,
                    priority,
                    status,
                    owner,
                    due_date::text AS due_date,
                    source,
                    evidence,
                    created_at::text AS created_at,
                    updated_at::text AS updated_at,
                    closed_at::text AS closed_at
                FROM securescope_iso_corrective_actions
                WHERE client_id = %s
                ORDER BY
                    CASE priority
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        ELSE 4
                    END,
                    updated_at DESC;
                """,
                (client_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def update_corrective_action(
    client_name: str,
    action_id: int,
    *,
    status: str,
    priority: str,
    owner: str = "",
    due_date: str | None = None,
    description: str | None = None,
) -> None:
    """Update analyst-owned workflow fields on one corrective action."""
    if status not in ACTION_STATUSES:
        raise ValueError(f"Invalid corrective-action status: {status}")
    if priority not in ACTION_PRIORITIES:
        raise ValueError(f"Invalid corrective-action priority: {priority}")

    init_iso_assessment_tables()
    with _connect() as conn:
        with conn.cursor() as cur:
            client_id = _client_id(cur, client_name)
            cur.execute(
                """
                UPDATE securescope_iso_corrective_actions
                SET status = %s,
                    priority = %s,
                    owner = %s,
                    due_date = %s,
                    description = COALESCE(%s, description),
                    closed_at = CASE
                        WHEN %s IN ('Closed', 'Accepted risk') THEN NOW()
                        ELSE NULL
                    END,
                    updated_at = NOW()
                WHERE id = %s AND client_id = %s;
                """,
                (
                    status,
                    priority,
                    owner.strip(),
                    due_date or None,
                    description,
                    status,
                    int(action_id),
                    client_id,
                ),
            )
            if cur.rowcount != 1:
                raise IsoAssessmentDatabaseError(f"Corrective action not found: {action_id}")
