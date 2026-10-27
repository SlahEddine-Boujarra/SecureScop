# SecureScope executive overview

## Purpose

SecureScope automates collection and normalization of technical security
evidence for vulnerability management and ISO/IEC 27001:2022 Annex A.8
assessment. Scanner findings are evidence inputs; analyst review and controlled
risk treatment remain explicit parts of the workflow.

## Business value

- One workspace per client with isolated assets, scans, findings, and reports.
- Persistent scan execution that continues independently of the browser.
- Consolidated visibility across OpenVAS, Nuclei, Nmap, and Wazuh.
- Repeatable ISO control evidence and audit-ready exports.
- Safer remediation through deterministic recipes, approvals, and verification.

## Technology

| Area | Technology |
|---|---|
| Application | Python 3.11, Streamlit |
| Persistence | PostgreSQL with versioned migrations |
| Discovery | Nmap |
| Vulnerability scanning | Greenbone/OpenVAS and ProjectDiscovery Nuclei |
| Endpoint/SIEM evidence | Wazuh |
| GRC synchronization | CISO Assistant |
| Reporting | ReportLab, OpenPyXL, ZIP evidence packages |

## Current evaluation status

Version 5.3.6 preserves the validated application behavior while introducing a
professional package layout, centralized filesystem paths, CI configuration,
security guidance, and a documented GitHub workflow. The application remains a
controlled evaluation build; production deployment should add centralized
authentication, secrets management, backup/restore automation, and formal
operational monitoring.

