# Annex A.8 control/evidence matrix

This matrix is generated from the control catalogue implemented in
`iso_control_assessment_service.py`.

| Control | Name | Automated technical scope |
|---|---|---|
| A.8.1 | User end point devices | Nmap endpoint inventory, OS identification, Wazuh agent coverage and endpoint-related OpenVAS findings. |
| A.8.2 | Privileged access rights | Exposed administrative services and authentication/privilege-related OpenVAS findings. RBAC and access reviews require manual evidence. |
| A.8.3 | Information access restriction | Exposed services and access-control findings. Authorization matrices and periodic reviews require manual evidence. |
| A.8.4 | Access to source code | Not reliably assessable by Nmap/OpenVAS. Repository permissions and branch protections require manual or API evidence. |
| A.8.5 | Secure authentication | Authentication, weak credential, TLS and exposed login service findings. MFA configuration requires manual evidence. |
| A.8.6 | Capacity management | Limited Wazuh/system telemetry evidence. Capacity thresholds, forecasts and plans require operational evidence. |
| A.8.7 | Protection against malware | Wazuh endpoint monitoring coverage and malware-related findings. Antivirus policy and response testing require manual evidence. |
| A.8.8 | Management of technical vulnerabilities | Strong technical coverage from OpenVAS reports, CVSS/CVE data, asset coverage, findings and re-scan history. |
| A.8.9 | Configuration management | Nmap service inventory, OpenVAS configuration findings and Wazuh monitoring. Approved baselines and change authorization require manual evidence. |
| A.8.10 | Information deletion | Not reliably assessable by network/vulnerability scanning. Retention schedules and deletion evidence are required. |
| A.8.11 | Data masking | Not reliably assessable by Nmap/OpenVAS. Application, database and test-data evidence is required. |
| A.8.12 | Data leakage prevention | Network exposure can indicate risk, but DLP policies, channels and alerts require dedicated/manual evidence. |
| A.8.13 | Information backup | Backup-related findings can indicate gaps. Backup schedules, restore tests and retention require manual evidence. |
| A.8.14 | Redundancy of information processing facilities | Limited network visibility only. Architecture, failover and recovery-test evidence are required. |
| A.8.15 | Logging | Wazuh monitoring coverage, timestamps, alert evidence and SecureScope scan/report history. |
| A.8.16 | Monitoring activities | Strong evidence from active Wazuh agents, alerts, asset coverage and repeated security scans. |
| A.8.17 | Clock synchronization | Wazuh endpoint time-service state, source, offset, manager/agent delta and evidence freshness; direct NTP server tests remain supporting evidence only. |
| A.8.18 | Use of privileged utility programs | Not reliably assessable by Nmap/OpenVAS. Application allowlisting, execution logs and approvals are required. |
| A.8.19 | Installation of software on operational systems | Service/software inventory and obsolete-software findings provide partial evidence. Approval workflows require manual evidence. |
| A.8.20 | Networks security | Nmap exposure inventory, OpenVAS network findings and Wazuh monitoring provide meaningful technical evidence. |
| A.8.21 | Security of network services | Nmap service/version inventory and OpenVAS service findings provide strong technical evidence. |
| A.8.22 | Segregation of networks | VLAN/subnet inventory and exposure evidence provide partial evidence. Firewall rules and architecture require validation. |
| A.8.23 | Web filtering | Not reliably assessable by Nmap/OpenVAS. Secure web gateway, DNS filtering and policy evidence are required. |
| A.8.24 | Use of cryptography | OpenVAS TLS/certificate/cipher findings provide technical evidence. Key-management governance requires manual evidence. |
| A.8.25 | Secure development life cycle | Security scan evidence can support the SDLC, but process gates, roles and lifecycle records require manual evidence. |
| A.8.26 | Application security requirements | Application findings help identify requirements. Approved requirement specifications require manual evidence. |
| A.8.27 | Secure system architecture and engineering principles | Technical exposure can identify architectural weaknesses, but design principles and reviews require manual evidence. |
| A.8.28 | Secure coding | Network/OpenVAS findings cannot prove secure coding. SAST, code review and coding-standard evidence are required. |
| A.8.29 | Security testing in development and acceptance | OpenVAS testing and repeated reports provide technical test evidence. Environment and acceptance linkage require validation. |
| A.8.30 | Outsourced development | Not assessable by Nmap/OpenVAS. Contracts, supplier reviews and delivery evidence are required. |
| A.8.31 | Separation of development, test and production environments | VLAN/subnet and asset labels may provide partial evidence. Architecture and access restrictions require validation. |
| A.8.32 | Change management | Scanner deltas may show technical changes, but approvals, testing and rollback evidence are required. |
| A.8.33 | Test information | Not reliably assessable by network/vulnerability scanning. Data selection, masking and access evidence are required. |
| A.8.34 | Protection of information systems during audit testing | SecureScope records authorized targets and scan evidence, but approvals, windows, safeguards and confidentiality require validation. |

Automated evidence is never treated as proof of organizational process or
management approval. Controls with insufficient technical evidence remain
available for analyst review and manual evidence.
