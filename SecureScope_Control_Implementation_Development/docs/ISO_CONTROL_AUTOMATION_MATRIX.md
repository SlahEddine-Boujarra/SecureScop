# ISO control automation matrix

This matrix defines the default collection route, not a compliance verdict.
Every requirement needs Consultant validation of design, implementation, scope
and effectiveness. The exact evidence requirements remain client- and
scope-specific and must be interpreted using a licensed copy of the standard.

## ISMS clauses 4–10

All 30 assessable requirements under clauses 4–10 are **Manual**:

`4.1–4.4`, `5.1–5.3`, `6.1.1–6.1.3`, `6.2`, `6.3`, `7.1–7.4`,
`7.5.1–7.5.3`, `8.1–8.3`, `9.1`, `9.2.1`, `9.2.2`, `9.3.1–9.3.3`,
`10.1`, and `10.2`.

Examples include context and climate relevance, interested parties, scope,
leadership, risk methodology and treatment, objectives, competence, awareness,
document control, operational planning, measurement, internal audit, management
review, continual improvement and corrective action.

## Annex A controls with hybrid evidence support

The following 44 controls have at least one defensible technical, API or
ticketing source. They remain **Hybrid**:

`A.5.7`, `A.5.9`, `A.5.15–A.5.18`, `A.5.23–A.5.28`, `A.5.30`,
`A.5.36`, `A.6.8`, `A.7.4`, `A.8.1–A.8.9`, `A.8.13`, `A.8.15–A.8.29`,
`A.8.31`, `A.8.32`, and `A.8.34`.

The explicit machine-readable list and source mapping is in
`src/securescope/grc/control_catalog.py`.

| Evidence area | Sources | Principal supported controls |
|---|---|---|
| Discovery and attack surface | Nmap, Amass, theHarvester, DNSRecon | A.5.7, A.5.9, A.8.20–A.8.22 |
| Infrastructure vulnerability | OpenVAS, Nuclei | A.8.7–A.8.9, A.8.16, A.8.20, A.8.21, A.8.24, A.8.29 |
| Web application security | ZAP, Nikto, Wapiti, Droopescan | A.5.17, A.8.5, A.8.8, A.8.16, A.8.23, A.8.24, A.8.26, A.8.29 |
| Endpoint, SIEM and incident | Wazuh | A.5.7, A.5.9, A.5.15, A.5.16, A.5.18, A.5.24–A.5.28, A.5.30, A.6.8, A.7.4, A.8.1, A.8.2, A.8.6–A.8.9, A.8.13, A.8.15–A.8.21 |
| Clock assurance | Wazuh and NTP evidence | A.8.17 |
| Host compliance | Lynis, OpenSCAP | A.5.36, A.8.1–A.8.3, A.8.7–A.8.9, A.8.13, A.8.18, A.8.19 |
| Cloud posture | Prowler, ScoutSuite | A.5.15, A.5.16, A.5.18, A.5.23, A.8.2, A.8.3, A.8.5, A.8.20, A.8.22, A.8.24, A.8.27, A.8.31 |
| Containers and dependencies | Trivy, Grype, OSV-Scanner | A.5.23, A.8.8 |
| Source code and SDLC | Semgrep CE, Bandit, SonarQube Community, GitLab CE | A.8.4, A.8.25–A.8.29, A.8.31, A.8.32 |
| Incident/remediation records | Redmine, GLPI, GitLab CE | A.5.24, A.5.26, A.5.27, A.6.8, A.8.32 |
| Authorized security-test imports | Metasploit, BeEF, Atomic Red Team | A.5.25, A.5.28, A.8.29, A.8.34 |

## Annex A controls defaulting to manual evidence

The following 49 controls are **Manual** by default:

`A.5.1–A.5.6`, `A.5.8`, `A.5.10–A.5.14`, `A.5.19–A.5.22`, `A.5.29`,
`A.5.31–A.5.35`, `A.5.37`, `A.6.1–A.6.7`, `A.7.1–A.7.3`,
`A.7.5–A.7.14`, `A.8.10–A.8.12`, `A.8.14`, `A.8.30`, and `A.8.33`.

Typical proof includes approved policies and procedures, responsibilities,
contracts, risk decisions, HR records, training records, interviews, physical
inspection, sampled transactions, management minutes and effectiveness tests.

## Assessment rule

Tool evidence can suggest `Likely implemented`, `Partially implemented`, `Gap
detected`, `Insufficient evidence`, or `Evidence expired`. Only an authorized
Consultant can finalize implementation status. `Not applicable` requires a
written justification and approval; no source tool can decide it.
