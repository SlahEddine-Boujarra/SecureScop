# SecureScope functional repetition audit

## Consolidation state in v5.3.8.10

The cleanup separates summary, investigation, assurance, governance and records
workspaces. Duplicate user workflows are removed only when an existing canonical
workspace already has the required functionality.

### Exposure Overview vs Vulnerabilities — intentional summary/detail split

- **Exposure Overview** answers: what is exposed, what is uncovered, and what needs action now.
- **Vulnerabilities** is the canonical multi-scanner finding inventory and lifecycle workspace.

The old report-centric **Reports & Findings** screen is no longer routed. The
sidebar now shows **Vulnerabilities**, while the internal navigation key remains
compatible with existing Streamlit session state.

### Controls & SoA vs Technical Assurance — intentional governance/assurance split

- **Controls & SoA** owns 93-control governance: control profiles, human assessment,
  control gaps, Statement of Applicability and Risk Treatment Plan.
- **Technical Assurance** owns the original A.8 evidence-to-control reasoning based
  on Nmap, OpenVAS/Nuclei, Wazuh, clock evidence and analyst validation.

Technical Assurance no longer contains a second corrective-action workspace or a
second CVE-intelligence workspace. Follow-up now routes to the canonical
**Controls & SoA**, **Remediation**, **Vulnerabilities** and **Evidence Hub**
workspaces as appropriate.

### Remediation ownership

- **Gap actions** are governance actions for ISO control gaps.
- **Remediation** is the technical finding remediation workspace with plans, tasks,
  milestones, verification and approved execution.

The legacy A.8 corrective-action persistence remains available internally for old
snapshots and A.8 PDF compatibility, but it is no longer presented as a competing
user workflow. A future data migration can retire that storage model after legacy
snapshot/report compatibility is no longer needed.

### Evidence and export ownership

- **Evidence Hub** is the canonical place for evidence collection, review, requests
  and auditor packages.
- **Technical Assurance** keeps only the A.8-specific assurance PDF export.

The duplicate A.8 evidence ZIP download was removed from the Technical Assurance UI.

### Records ownership

- **Client History** now owns workspace asset history, scanner history and the
  lifecycle/remediation/governance audit trail.
- The old unrouted `render_reports_audit_page` presentation function was removed.

### Remaining technical debt

1. The legacy `securescope_iso_corrective_actions` model remains for compatibility
   with saved A.8 snapshots/PDFs. It should eventually be migrated into canonical
   control-gap/remediation records.
2. CISO Assistant synchronization is still supported, but it should stay in
   integration-specific workflows rather than reappearing as a primary exposure or
   history KPI.

## Product rule

Before adding a new page or action, classify it as exactly one of:

- **summary** — current decision dashboard,
- **investigation** — detailed technical records,
- **assurance** — evidence-to-control reasoning,
- **governance** — human ISO decisions and treatment,
- **records** — historical/audit memory,
- **legacy duplicate** — same outcome and same data lifecycle as another workspace.

Only the final category should create a deletion/consolidation task.
