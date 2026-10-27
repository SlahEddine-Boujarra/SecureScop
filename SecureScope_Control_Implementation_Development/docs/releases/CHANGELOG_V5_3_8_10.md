# SecureScope v5.3.8.10 — Functional Consolidation

## Purpose

Reduce duplicated workflows after the Exposure Overview rebuild while preserving
the original SecureScope technical-assurance architecture.

## Changes

- Routes **Vulnerabilities** to the canonical multi-scanner finding repository UI.
- Keeps the legacy sidebar navigation key for session-state compatibility while
  changing the visible label from **Reports & Findings** to **Vulnerabilities**.
- Adds KEV/EPSS decision signals and canonical trend analysis to the detailed
  vulnerability workspace.
- Removes duplicate **Corrective actions** and **Vulnerability intelligence** tabs
  from Technical Assurance.
- Technical Assurance now focuses on A.8 dashboard, control review, technical
  evidence, methodology and A.8 export.
- Routes technical-assurance follow-up to canonical Controls & SoA, Remediation and
  Evidence Hub workspaces.
- Removes duplicate A.8 audit-evidence ZIP UI; Evidence Hub owns auditor packages.
- Preserves the A.8-specific assurance PDF.
- Makes A.8 and Controls & SoA tab labels visible instead of icon-only navigation.
- Moves exposure lifecycle/remediation/governance audit history into Client History.
- Removes the old unrouted `render_reports_audit_page` presentation function.
- Removes CISO synchronization as a primary Client History KPI without removing the
  integration itself.

## Compatibility

- No database migration.
- No scanner worker changes.
- No OpenVAS/Nuclei/Wazuh evidence semantics changed.
- No ISO assessment status logic changed.
- Legacy A.8 corrective-action storage remains for snapshot/report compatibility.

## Validation

- Python source compilation succeeds.
- 173 automated tests pass.
