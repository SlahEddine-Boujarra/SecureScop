# SecureScope v5.3.8.11 — Assurance & Remediation UX

## Navigation ownership

- **Control Assurance** is the single visible ISO control workspace.
- Evidence collection, consultant review, evidence requests and auditor packages are embedded in Control Assurance.
- The legacy A.8 technical engine is preserved as a contextual drill-down, not a parallel sidebar workspace.
- **Vulnerabilities** owns finding investigation and lifecycle.
- **Remediation** owns vulnerability treatment execution, verification and finding-specific risk acceptance.

## Remediation workflow

The primary workflow is:

`Triage → Plan → In progress → Verify → Closed`

Prioritization uses the existing deterministic SecureScope model: severity, CVSS, CISA KEV, EPSS, asset criticality, external exposure and age. Scanner remediation text remains advisory and is never executed directly.

Closure requires verification evidence. Accepted risk remains explicit, authorized and reviewable.

## Vulnerability workspace

The page is dashboard-first:

1. Active findings
2. Priority exposure
3. Exploit signals
4. Ready-to-verify work
5. Severity distribution and recent activity
6. Priority findings table
7. Secondary filters and lifecycle administration

## Page headers

Legacy full-width descriptive hero banners are replaced by compact title rows. Page-specific guidance stays close to the action it explains.

## Asset identity

Asset tables use **Asset tag** as the stable identity. Hostname remains available internally for discovery/correlation but is not displayed in Asset Management or Asset Discovery tables.
