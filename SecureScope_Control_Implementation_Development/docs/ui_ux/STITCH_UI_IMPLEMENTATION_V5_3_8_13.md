# SecureScope v5.3.8.13 — Stitch UI Foundation

## Purpose

This release translates the approved Stitch visual direction into the existing
Streamlit application without importing Tailwind, Google Fonts, external avatar
URLs, or Material Symbols webfonts into the production runtime.

The design is a presentation evolution. PostgreSQL schema, workspace isolation,
Nmap discovery, OpenVAS, Nuclei, Wazuh, canonical findings, Control Assurance,
Evidence, Gap Actions, Statement of Applicability, Risk Treatment, remediation,
and reporting workflows remain authoritative.

## Design tokens

- Application background: `#f8f9ff`
- Primary surface: `#ffffff`
- Main text: `#0b1c30`
- Muted text: `#667085`
- Primary teal: `#00685f`
- Assurance navy: `#0f172a`
- Border: `#e2e8f0`
- Field border: `#cbd5e1`
- Desktop content maximum: 1440 px
- Desktop gutter: 24 px
- Standard radius: approximately 10 px
- Font stack: Inter first, then Windows-native Segoe UI Variable/Segoe UI and
  system fallbacks.

## Shared navigation

The visible sidebar is intentionally small:

1. Command Center
2. Exposure Overview
3. Programme Foundation
4. Control Assurance
5. Asset Management
6. Scan Center
7. Vulnerabilities
8. SIEM
9. Remediation
10. Reports & Audit
11. Client Workspace

Asset Discovery, detailed A.8 Technical Assurance, and the standalone Evidence
Hub remain internal/contextual routes. Their functionality has not been removed.

## Command Center

The Command Center is a programme decision surface:

- Programme Foundation
- Controls Assessed
- Open Gaps
- Evidence Coverage
- Certification Journey
- Human Control Assurance distribution
- Technical Assurance coverage
- compact Programme Attention

The primary action is state-aware. It routes to Programme Foundation, Control
Assurance, Evidence, Gap Actions, or audit preparation according to current data.

Technical source cards show coverage when coverage can be calculated. Missing
engine-specific or Wazuh telemetry is rendered as unavailable rather than zero.

## Exposure Overview

Exposure Overview now follows the approved decision hierarchy:

- Active Vulnerabilities
- Priority Findings
- Scan Coverage
- Monitoring Coverage
- Exposure by Severity
- Actionable Risk Triggers
- Most Affected Assets
- Coverage Gaps
- Priority Findings

Canonical findings remain the source for current vulnerability posture so repeat
OpenVAS/Nuclei observations do not inflate counts. Asset Tag is the primary
identity and hostname is excluded from the default affected-assets table.

Coverage Gaps means in-scope assets missing scan/monitoring evidence. It does not
mean the assets are outside the approved ISMS scope.

## Control Assurance

Control Assurance keeps all six professional workflows:

- Control Profiles
- Assess Control
- Evidence
- Gap Actions
- Statement of Applicability
- Risk Treatment Plan

The Control Profiles table explicitly separates:

- SecureScope recommendation
- Human assessment

SecureScope recommendation labels are advisory (`Likely implemented`, `Partial
support`, `Gap signal`, `Insufficient evidence`, or `Manual review`). They are not
derived by copying the human assessment result.

All existing Evidence, Gap Action, SoA and RTP forms/tables remain intact.

## Programme Foundation

The overview now follows the consultant-facing lifecycle:

`Discover → Suggest → Review → Approve`

The primary action is calculated from the actual missing foundation requirement.
Formal Context, Interested Parties, Scope, Roles/RACI, Engagement, and other
registers remain available and are not replaced by the summary cards.

Missing information is visually treated as input-needed/warning state rather
than as a security failure.

## Production implementation rule

Stitch HTML is a design reference only. Production uses Streamlit widgets and
local CSS. No CDN dependency is required for fonts or icons, preventing the raw
icon-name and HTML-rendering failures encountered in earlier UI revisions.
