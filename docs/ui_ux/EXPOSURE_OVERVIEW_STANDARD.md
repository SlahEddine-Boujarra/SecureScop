# SecureScope Exposure Overview Standard

## Purpose

Exposure Overview is a decision dashboard. It must answer three questions quickly:

1. What is exposed now?
2. What is not covered by SecureScope evidence sources?
3. What requires action next?

It is not a scanner-administration page, SIEM configuration page, historical report browser, CISO synchronization page, or ISO programme dashboard.

## Information hierarchy

### Tier 1 — Current posture

The top row contains only:

- active canonical vulnerabilities;
- Critical + High priority findings;
- current vulnerability scan coverage of inventoried assets;
- Wazuh monitoring coverage of inventoried assets.

### Tier 2 — Decision context

- Recommended next step: exactly one primary action.
- Exposure posture: canonical severity distribution plus exploit/age signals.
- Coverage & sources: scan coverage, Wazuh coverage and compact OpenVAS/Nuclei health.
- Needs action: only actionable conditions, not every system status.

### Tier 3 — Investigation

- Exposure concentration by asset.
- Priority findings table.
- Vulnerability-age distribution.

### Tier 4 — Audit detail

Recent scan history remains available in a collapsed expander. Historical reports must not visually compete with current posture.

## Data rules

- Current vulnerability metrics use the canonical finding repository so repeated OpenVAS/Nuclei observations do not inflate counts.
- Historical scanner reports remain traceable but do not define current canonical exposure.
- Missing enrichment must render as unavailable, never as zero.
- Wazuh coverage is not inferred when there is no current Wazuh snapshot.
- Duplicate inventory IPs produce one concise data-quality warning; the detailed repair workflow belongs in Asset Management.

## Removed from Exposure Overview

The following information remains available elsewhere and must not dominate this page:

- CISO Assistant synchronization coverage;
- NTP / clock synchronization;
- full scanner-fabric campaign tables;
- raw duplicate-IP register;
- general ISO control gaps;
- multiple competing quick-action buttons;
- expanded historical scan tables.

## Priority finding table

Default columns:

| Column | Purpose |
| --- | --- |
| Severity | Immediate technical priority |
| Finding | Human-readable issue |
| Asset | Business/technical target |
| CVSS | Technical severity context |
| Exploit signal | KEV or high-EPSS prioritization |
| Source | Scanner provenance |
| Last seen | Freshness |

Detailed lifecycle, port/service, evidence and remediation fields belong in Reports & Findings.

## Action hierarchy

Exposure Overview renders one primary recommended action based on the current state:

1. Discover assets if the inventory is empty.
2. Complete scan coverage if inventory assets are unscanned.
3. Review Critical/High findings.
4. Resolve overdue remediation.
5. Monitor active scans.
6. Otherwise show a current/healthy state with no forced action.
