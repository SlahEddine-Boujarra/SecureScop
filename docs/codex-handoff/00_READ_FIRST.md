# READ FIRST — Codex development handoff (2026-10-15)

## What this pack is
A structured transfer of the SecureScope decisions made in a long ChatGPT design/development discussion. It is **not a complete chat transcript, audited specification, live-code patch, or certification attestation**. It is designed to give Codex durable, precise context while Codex independently verifies the checked-out code and user requirements.

## Inputs and authority
1. **Current checked-out SecureScope source code and actual database schema** are authoritative for the present implementation. Never overwrite work solely because a dated archive differs.
2. Source reference reviewed while preparing this handoff: `SecureScope_Control_Implementation_Development (21).zip` (its README states evaluation build v5.4.9.dev0 / remediation in progress). Important files were inspected to verify module locations and two specific Wazuh status problems.
3. Approved design reference: `SecureScope_ATLAS_v10_Offline_Compliance_Classification.zip`, plus later decisions in `03_UX_DECISIONS.md` (v10 is the latest archived offline design here; some later guidance is newer than its pixels).
4. ISO mapping rules here are **deliberately conservative**. A source may show technical coverage/gaps, never issue automatic ISO compliance decisions.

## User priorities in order
1. Automated technical evidence collection and traceability, including SIEM asset monitoring, are SecureScope's product differentiator.
2. ISO/IEC 27001:2022 assurance with real clause 4–10 ISMS workflows, 93 Annex A controls, approved SoA, risk treatment and auditable consultant judgments.
3. Reliable authorized security scanning (Nmap and Nuclei) plus Wazuh API monitoring; precise factual states in Asset Management and SIEM.
4. Professional enterprise UX; preserve useful existing screens/functions rather than sacrificing workflow for cosmetic similarity.
5. Safe incremental integration, no regression or data loss.

## First action for Codex
Inventory the repository, current branch, existing tests, current schema and all relevant modules; compare to `01_ARCHITECTURE.md` and `02_EVIDENCE_AND_ISO_RULES.md`. Produce a short verified/partially implemented/missing table **with file references**. Then implement only Milestone 1, after user approval if the repo is risky or findings conflict with assumptions.

## Terminology and critical distinctions
- Workspace / Client, Engagement, approved ISMS Scope and Asset are distinct contexts. Asset in inventory is not automatically in ISMS scope.
- Source trust: confidence in authenticity/provenance of a machine-collected artifact. Requirement coverage: relevant technical condition measured/tested for the correct scoped asset at a suitable time. Human assessment: assessor's professional ISO conclusion. Do not conflate.
- Policy library: compact list; Policy Builder: suggestions | editable Word-like document. Approval/version history retained in data even when not prominent in library UI.
- Asset classification is independent from scope and from vulnerability severity: `Criticality` (impact to business) and `Information sensitivity` (data classification) are separate governed fields.

## Final completion standard
Evidence -> scope association -> requirement check -> UI and historical audit trail -> human assessment must all function under workspace authorization. A visually correct page backed by fake metrics is not a completed feature.
