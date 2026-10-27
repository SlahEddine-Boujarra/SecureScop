# Phased coding roadmap — vertical slices with acceptance gates

## M0 — Preflight / no feature edits initially
- Confirm exact repo root, current git status/branch, schema/version, tests, run instructions, worker health, user permissions and credentials configuration with secrets redacted. Backup DB and keep rollback branch. Identify source vs handoff differences.
- Baseline: `python -m compileall -q src tests`, `python -m pytest -q` (capture environment blockers rather than claiming green); scoped integration tests in dedicated PostgreSQL test schema only. Determine whether an existing AGENTS.md conflicts.

## M1 — Accurate SIEM status / asset identity (P0)
- Modify existing Wazuh service and persistence rather than adding a dedicated worker.
- Separate registered, active, telemetry-verified, stale, disconnected, unverified; exact identity matching; no ambiguous IP / fuzzy match automatic proof. Preserve raw agent status and timestamps.
- Remove automatic A.8.16 `'Implemented'` conclusion from monitoring summary. Keep factual coverage metrics, no false compliance decisions.
- Tests for no match, stale, active-no-observation, explicit verified observations, disconnected, duplicate IPs, cross-workspace, API/Indexer unavailable, no alerts and missing scope.
- Deliver one UI table and asset detail using real service data; never claim that no Wazuh agent means no monitoring anywhere.

## M2 — Wazuh automated evidence + Nuclei hardening (P0)
- Extend existing `wazuh_bridge.py`, normalizer, evidence worker and repositories: source trust, exact asset/scope, SHA-256, idempotency, temporal freshness, collection history and errors.
- Ensure completed Nuclei scan produces canonical evidence including zero findings; map conservative support/gap checks and keep JSONL raw artifacts. Support safe backfill of old completed scans.
- Confirm scopes mapped only with independent evidence. Missing scope => unassigned, not inferred cross-tenant association.
- A.8.15, A.8.16, A.8.17 mapping only from source-specific verified observation. Tests demonstrate explicit semantics.

## M3 — ISO Control Assurance (P0/P1)
- Requirement-specific evidence coverage, freshness and gap derivation; A.8.8 three distinct requirements (assessment, triage, remediation verification). Add/repair controlled machine-check requirement templates for A.8.5/A.8.9/A.8.24 without corrupting customized profiles.
- Source fact vs control conclusion separation; human assessment, scoped filters, correct asset links, no duplicate seeded requirements. SoA applicability and approved exclusion semantics.
- Integrate UI: `Collect new evidence` vs `Link existing evidence`, carry client/engagement/scope/control/requirement context, return to control profile correctly.

## M4 — ATLAS UX integration (P1)
- Shared shell, navigation, workspace scope, components and CSS hardening. Port ONE screen at a time into existing Streamlit/Components v2. Use real backend data.
- Priority screens: SIEM monitoring -> Evidence Register -> Control Profiles/Assess Control -> Asset Management/Classification -> Nmap -> Nuclei Scan Center -> Policy Builder -> Risk Register -> Governance -> Audit.
- Keep policy editing/suggestion/export working; original Nmap builder options; dual Risk matrices and original registers.

## M5 — Complete ISO lifecycle (P1)
- Verify real workflows/records for 9.1 monitoring/measurement, 9.2 internal audit, 9.3 management review, 10.2 corrective action, 7.2-7.4 support, 6.3 planned changes, 7.5 documented information, SoA and residual risk acceptance.
- Implement only gaps demonstrated by code/schema review; preserve governance sign-offs.

## M6 — hardening + demonstration (release gate)
- Threat model, host connector permissions, secret handling, audit events, encrypted settings, backups/restore, versioned docs, test environments, rate-limited scan jobs, access controls, tenancy, retry idempotency.
- Perform end-to-end demo: authorized Nmap discovery -> admitted asset -> Nuclei completed JSONL -> canonical evidence -> Wazuh verified monitoring -> scoped ISO requirement coverage/gaps -> consultant assessment -> auditable report. No silent compliance jumps.

## Working practices
Each milestone: (1) baseline inspection, (2) narrow plan, (3) migrations/spec, (4) tests, (5) implementation, (6) end-to-end tests, (7) screen captures, (8) summarized changed files/gaps/rollback. Review before proceeding to next milestone.
