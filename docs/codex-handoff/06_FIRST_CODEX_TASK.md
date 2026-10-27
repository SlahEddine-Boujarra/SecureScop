# M1 task request — Verified Wazuh monitoring coverage

## Objective
Implement accurate per-asset Wazuh monitoring status and transparent ISO evidence *coverage* without making automatic compliance assertions.

## Files to inspect first
`src/securescope/integrations/wazuh_service.py`, `src/securescope/persistence/db_wazuh_service.py`, `src/securescope/evidence/wazuh_bridge.py`, `src/securescope/evidence/continuous_assurance.py`, SIEM and Asset Management presenters, migrations, tests, and auth/workspace repositories. Detect renamed modules in the current branch.

## Behavior changes
- Replace unmatched agent `Not monitored` with `Monitoring not verified` / state code; distinct active/telemetry-verified/stale/disconnected states. Agent alone is insufficient.
- Agent identity linking deterministic, reject duplicate/ambiguous IP/hostname and fuzzy matches as verified proof. Preserve candidates for review if existing workflows support them.
- Derive last-seen/freshness from source timestamps/configured policy; show source health/error when API unavailable. No-event ≠ no-monitoring.
- Change A.8.16 automatic summary from `Implemented`/`Partial` control conclusion to coverage-specific result; keep any approved human assessment untouched.
- Surface accurate source-backed status in SIEM and Asset Management, plus ISO requirement coverage where existing evidence bridge warrants. No new Wazuh worker.
- Include additively persisted monitoring snapshot/collection history if the existing tables do not already support required fields.

## Security/acceptance
Tests for no agent, active but no telemetry, verified relevant log evidence, stale, disconnected, ambiguous identities, API failure and tenants. No scope inference. Never persist plaintext credentials or fetch unrelated workspaces. Do not start unauthorized scans.

## Deliverables
(1) plan and file impact, (2) changes with migrations if necessary, (3) tests + exact results, (4) user-facing screenshots or honest caveat, (5) remaining risks and next milestone suggestion.

## First response from Codex should be
"I read AGENTS.md and docs/codex-handoff. Here is what the current repository already implements, what is missing and which exact files I intend to edit. I'll first verify the Wazuh behavior and affected tests, then implement M1 with minimal changes."
