# M3 exact implementation changes

M2 baseline: `fc011fc604ff7d7fa6017b662c9cb1644b50a0aa`.
Implementation commits: `31e66f7`, `a47c16a` (documentation and validation packaging follow separately).
Machine-readable changed paths: `validation/m3/implementation-changes.txt`. The delivery also includes the complete baseline-to-delivery patch.

| File under application root | Change |
|---|---|
| `database/migrations/020_requirement_check_attribution.sql` | Add immutable source facts and requirement attributions with ownership/identity guards and indexes |
| `src/securescope/evidence/automated_checks.py` | Rule version 3; exact IDs/CVE pattern only; no tag/prefix authority |
| `src/securescope/evidence/nuclei_assurance.py` | New bounded JSONL source parser and conservative traceable criterion evaluator |
| `src/securescope/grc/assurance_requirements.py` | Validate reviewed selectors; route eligible Nuclei checks; incomplete-window guard; advisory/human fields and review signal |
| `src/securescope/grc/requirement_templates.py` | Four M3 controls get template version 3; customized criteria preserved and reviewed explicitly |
| `src/securescope/persistence/requirement_evidence_repository.py` | New queue target capture, immutable source attribution and read-time source/current-context verification |
| `src/securescope/persistence/nuclei_persistence.py` | Capture server-derived target snapshots in existing job payload; formatting of existing SQL calls only elsewhere |
| `src/securescope/persistence/evidence_repository.py` | Capture first source; scope links from actual attribution; prevent replay fan-out/history rewriting; verify Nuclei currency on reads |
| `src/securescope/persistence/assurance_workspace_repository.py` | Current approved scope pointer; detect truncated source window at 501 rows |
| `src/securescope/ui/control_workspace.py` | Reviewed predicate selector and JSON technical-trace export within existing workspace |
| `src/securescope/ui/components_v2/assurance_workbench.js` | Explainable technical details; advisory label and separate recorded human decision |
| `tests/test_m3_assurance.py` | 32 deterministic rule/identity/freshness/negative-proof/baseline cases |
| `tests/test_m3_postgres.py` | 12 parameterized real SQL/artifact/repository/history/isolation cases |
| `tests/test_m3_upgrade_postgres.py` | Seeded 001–019 to 020 ledger upgrade, repeatability and retained historical rows |
| `tests/test_m3_native_postgres.py` | Native-only competing Nuclei publication gate; explicitly skipped here |
| `tests/frontend/m3_assurance.test.mjs` | Advisory/human distinction, trace rendering and escaped endpoint regression |
| `tests/test_correction_pass_20261005.py` | Source-backed fixtures; exact auth ID; unassigned candidate semantics; JSON-stable asset-result keys |
| `tests/test_m1_evidence_postgres.py` | Correct the evaluated requirement ID to the actual persisted approved identity |
| `tests/test_m2_upgrade_postgres.py` | Keep historical M2 upgrade fixture limited to migrations 018/019 |
| `tests/test_nuclei_evidence_pipeline.py` | Explicit repository eligibility facts in pure evaluator fixture |
| `tests/test_requirement_templates.py` | Expect per-control baseline version rather than one global version |

Other delivery changes are the M3 plan copy, this change list, acceptance/eligibility/demo documentation, validation logs and runner, and reconciliation of the previously stale application-local SHA-256 manifest. No prior migration, Wazuh collector, clock identity module, Evidence Worker scheduler, Nmap implementation, policy workflow or risk-management implementation is rewritten.
