# Reproduce M3 development verification

Run from the application root in an isolated development workspace. All examples below use synthetic `.invalid`/documentation-IP sources and disposable database schemas. They do not execute Nuclei, contact Wazuh, enable production collection or approve a control.

## Environment and unit/component tests

Use supported Python 3.11/3.12 (the recorded run used 3.12), Node.js and npm:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q -ra
PYTHONPATH=src .venv/bin/python -m pytest -q tests/test_m3_assurance.py
npm ci --prefix tests/frontend
npm test --prefix tests/frontend
```

The full Python run without a database deliberately skips database tests. Do not interpret those skips as passes.

## Disposable embedded SQL demonstration

```bash
npm ci --prefix validation/m3/pglite
.venv/bin/python validation/m3/run_pglite.py -m pytest -q -s \
  tests/test_m1_evidence_postgres.py \
  tests/test_wazuh_monitoring_postgres.py \
  tests/test_m2_evidence_postgres.py \
  tests/test_m2_scheduling_postgres.py \
  tests/test_m2_upgrade_postgres.py \
  tests/test_m2_native_postgres.py \
  tests/test_m3_postgres.py \
  tests/test_m3_upgrade_postgres.py \
  tests/test_m3_native_postgres.py
```

The runner binds loopback, creates an in-memory PGlite database and injects the explicit test DSN only into the test process. Fixtures create and drop unique schemas, apply actual migrations and store encrypted artifacts in temporary directories. Native-only tests refuse to pass on this engine. `engine.json` records the engine identity, and `postgresql-compatibility.log` retains the executed demonstration output from this delivery.

## What the demonstrated path does

`test_scanner_artifact_to_exact_requirement_and_unchanged_decision` runs four cases through the existing Nuclei batch repository, actual ingestion service, canonical artifact store, attribution repository and requirement evaluator:

| Case | Input | Expected trace |
|---|---|---|
| A.8.8 | Successful empty JSONL | Scan-coverage PASS for the approved asset; SHA-256 of the empty artifact; no vulnerability/remediation conclusion |
| A.8.9 | Exact missing-header finding | Scoped technical FAIL with template/check/source/profile/asset IDs |
| A.8.24 | Exact expired-certificate finding | Scoped technical gap; no organization-wide crypto conclusion |
| A.8.5 | Exact Grafana default-login finding | Scoped authentication gap; no MFA/IAM conclusion |

Each case emits `M3 TRACE` JSON with actual source timestamps and artifact SHA-256. Synthetic job completion replaces real scanner execution; that boundary is intentional and explicitly unverified live. Repeated delivery returns the same evidence identity and one attribution. The seeded human assessment row remains unchanged.

`test_real_workspace_audit_is_idempotent_and_preserves_prior_decisions` then exercises the actual Control Assurance `load_workspace` and encrypted `record_evaluation` path. A new scoped finding produces Needs Review, preserves the existing Implemented and effective decision and earlier snapshot, and repeated unchanged evaluation does not add a duplicate.

The other M3 SQL cases demonstrate origin-scope isolation, profile changes before/after ingestion, approved-scope replacement, a newer draft, changed criterion digests, append-only ownership guards, corrupted encrypted bytes, job-state/target tampering, conservative empty-retest behavior and the 501-row read bound. The upgrade fixture seeds real M2 history, runs the actual checksum migration ledger and verifies no automatic backfill.

Preserved M2 SQL demonstrations exercise quiet-agent collection health through the existing Evidence Worker to protected Wazuh artifacts and exact A.8.16 evidence coverage. Active-agent-only remains unverified; a qualified health proof does not automatically satisfy A.8.15. M2 source recency and recovery fixtures remain included. Pure clock fixtures verify the existing path without claiming the deferred A.8.17 identity work is complete.

## Native PostgreSQL acceptance — still required

Use an explicitly disposable native database owned by the test principal. Supply `SECURESCOPE_TEST_DATABASE_URL` securely in the environment, then run:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q -ra
PYTHONPATH=src .venv/bin/python -m pytest -q -s \
  tests/test_m2_native_postgres.py tests/test_m3_native_postgres.py
```

The suite creates/drops test schemas; never point it at production. Native tests cover competing claims, killed-worker fencing/recovery, concurrent audit appends and duplicate Nuclei publication. They are supplied but **not validated in this environment**. Also complete the older ISMS/SoA native persistence tests and a database+artifact+key backup/restore rehearsal before deployment.

## Application review after approved deployment to a test environment

1. Apply migration 020 with the existing `securescope-migrate` entry point after a verified backup. Start the existing app and workers using the project's normal development setup.
2. Select the correct workspace, engagement and approved ISMS scope. Review the current Control Profile requirements, assign explicit canonical assets and choose the exact supported template predicates. Keep ordinary manual/documentary criteria intact.
3. Use the existing Collect New Evidence/Nuclei flow for an authorized target. Verify the resulting artifact and current scope/profile attribution in Evidence Register and Control Assurance.
4. Open a requirement's Technical details to inspect the reason, source check and missing assets. Download the technical-check JSON from the existing workspace. Compare the persisted human assessment shown separately.
5. Repeat with an approved profile revision and a new draft/approved scope transition. Old records must stay readable while their current eligibility changes. Review any recommendation manually; no treatment, risk acceptance or compliance approval is executed automatically.

These UI steps are a review script, not a claim that a real Streamlit/browser run occurred. Live source validation, authenticated worker hardening and production-release gates remain open. Do not enable production recurring collection as part of this demonstration.
