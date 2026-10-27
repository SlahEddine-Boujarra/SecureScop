# M2 operations and reproducible demonstration

Run commands from the extracted application root. This guide describes development verification; production recurring execution remains disabled. Native database and live integration commands below are reproducible instructions, **not claims they were executed here**.

## Environment and migrations

Use Python 3.11 or 3.12 and a virtual environment. Install the existing application and development dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
export PYTHONPATH=src
```

Supply `SECURESCOPE_DATABASE_URL` through your existing protected development configuration. Back up the database before applying migrations to an existing installation. On a disposable native database restored from M1, run:

```bash
python -m securescope.cli.run_migrations
python -m securescope.cli.run_migrations
```

The first run applies 018/019 if the M1 ledger is current. The second applies nothing. Preserve migrations 001–017 and their existing ledger checksums. There is no destructive down migration. For rollback, stop workers and restore a consistent database/artifact/key backup; do not drop new tables while retaining jobs that refer to them. Do not resume an old worker binary against enabled M2 schedules.

## Reproduce the synthetic end-to-end demonstration

Node/npm are required only for the supplemental embedded database harness. Install its pinned dependencies, then run the packaged test:

```bash
npm ci --prefix validation/m2/pglite
python validation/m2/run_pglite.py -m pytest -q -s \
  tests/test_m2_evidence_postgres.py::test_quiet_agent_protected_evidence_reaches_exact_control_assurance
```

Expected output includes:

```text
M2 E2E: quiet agent -> protected artifact -> exact A.8.16 requirement PASS; A.8.15 excluded.
1 passed
```

The fixture creates disposable M1/M2 schema, an approved exact scope/profile target, a synthetic quiet agent and a validated canary. It queues a job, claims it and invokes the same typed handler used by the Evidence Worker. It verifies encrypted artifact bytes and SHA-256, canonical evidence, exact requirement eligibility and the actual Control Assurance load/evaluation path. It asserts that the seeded human assessment and decision-table snapshots remain unchanged. The live Wazuh client and request-admission wait are replaced; no network transport or real worker-process concurrency is proved by this demonstration. Its database is discarded afterward, so no persistent demo evidence appears in your real workspace.

Reproduce the selected actual-schema suite:

```bash
python validation/m2/run_pglite.py -m pytest -q -s \
  tests/test_m2_evidence_postgres.py \
  tests/test_m2_scheduling_postgres.py \
  tests/test_m2_upgrade_postgres.py \
  tests/test_m2_native_postgres.py \
  tests/test_m1_evidence_postgres.py \
  tests/test_wazuh_monitoring_postgres.py
```

Recorded result: 25 passed, three native-only tests skipped. PGlite is PostgreSQL compiled to WebAssembly and remains supplemental. Its runner writes `engine.json` and a server log and has a 180-second child-command limit.

Run non-live regressions with:

```bash
python -m pytest -q
node --test tests/frontend/*.test.mjs
```

With no dedicated test database configured, the recorded Python run is 850 passed/33 skipped; frontend is 50 passed. Test counts may change after future edits. Keep executed output with each verification.

## Mandatory native PostgreSQL verification

Use an isolated disposable native PostgreSQL database and a role allowed to create/drop test schemas. Set `SECURESCOPE_TEST_DATABASE_URL` to that database using your secret-management mechanism. Never point these tests at production. On Linux, run:

```bash
python -m pytest -q -s \
  tests/test_m2_native_postgres.py \
  tests/test_m2_scheduling_postgres.py \
  tests/test_m2_evidence_postgres.py \
  tests/test_m2_upgrade_postgres.py \
  tests/test_m1_evidence_postgres.py \
  tests/test_wazuh_monitoring_postgres.py \
  tests/test_isms_project_persistence.py \
  tests/test_soa_draft_migration_postgres.py
python -m pytest -q
```

The three native gates use real forked processes for competing claims, a killed claimant with stale-token rejection, and simultaneous first audit appends. Expiry is advanced in the recovery test to avoid a 90-second sleep. All three explicitly reject embedded engines. They are supplied but unverified in this delivery. Also exercise killed workers at source/artifact/evidence-commit boundaries and database/artifact/key restoration in the deployment environment; deterministic embedded recovery tests alone do not prove these operating-system failure scenarios.

## Configure a development collection

1. Configure the existing Wazuh API/indexer connector with valid HTTPS certificates and verified TLS. Retain the existing host-level credential mechanism; do not put secrets in schedules, target JSON, artifacts or logs. Verify the deployed archive index mapping and read permissions before enabling health proof.
2. Select an explicit verified asset binding. Ensure its engagement is current, the ISMS scope has a current approved version containing the asset, and the latest profile for this control/scope has the reviewed requirement. An unscoped profile or a profile in a different scope cannot authorize collection.
3. For a narrow A.8.16 health requirement, use the existing Control Profile advanced settings to permit collection-health evidence. Do not enable this option for A.8.15. Keep human assessment/approval as a separate action.
4. In the existing Wazuh monitoring screen, review the exact target IDs and health policy, create the schedule disabled, then enable it deliberately. Configuration changes create an immutable replacement revision. Re-review after a changed connector, binding, approved scope or profile; do not silently retarget old jobs. An unfinished M1 collection blocks enablement and requires investigation.
5. Supply both `SECURESCOPE_EVIDENCE_ENCRYPTION_KEY` and `SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY` through protected configuration. Use valid Fernet keys and preserve them for restore. The first is mandatory for new M2 source artifacts; the second supports encrypted assurance snapshots. Configure a durable `SECURESCOPE_EVIDENCE_STORAGE_ROOT` with restricted filesystem access.
6. Enable only the development gate, with a matching worker identity:

```bash
export SECURESCOPE_DEPLOYMENT_MODE=development
export SECURESCOPE_RECURRING_EVIDENCE_ENABLED=true
export EVIDENCE_WORKER_NAME=m2-development-worker
export SECURESCOPE_EVIDENCE_WORKER_ALLOWLIST=m2-development-worker
python -m securescope.evidence.evidence_worker
```

This runs the existing Evidence Worker. For a controlled single pass, use:

```bash
python -c 'from securescope.evidence.evidence_worker import run_worker; raise SystemExit(run_worker(once=True))'
```

A single-pass process exit is not evidence that a job succeeded: inspect the persistent job/target outcome and evidence IDs. Recurring execution is allowed only when mode is exactly `development`, the flag is true, and the worker name is allowlisted. **This is a development interlock, not authenticated worker authorization.** Production mode is hard-denied. Do not bypass it by changing the deployment label; production release requires separate verified authentication hardening and the open gates in the acceptance report.

## Health source contract

Example reviewed policy, with deployment-specific channel/index values:

```json
{
  "schema_version": 1,
  "mode": "canary",
  "index_pattern": "wazuh-archives-*",
  "channel": "/var/log/health",
  "max_age_seconds": 120
}
```

For canary mode the indexed hit must contain exact `agent.id`, `manager.name`, `location`, receipt `timestamp`, index and document ID. Its decoded data must include:

```json
{
  "securescope_health": {
    "version": 1,
    "channel": "/var/log/health",
    "event_id": "example-event-000001",
    "sequence": 1,
    "observed_at": "2026-10-19T12:00:00+00:00"
  }
}
```

The example time is illustrative, not fresh proof. Generate real event time/identity/sequence at the reviewed source. Sequence must be a positive integer and event ID 16–128 allowed alphanumeric/underscore/hyphen characters. The indexed location and embedded channel must match policy. Require source time ≤ receipt time ≤ collection time and source age strictly below policy. Regressed sequences or altered reuse of an identity are rejected. Re-reading the same unchanged event cannot renew its source age.

Archive mode uses the exact selected archive document's receipt time and documents that limitation; it does not require a canary payload. Confirm actual Wazuh timestamp semantics before relying on this route. Queries request one newest hit and retain allowlisted fields; health response bytes are limited to 256,000. The adapter neither installs probes nor enables archives. Zero alerts plus no health proof remains telemetry-unverified, not a claim that monitoring is absent.

## Observe, recover and reconcile

The existing Wazuh schedule controls expose enable/pause, Run now, cancellation, attempts, target stages and result IDs. Inspect last attempt/success, queue lag, missed polls and failed jobs since the last success. A job may finish collection with no eligible evidence; infrastructure success and ISO coverage differ. A partial failure retains successful evidence and retries only incomplete stages. Permanent failures require correcting the authorization/configuration and reviewing the schedule before retrying.

Defaults: 60-second interval, three total attempts, 90-second lease renewed about every 15 seconds, 900-second execution deadline. Allowed intervals are 30–604800 seconds and must be strictly shorter than the binding and health freshness windows. Retry backoff starts around 30 seconds, doubles by attempt, adds up to 10 seconds jitter and honors capped Retry-After. Connector request admission uses shared database rate state; a budget wait is bounded. Missed scheduled polls coalesce rather than fabricating historical observations. Assurance refresh processes bounded batches and retries failed snapshots at most three times with a five-minute delay. Investigate exhausted refresh failures even if canonical evidence was collected successfully.

On restart, normal worker ticks recover expired executions. Do not manually reset fencing tokens or edit immutable source/association records. A paused or cancelled job cannot publish through an old lease. After scope/profile changes, historical evidence remains retrievable while current coverage can become ineligible. Worker downtime can make proof stale on read without rewriting historical snapshots.

For a host-authenticated workspace administrator, inspect protected artifacts without deleting anything:

```bash
python -m securescope.cli.verify_evidence_artifacts --workspace 'Exact workspace name'
```

The existing host identity is provided by `SECURESCOPE_CURRENT_USER_EMAIL`; workspace Administrator membership is checked. Output includes referenced/verified counts, failed artifact IDs and unreferenced relative filenames. A nonzero exit requires investigation. Do not delete referenced files or orphan candidates merely because they appear in a report.

Before production, stop collection, back up database plus artifact tree and both encryption keys, restore them to an isolated environment, run integrity inspection, retrieve historical evidence and assessments, and verify source hashes/history. Test recovery after interruption and confirm no duplicate canonical evidence or cross-context links. This restore exercise and live Wazuh demonstration remain unverified. A.8.17 identity improvements remain excluded; no clock-specific procedure or identity logic is changed by M2.
