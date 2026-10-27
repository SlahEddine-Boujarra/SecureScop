# M1 final verification — 16 October 2026

**Disposition: M1 correction ready for review; final M1 acceptance remains pending native PostgreSQL and authorized live Wazuh verification. M2 has not started.**

Reviewed baseline: `4a03cf11bdd9e2a10cf5fd00f38be47716890865` (the supplied M1 source). This is a local branch with no configured Git remote. It does not establish the state of the private GitHub repository or a deployed installation.

## Executed results and their limits

| Check | Actual result | Scope of evidence |
|---|---|---|
| Native PostgreSQL server | **Unavailable; not executed** | No native server, container runtime or dedicated database URL was available. Installation was blocked by the execution environment. Native process isolation, concurrent writers, deadlocks and deployment/restore behavior remain open. |
| Embedded PostgreSQL | **7 passed in 7.91 seconds** | PGlite 0.5.8: PostgreSQL 18.3 compiled to WebAssembly, socket adapter 0.2.11, real psycopg2 connections, real application DDL and SQL, disposable in-memory database and uniquely named schemas. This is supplemental PostgreSQL-engine evidence, not native PostgreSQL acceptance. |
| Full Python regression | **817 passed, 12 skipped, 1 warning in 34.45 seconds** | `PYTHONPATH=src python -m pytest -q`. The 12 skips comprise the seven focused database cases executed separately above, four existing ISMS database cases and one existing SoA migration case. The latter five remain unverified against native PostgreSQL. |
| Frontend regression | **50 passed, 0 failed** | Existing Node DOM/component tests; no UI redesign. |
| Compile, dependencies and changed-file formatting/lint | **Passed** | Commands and output in `validation/m1-final/checks.txt`. |
| Live Wazuh Manager/Indexer | **Unavailable; not executed** | No authorized live endpoint/credentials supplied. Connector tests use synthetic responses; persistence tests use synthetic source facts. No real agent, live TLS chain, permissions or indexing delay was validated. |

Python 3.12.14 was used. The warning is the existing Starlette/httpx test-client deprecation. Python 3.11, Windows and a live database-backed browser were not tested in this pass. No scanner was launched and no production database, evidence or credentials were accessed.

The full Python suite initially had one environment failure because its worker subprocess could not import the uninstalled source package. Rerunning with the repository's documented `PYTHONPATH=src` command resolved it without application changes. An initial broader embedded run also exposed that PGlite ignores startup `options=-c search_path=...`; the focused tests now issue explicit `SET search_path` on their connections. Neither initial run is counted as a passing native PostgreSQL test.

## Required M1 correction

`asset_scope_memberships` and the originating-requirement association query filtered profiles for approved scope validity **before** selecting the newest profile. If a newer configuration referenced an obsolete/invalid scope version, the query could revive an older profile's asset membership and link new evidence to that scope.

A database regression reproduced this: two Nuclei cases passed and the latest-invalid-profile case failed before the correction. Both queries now select the latest profile first, then require its scope version to match the current approved scope. Two regression cases cover association with and without an originating requirement. The correction changes only `src/securescope/persistence/evidence_repository.py` in application runtime code.

The revised portable reproduction helper was also executed successfully: **7 passed in 7.09 seconds** (`validation/m1-final/reproduction.txt`).

No migration changes are required. Migration 017 and all earlier migrations remain byte-for-byte unchanged. Existing evidence, scope links and human approvals are not deleted or rewritten. This prevents new invalid links; it does not retroactively adjudicate links created under older configurations. Existing affected links, if any exist in an installation, require a scoped human review with audit history preserved.

## Database verification details

The fixture applies the actual base schema, canonical migrations 001–017 and Nuclei tables. Only connection factories and configuration boundaries are replaced; ingestion, repository SQL, constraints, artifact encryption, Control Profile evidence reads and requirement evaluation run normally. Subsequent migration discovery calls are disabled only after the real DDL has been applied in the disposable schema. This does not test the production migration ledger/pool lifecycle.

### Migration 017 and observation history

- Applied 017 twice before fixture records and again after observations, run references and binding revocation exist; data remains readable.
- Existing legacy Wazuh rows survive. Observation payload, stable source key and SHA-256 survive reapplication/revocation.
- SQL rejects cross-workspace asset ownership, cross-workspace run references and an observation reference for the wrong asset.
- SQL rejects duplicate active agent identity across workspaces and duplicate active asset binding. A distinct row ID is used so a primary-key collision cannot masquerade as the intended uniqueness check.
- Duplicate source-key insertion deduplicates; an explicit conflicting insert raises the expected unique violation. Attempted observation update raises the immutable-observation exception.
- Rejection tests check SQLSTATE and the relevant exception/constraint message, rather than accepting any database error.
- Real repository calls finalize two collections of unchanged source facts, with changed collection timestamps and repeated completed-run finalization. They retain one observation and two run/asset references.
- A changed event creates a second immutable observation and a second canonical evidence record. Earlier source facts, SHA-256 and Evidence Register retrieval remain intact. A later no-telemetry observation cannot renew that evidence's current monitoring proof.

### Nuclei evidence and Control Profile boundaries

- A synthetic completed zero-finding job is ingested through the actual Nuclei evidence service, yielding one encrypted empty JSONL artifact and one canonical evidence record across repeat delivery.
- The artifact's SHA-256 matches the retained bytes. The other client cannot retrieve that artifact.
- Evidence appears through the actual Control Profile repository query only for the explicitly associated asset and approved scope. It does not appear in an unrelated asset scope, draft scope or another client/workspace with an overlapping IP address.
- Attempting to ingest the first client's job in the other workspace is rejected.
- Obsolete scope-version configurations and empty originating-requirement asset lists do not authorize a new link. The newest invalid profile cannot revive a historical membership.
- Current completed-scan evidence satisfies the configured **recent vulnerability scan requirement**. It does not establish remediation or overall A.8.8 compliance.

### A.8.16 and human approval

- Current exact-identity telemetry supports the configured monitoring coverage requirement.
- Historical active-agent-only evidence, including a human-approved mapping and a future evidence expiry date, remains stored/retrievable but produces **NO EVIDENCE** for verified monitoring coverage. Approval of a mapping cannot upgrade its source facts.
- Two stored human assessments, including an earlier gap and a later `Implemented and effective` decision, remain field-for-field unchanged through repeated collection/ingestion and loss of current telemetry proof.
- Existing audit rows, including their stored hashes, remain identical; new collection/evidence audit events append. This is preservation evidence, not a concurrent audit-chain or privileged database-tamper certification.
- Workspace outsiders and a user without membership in the second workspace cannot start monitoring collection.

## Monitoring accuracy and work deferred to M2

An active agent without qualifying telemetry remains `active_unverified` (agent active, telemetry unverified). Zero recent security alerts is an absence of qualifying security-event proof, not proof that monitoring is absent or failed. An API-only source also remains telemetry-unverified. Current/stale/disconnected/unavailable behavior and exact manager/agent checks are covered by the existing monitoring regression suite.

The pure verification model accepts an authenticated, exact-source collection-health observation, and its existing synthetic test verifies that such proof need not contain an alert. **The M1 connector does not acquire that collection-health proof.** It currently acquires qualifying security events. Defining and validating deployment-specific health endpoints or probes, their identity/provenance/freshness semantics, and quiet-source health collection are deferred to M2 design and approval. Recurring scheduling, retries/no-overlap orchestration and protected retention/restore work also remain outside this pass. No M2 implementation was added.

## A.8.17 exclusion and preservation

Clock-evidence identity validation is **deferred and not completed**. The clock collector, bridge's clock-specific branches, integration scripts, migrations and associated existing tests are unchanged from the reviewed M1 baseline. A byte comparison against the delivered M1 ZIP confirmed 38 selected migration/Wazuh/clock files are unchanged; their SHA-256 values are in `validation/m1-final/preservation.json`. Existing clock records were not altered or deleted; no data migration or production write occurred. This pass makes no claim that historical clock evidence has a fully verified identity. The shared scope-selection correction applies to automatic associations; it does not change clock acquisition or identity validation.

Nmap/Nuclei executors, Wazuh acquisition, Evidence Register UI, risk matrices and ISO approval workflows were not redesigned. The complete regression suite includes their existing tests; this is not a claim of new live end-to-end acceptance for those integrations.

## Reproduce and complete outstanding gates

Use an isolated virtual environment with `requirements-dev.txt`. Run from the application root:

```bash
PYTHONPATH=src python -m pytest -q
(cd tests/frontend && npm test)
python -m compileall -q src tests
python -m pip check
```

For **native PostgreSQL**, configure `SECURESCOPE_TEST_DATABASE_URL` securely to an empty disposable test database, never production, and run:

```bash
PYTHONPATH=src python -m pytest -v \
  tests/test_wazuh_monitoring_postgres.py \
  tests/test_m1_evidence_postgres.py \
  tests/test_isms_project_persistence.py \
  tests/test_soa_draft_migration_postgres.py
```

Tests create and remove only uniquely named fixture schemas. Native verification must also exercise simultaneous duplicate collections/ingestions, transaction rollback and deployment backup/restore; those behaviors are not established by the embedded run.

To reproduce the **supplemental embedded** run, Node/npm and the Python environment are required:

```bash
npm ci --prefix validation/m1-final/pglite
python validation/m1-final/run_pglite.py -m pytest -v \
  tests/test_m1_evidence_postgres.py tests/test_wazuh_monitoring_postgres.py
```

The helper starts only a disposable loopback in-memory database and supplies its URL to the child test process. Test-only npm dependencies are pinned in `validation/m1-final/pglite/package-lock.json`; they are not application dependencies. PGlite's socket adapter has differences from a native multi-process PostgreSQL server: https://pglite.dev/docs/pglite-socket.

Live Wazuh acceptance still requires an authorized test workspace, known agent binding and Manager/Indexer access. Follow the existing M1 handoff steps, exercising a qualifying event, active/no-event agent, stale/disconnected agent, unauthorized/foreign identity and API/Indexer outage. Confirm on-screen Evidence Register/Control Profile results and unchanged human approvals. A.8.17 identity redesign is not part of that M1 exercise.

## Final M1 acceptance checklist

| Acceptance item | Status |
|---|---|
| Focused scope-association defect reproduced and corrected | **Pass** |
| Migration 017 repeatability, ownership, uniqueness and history in embedded PostgreSQL | **Pass — supplemental engine result** |
| Same verification on isolated native PostgreSQL | **Open — environment unavailable** |
| Native concurrent writer, rollback and restore checks | **Open — not executed** |
| Nuclei ingestion, artifact isolation and scoped Control Profile reads | **Pass in database-backed synthetic fixtures** |
| Active-only / no-alert monitoring truthfulness | **Pass in synthetic behavior and database tests** |
| Historical active-only A.8.16 evidence cannot satisfy verified monitoring | **Pass** |
| Human assessments and existing audit records preserved | **Pass in executed fixtures** |
| Collection-health limitations clearly deferred | **Documented; M2 not started** |
| Live Wazuh and database-backed UI acceptance | **Open — no authorized live environment** |
| A.8.17 clock code/data preserved; identity improvement excluded | **Preserved; identity verification remains deferred** |
| Python and frontend regressions | **Pass; database skips explicitly accounted for** |
| User approval of completed M1 | **Pending** |

Review files: this report, the revised tests, runtime diff and `validation/m1-final/` logs/engine metadata. The prior M1 handoff remains historical context; this report supersedes its verification status. Do not start M2 without the user's completed-M1 approval.
