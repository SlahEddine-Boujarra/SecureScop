# M1 — Verified Wazuh monitoring and evidence

**Final verification update (16 October 2026):** See [M1_FINAL_VERIFICATION.md](M1_FINAL_VERIFICATION.md) for the scope-association correction, executed embedded PostgreSQL results, and outstanding native PostgreSQL/live Wazuh acceptance gates. A.8.17 identity improvements remain excluded and incomplete. The results below describe the original M1 handoff.

**Date:** 15 October 2026. **Status:** implementation ready for review; live integration acceptance remains open.

This implements the approved M1 plan against the uploaded SecureScope source. The Python/Streamlit, Components v2, PostgreSQL and existing worker architecture is retained. No repository remote was provided: this is a local working branch, not a change pushed to the private GitHub repository.

## What changed

| Area | M1 behavior |
|---|---|
| Identity | An authorized connector/workspace administrator explicitly binds a canonical inventory asset to the exact connector, manager and agent ID, with an approval rationale. Duplicate or fuzzy matches cannot establish identity. A binding does not assign ISMS scope. |
| Collection | On-demand collection requests only bound agent IDs, paginates the agent API, and queries the Indexer by exact manager/agent. Foreign, partial and malformed responses are rejected. A connection test authenticates without returning the manager's inventory or token. |
| Truthful status | Registered, active without telemetry, verified, stale, disconnected, unverified and source-unavailable states are distinguished. An empty security-event query is not a monitoring-failure conclusion. |
| Freshness | Each binding has administrator-approved heartbeat/collection and telemetry age limits. The suggested form values are 300 and 3,600 seconds; they are not universal production thresholds. Reads do not renew observations. |
| Source trust | API and Indexer TLS verification must be enabled for verified source proof. Lab connections with certificate verification disabled remain possible, but cannot generate verified monitoring evidence. Endpoint, alert-index or TLS-policy changes invalidate previous connector identity; password rotation alone does not. |
| History | Migration 017 adds bindings, collection runs, hashed JSON observations and run/asset references. Repository writes append source facts; an update trigger protects observations from rewriting. Revocations preserve history. Existing legacy source rows remain stored. |
| Canonical evidence | Current verified telemetry supports A.8.16 monitoring coverage; an actual security event separately supports A.8.15 log-source coverage. The existing explicit A.8.17 clock observation path remains separate. SHA-256, stable source keys, event IDs, binding IDs and check version 2 accompany the retained snapshot. |
| Scope | Automatic links require explicit asset membership and a configuration tied to the current approved scope version. Empty requirement asset lists no longer assign every collected asset to that scope. Unassigned evidence can remain in the register. This shared link correction also affects Nuclei's automatic associations. |
| Human assessment | Active-only legacy Wazuh proof cannot satisfy the new check. Evidence is marked for source review when current proof is lost. Existing human decisions are retained. A.8.15/A.8.16 summaries show coverage, with no generated maturity/technical compliance score. |
| Existing UI | SIEM, the asset register/detail, dashboard counts, CSV/Excel exports and Evidence Register use the new status. The binding forms and evidence inspector use existing Streamlit services. |

The retained JSON is a minimal source-fact snapshot, not the full HTTP response or an exported raw-log archive. Its hash supports integrity checking against that snapshot. Protected archival storage, broader retention policy and recurring collection are later work.

## Verification rule

“Monitoring verified” requires all of the following: an exact approved asset/source binding, a confirmed active agent, a current heartbeat, a current successful collection, and a recent authenticated relevant event with matching manager/agent identity. Freshness expires at the earliest applicable deadline. An active agent alone never qualifies.

The pure verification model accepts an explicit authenticated collection-health observation as an alternative to a security event. **M1's live connector implements the security-event lookup only.** No deployment-specific collection-health endpoint or synthetic probe is claimed. API-only installations and quiet sources without qualifying telemetry therefore remain honestly unverified.

Collection-run success describes completion of source requests, not universal asset coverage or ISO conformity. A healthy empty event search can complete successfully while its asset remains telemetry-unverified. Failed collection retains prior telemetry where the same binding exists, but does not treat it as current proof. Stable identical source facts reuse the observation identity; materially changed heartbeat, event, state or source-health facts create new observations.

## Validation performed

Environment: Python 3.12.14, Streamlit 1.62, isolated development virtual environment. Test records use synthetic identities and documentation-range addresses. No production data or credentials were used.

| Check | Exact result |
|---|---|
| `PYTHONPATH=src python -m pytest -q` | **817 passed, 6 skipped, 1 warning**; 17.48 seconds |
| `npm test` from `tests/frontend` | **50 passed, 0 failed** |
| `python -m compileall -q src tests` | Passed |
| `python -m pip check` | Passed; no broken requirements |
| isort / Black / Flake8 on changed Python files | Passed |
| `git diff --check` | Passed |

The six skips are the four existing ISMS PostgreSQL tests, the existing SoA PostgreSQL migration test, and the new Wazuh PostgreSQL migration test. `SECURESCOPE_TEST_DATABASE_URL` is not configured. An attempt to install a local PostgreSQL service was blocked by the execution environment. Migration execution, real SQL transaction/constraint behavior, database rollback/restore and end-to-end tenant isolation therefore remain **unverified**, not passed.

The warning is the existing Starlette/httpx test-client deprecation. Python 3.11 and Windows runtime behavior were not executed here.

New tests exercise state/freshness boundaries, exact identity, conflicting IPs/agents/managers, scoped pagination, malformed/partial responses, credential-safe errors, API-only operation, TLS trust, authorization-before-network, foreign collection context, source outages, connector changes/revocation, stable persistence keys, completed-run retry behavior, retained human review and four Streamlit AppTest interactions. The full suite includes the existing scanner, evidence, ISO, policy and risk regressions.

**UI caveat:** Streamlit AppTest and existing DOM tests passed. A live database-backed browser session and desktop/mobile screenshot review were not performed. This is not a full ATLAS visual implementation or visual acceptance claim.

Full command output is in `validation/m1/`. The migration test creates a uniquely named disposable schema only when an explicit dedicated test database is supplied.

## Migration and evaluation setup

1. Keep the existing installation and a consistent PostgreSQL/artifact/configuration backup. Extract this source into a separate evaluation directory. Retain the application's current version identifier; this is an M1 branch, not a production release.
2. Follow `START_HERE.md` for the existing virtual environment, dependencies and launch configuration. Carry over the established secure configuration through your normal host process. Do not copy credentials into source control or chat.
3. Configure `SECURESCOPE_TEST_DATABASE_URL` for a dedicated test database and run `python -m pytest -q tests/test_wazuh_monitoring_postgres.py tests/test_isms_project_persistence.py tests/test_soa_draft_migration_postgres.py`. Complete this gate before evaluating migration 017 against an installation with real data.
4. Use the existing migration command, `python -m securescope.cli.run_migrations`, against the intended evaluation database. The existing runner also applies pending migrations during relevant startup/read paths. Migrations 001–016 are unchanged; 017 is additive. Do not delete or recreate existing tables to upgrade.
5. Use existing workspace membership and host connector-administrator configuration. Binding approval requires both workspace Administrator membership and the existing `SECURESCOPE_CONNECTOR_ADMINS` / server-identity authorization. Collection requires Consultant or Administrator membership. These checks do not replace the application's outstanding authenticated-identity release work.
6. In **SIEM & Wazuh → Wazuh actions · Configuration and asset bindings**, configure the existing Manager and optional Indexer credentials. Use read permissions limited to the authorized test assets/index. Verify certificates using your established host trust configuration.
7. Approve the exact inventory asset, Wazuh manager name and endpoint agent ID. Confirm ownership from the actual Wazuh inventory and choose suitable freshness windows. Agent `000` is excluded. Test the connection, then collect evidence.
8. Inspect the per-asset reason, source health, heartbeat, event reference, verification expiry and snapshot hash. Verify no-event, stale, disconnected and API-failure cases with authorized fixtures in that environment.
9. Review Evidence Register records and the approved scope's explicit asset requirements. Confirm A.8.15/A.8.16 coverage remains distinct from human assessment, and that existing approved decisions, Nmap/Nuclei workflows, clock evidence and risk matrices still operate.

Old active-only snapshots are retained but are not promoted into new monitoring proof. Existing assets initially require an explicit binding and recollection. Scope configurations tied to an obsolete scope version require review before new automatic scope associations qualify. No silent migration of these approvals is performed.

Rollback is a code rollback to the original ZIP/baseline plus the normal tested backup/restore process if needed. Leave additive monitoring history intact; do not use destructive reverse migrations to erase evidence. Do not operate legacy active-only monitoring semantics as trusted proof after rolling back.

## Files and review boundaries

- New domain/orchestration/UI: `integrations/wazuh_monitoring.py`, `integrations/wazuh_collection.py`, `ui/wazuh_monitoring_ui.py` under `src/securescope/`.
- Updated connector/repositories/bridge: `integrations/wazuh_service.py`, `persistence/db_wazuh_service.py`, `persistence/evidence_repository.py`, `evidence/wazuh_bridge.py`, `evidence/automated_checks.py`.
- Updated consumers: `app.py`, `compliance/iso_control_assessment_service.py`, `core/gap_assessment_domain.py`, `ui/evidence_hub_ui.py`, `ui/components/stitch.py`, `validation/full_stack_validation.py`.
- New additive schema: `database/migrations/017_verified_wazuh_monitoring.sql`.
- Tests: five `tests/test_wazuh_monitoring*.py` files and the two existing tests whose expected active-only behavior was replaced.
- `AGENTS.md` and `docs/codex-handoff/` were copied from the supplied handoff. The earlier M0 audit is included for traceability. The ATLAS prototype was not installed as business logic.

Nmap and Nuclei executors, both risk matrices, policy/SoA approval persistence, existing workers and the clock collector were not rewritten. No external scans or production migrations were executed.

## Remaining acceptance and next milestone

M1 still needs real PostgreSQL migration/transaction tests, authorized Wazuh API/Indexer validation, source retention/restore evaluation and responsive browser review. The uploaded source does not establish the state of the private GitHub branch or deployed application.

The existing header/environment/local-session identity model remains a release blocker for unattended multi-client operation. This milestone retains its current boundaries; it does not claim production-grade authentication or choose an identity provider.

**Stop here for M1 review.** M2 would schedule bounded, authorized collection through the existing Evidence Worker/job infrastructure, with retries/no-overlap behavior, deployment-specific collection-health proof and protected retention. No dedicated Wazuh worker or M2 scheduler has been added.
