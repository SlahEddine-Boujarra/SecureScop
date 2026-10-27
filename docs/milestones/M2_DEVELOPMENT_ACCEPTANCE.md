# M2 automated evidence collection — development acceptance report

Date: 19 October 2026. Baseline: accepted M1 `88bee60a89b7117de3dafd9b94b49d9465f386aa`.

**Status: implementation ready for user development acceptance review; production approval is not requested or implied.** The approved 18 October plan is retained verbatim as `M2_IMPLEMENTATION_PLAN_APPROVED.md`; its original pre-approval wording is historical. The user's subsequent implementation approval governs this work.

## Delivered architecture

The existing Evidence Worker now schedules and dispatches `wazuh.monitoring.collect` jobs through the existing PostgreSQL evidence-job table. No dedicated Wazuh worker, broker, application rewrite or ATLAS redesign was introduced. Nuclei retains its existing worker. Existing synchronous Wazuh monitoring calls enter the approved queue once a workspace/connector has M2 schedules; disabling a flag does not bypass this boundary. Existing unfinished M1 collections block schedule enablement until investigated.

An administrator reviews explicit targets and creates an initially disabled immutable schedule revision. Each target pins the workspace, connector, binding, asset, engagement, current approved scope version, exact scoped Control Profile and requirement. Revisions get their own schedule row IDs; `(schedule_id, scheduled_for)` therefore uniquely identifies an occurrence of a particular revision. Ownership and administrator delegation are revalidated at execution and publication. No IP or hostname inference authorizes membership.

Bounded scheduler ticks coalesce missed polls and avoid overlapping execution per workspace/connector. Renewable 90-second leases, monotonically increasing fencing tokens and a 900-second execution deadline protect publication. A renewal thread supports the existing worker process; it is not a separate Wazuh worker. Cancellation invalidates publication and retains the lease until expiry to account for in-flight HTTP. Expired attempts are recovered with durable history. Default three total attempts (allowed one to five) use bounded exponential backoff and jitter, with Retry-After capped at 300 seconds. Authentication, TLS or context failures stop/pause safely; per-target acquisition and ingestion failures remain distinguishable. Successful partial outputs survive retries.

Read-only archive/canary queries validate manager, agent, channel, index/document identity, timestamps, policy hash and replay sequence. A quiet agent can support an explicitly permitted A.8.16 collection-health requirement. Active status or a successful empty query alone cannot establish monitoring. Health-only proof never satisfies A.8.15. M1 qualifying security events retain their original contract. Archive mode records receipt-time semantics explicitly; it does not fabricate an endpoint observation time. Canary mode requires both source and receipt timestamps. A canary proves the configured path, not every log source or detection rule.

Normalized source subsets are encrypted using existing Fernet artifact storage, hashed over retained plaintext with SHA-256, and attached to exact immutable observations, runs and target associations. Credentials and full raw responses are excluded. Retries resume the exact persisted source rather than whichever observation is newest. File staging precedes fenced database publication: interrupted transactions can leave unreferenced files, but must not publish missing artifacts. The read-only reconciliation command reports such files without deleting them. Downloads and exports verify the recorded hash where supplied by canonical metadata.

Requirement coverage uses current eligible associations and source age. Re-reading old observations does not refresh their time. Scope/profile replacement removes current eligibility without rewriting history. Continuous assurance is bounded; snapshot-refresh failures have persistent retry state independent of successfully collected evidence. Automated coverage and snapshots do not change human assessments, compliance approvals, SoA decisions or risk acceptance.

**Control Profile selection remains intentionally per `(client_id, control_id, scope_id)`.** Version numbers still allocate per workspace/control. A newer version in another scope does not supersede this scope's profile; an unscoped display fallback cannot authorize M2 collection.

## Database changes

| Migration | Additions and integrity boundaries |
| --- | --- |
| `018_evidence_collection_scheduling.sql` | Immutable versioned schedules/targets; typed job operation and occurrence fields; execution leases/fencing/deadline; durable attempts and target stages; multiple evidence result links; diagnostic and assurance-refresh state; ownership keys/triggers and due-work indexes. A connector-wide request-budget table contains operational rate state only, without workspace evidence payloads. |
| `019_wazuh_health_evidence_provenance.sql` | Immutable source/artifact/policy sidecars for existing observations; exact evidence-association provenance; attempt/run links; job/target/source ownership guards; current-source indexes. |

Migrations 001–017 are byte-identical to the accepted baseline, including historical aliases. No historical evidence or assessment backfill claims M2 provenance. Requirement IDs remain validated inside their pinned immutable profile JSON rather than receiving a fictitious relational requirement FK. The real migration runner was exercised from an M1 ledger through 018/019 and returned no pending migrations on repetition, with seeded assessment history unchanged. This was **embedded PostgreSQL**, not native PostgreSQL.

## Executed verification

Logs are in `validation/m2/`. Counts below are separate runs and must not be added as unique test totals; focused tests overlap the full suite.

| Execution | Actual result | Log |
| --- | --- | --- |
| Full Python regression | **850 passed, 33 skipped, 1 warning** | `full-regression.log` |
| Selected M1/M2 actual-schema database regression | **25 passed, 3 skipped**, PostgreSQL 18.3 compiled to WASM, PGlite 0.5.8 | `postgres-regression.log`, `engine.json` |
| Frontend regression | **50 passed** | `frontend.log` |
| Focused health/connector tests | **57 passed** | `health-unit.log` |
| Minimal operational controls | **3 passed**, existing warning | `controls.log` |
| Packaged end-to-end demonstration | **1 passed**, synthetic Wazuh through actual repositories and Control Assurance | `reproducible-demo.log` |
| New core modules, targeted pylint errors/unused imports | No findings | `new-module-lint.log` |
| Existing modified modules, same pylint selection | Four pre-existing findings, reproduced against M1 | `lint.log`, `baseline-lint.log` |
| Final formatting, imports, compilation and patch whitespace | See executed final check log | `final-checks.log` |
| Migration/scanner/risk/clock preservation | Baseline hashes and clock-branch AST match | `boundary_integrity.json` |

The 33 database skips in the full suite reconcile as 25 subsequently passing in the embedded run, three native-only gates still skipped, and five legacy database cases without a completed result. The latter attempted ISMS persistence and SoA migration run produced only the engine banner before its execution session became unavailable; no test summary or reliable exit status was recovered. They are **unverified**, not passed; `other-database-regression.log` retains that incomplete output. The harness has a 180-second subprocess limit, but this report does not infer a confirmed timeout or root cause from an absent completion record.

The Python warning is the existing Starlette TestClient/httpx deprecation. The four existing targeted pylint findings are the missing argument in `app.py`, optional-unpack inference in `wazuh_bridge.py`, and two optional tuple-index findings in `evidence_repository.py`; the baseline log reproduces them. Whole-application lint is not claimed clean.

Database tests cover quiet-agent evidence reaching the exact A.8.16 requirement; A.8.15 exclusion; active/no-proof history; protected bytes and tenant/hash checks; exact-source ingestion recovery and stale-token rejection; partial stream failure; scope/profile invalidation; replay; missing-file recovery; snapshot retry; and non-destructive artifact reconciliation. Scheduling tests cover delegation, ownership, uniqueness, retry/cancel/recovery and production gating. The migration test uses the actual runner/ledger. A seeded human assessment survives the end-to-end collection unchanged. Other decision-table snapshots are fixture-based, including empty tables; this is not evidence of live production-data migration.

The full regression includes Nuclei zero-finding canonical evidence and deduplication, generic evidence jobs, Nmap and existing policy/risk/ISO workflows. It does not substitute for live scanner execution. A.8.17 clock branches and clock persistence remain unchanged; clock identity validation is explicitly **not completed**.

## Remaining limitations and mandatory release gates

1. **Native PostgreSQL unavailable.** No native server/container runtime was available. Three Linux multiprocess tests are supplied but not passed: competing schedule/lease claims, killed claimant recovery/fencing, and simultaneous first audit-chain writes. Embedded SQL validates schema/transactions but cannot establish native inter-process concurrency. Run these plus all database regressions and a seeded native upgrade before production.
2. **Live Wazuh unverified.** Tests use synthetic sources and mocked network boundaries. Actual deployment mappings, archive timestamp semantics, least-privilege access, TLS, quiet-agent transport, outage recovery and rate behavior must be verified. The end-to-end fixture replaces the live client and request admission wait; it is not a live network/load demonstration.
3. **Authentication hardening incomplete.** Development requires an explicit environment gate and worker-name allowlist plus existing administrator delegation. A worker name/environment/header identity is not cryptographic worker authentication. Production mode is hard-denied even if recurring collection is enabled. Do not relabel a production deployment as development to bypass this gate.
4. **Five legacy database regressions remain unverified**, as detailed above. Native validation must resolve these before release.
5. **Operational restore and deployment performance remain unverified.** Back up and restore the database, protected artifact tree and encryption keys together; exercise interrupted-write recovery and deployment-specific load. The archive is source delivery, not a production deployment or backup of user data.
6. Host-level Wazuh credentials remain shared configuration. Explicit bindings isolate workspaces; this milestone does not add independent per-workspace connector credentials. Health proof requires separately reviewed archive/canary configuration; SecureScope installs no probe and changes no Wazuh settings.
7. Artifact protection is not privileged-administrator-proof WORM retention. Unreferenced files are reported, not automatically purged. Snapshot refresh retries are bounded and visible; exhausted failures require investigation.

## Development acceptance checklist

- [x] Existing Evidence Worker/PostgreSQL architecture retained; no new broker or Wazuh worker.
- [x] Scheduling, explicit delegation, bounded retry, attempts, leases, fencing, cancellation and recovery implemented; synthetic/embedded checks recorded.
- [x] Quiet-agent health path and active-only rejection implemented; A.8.15/A.8.16 eligibility separated.
- [x] Protected canonical source artifacts, SHA-256, timestamps, provenance, exact associations and retained history implemented.
- [x] Scope/profile ownership and version isolation tested; human assessment remains unchanged in seeded demonstration.
- [x] Nuclei zero-finding/deduplication and existing regression suite preserved.
- [x] Additive 018/019 only; published 001–017 unchanged.
- [x] A.8.17 identity logic preserved and still deferred; no ATLAS or M3 work.
- [x] Production recurring execution hard-disabled; release gates documented.
- [x] Reproducible synthetic demonstration, exact change list, migration details and executed logs packaged.
- [ ] User accepts completed M2 development.
- [ ] Native PostgreSQL concurrency/recovery/full database upgrade and regressions pass.
- [ ] Live Wazuh validation, authenticated worker authorization and operational restore gates pass before production.

Exact paths and diff sizes are in `validation/m2/changes.txt`; the archive's patch and manifest identify the complete change against M1. No production deployment occurred.
