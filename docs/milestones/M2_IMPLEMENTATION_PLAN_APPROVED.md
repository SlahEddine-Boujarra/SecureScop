# SecureScope M2 — automated security evidence collection

**Planning proposal · 18 October 2026 · implementation requires approval**

M1 has passed the user's development acceptance review. That decision supersedes the pending-development-approval wording in the historical M1 verification report. Native PostgreSQL verification, live Wazuh validation and authentication hardening remain mandatory production gates.

This plan is based on the final M1 verification report and inspected source at commit `88bee60a89b7117de3dafd9b94b49d9465f386aa`. The working tree was clean. AGENTS.md and the development handoff were reviewed. No application code, migration, configuration, assessment or existing report was changed during planning. No new test execution or deployment is claimed.

## 1. Confirmed implementation and gaps

| Area | Present in the inspected source | M2 addition |
|---|---|---|
| Evidence Worker | `evidence/evidence_worker.py` polls the canonical queue and invokes continuous assurance periodically. Current dispatch builds local defensive CLI plans. | Typed Wazuh API collection dispatch in this same worker; bounded scheduling tick. No dedicated Wazuh worker or new broker. |
| Persistent jobs | `evidence_repository.py` claims due jobs with `FOR UPDATE SKIP LOCKED`. Jobs have attempt counts, availability and heartbeat fields. | Actual retry scheduling, renewable leases, stale-worker fencing, crash recovery, cancellation and durable attempt history. Current failure handling terminates a job rather than rescheduling it. |
| Wazuh collection | `integrations/wazuh_collection.py` collects bound agents on demand, searches qualifying security events, persists observations and bridges evidence. | Explicit bounded job targets, run-specific ingestion, collection-health sources and partial-result recovery. |
| Health | `wazuh_monitoring.py` recognizes a synthetic collection-health structure. | A source-backed acquisition and validation contract. The connector currently does not acquire this proof. |
| History | Migration 017 provides bindings, runs, immutable observations and run/asset references. | Reuse these records; link them to attempts, protected artifacts and exact association snapshots. |
| Canonical evidence | Stable source identities, mappings, artifact infrastructure and scope links exist. Wazuh currently retains normalized facts without attaching a protected source artifact in its bridge. | Protected, bounded Wazuh source packages with verifiable provenance and hashes. |
| Artifact storage | Atomic file writes, workspace directories and optional Fernet encryption exist. | Require encryption for new M2 Wazuh artifacts; verify expected hashes on authorized retrieval. Preserve legacy storage compatibility. |
| Continuous assurance | Reevaluation appends encrypted audit snapshots; it does not approve human assessments. | Trigger bounded reevaluation after evidence changes and periodically for expiry, independently of collection success. |

The existing Wazuh configuration is host-level. M2 will reference that configured connector's non-secret identity and each workspace's explicit bindings. It will not silently turn the existing generic connector table into a multi-credential routing system. Separate per-workspace Wazuh credentials are a later extension if required; no credentials belong in schedule/job JSON.

## 2. Control Profile version selection — confirmed

**Yes: scoped profile selection is intentional, per `(client_id, control_id, scope_id)`.** Engagement ownership is validated against the canonical scope. This is different from profile version-number allocation.

Evidence in the current source:

- `evidence_repository.asset_scope_memberships`: filters the client, selects the newest profile per control/scope, then validates its engagement and current approved scope version. The final M1 correction prevents fallback to an older valid profile when the newest profile is invalid.
- `assurance_workspace_repository.automated_candidates`: selects newest rows per client/control/scope before checking whether automation is enabled. A newer disabled profile therefore cannot revive an older enabled configuration.
- `configured_profiles`: selects the newest version per control within the requested workspace/scope.
- `control_implementation_repository._load_bundle`: prefers the exact scope, with an unscoped profile fallback for legacy/bootstrap display.
- `grc_repository.create_profile_version`: allocates the next number across the workspace/control pair, then selects the requested scope's predecessor and checks optimistic concurrency. The schema has `UNIQUE(client_id, control_id, profile_version)`.

For example, Scope A may use version 7 and Scope B version 9 of the same control. Version 9 in B does not replace version 7 in A. M2 preserves this numbering and history; it does not introduce separate counters or renumber profiles.

M2 automation must use an exact scoped profile. An unscoped display fallback cannot authorize collection or scope assignment. Each schedule pins profile ID/version, requirement IDs and approved scope-version ID. A changed profile or approved scope pauses the affected target pending review; it never selects an older configuration or silently adds assets. A new draft scope version alone does not invalidate the still-current approved version. Automatic association always checks `current_approved_version_id`, not merely the highest scope version number.

## 3. Execution architecture

Use the existing Evidence Worker process and PostgreSQL queue:

1. An authorized administrator enables a versioned schedule with an explicit asset/binding list and approved context. Existing on-demand Wazuh collection is routed through the same job boundary for overlap protection; its existing screen can show queued/running/results without a redesign.
2. A bounded tick inside the worker locks due schedule rows, inserts one occurrence/job and advances `next_run_at` in one transaction. No HTTP occurs inside that transaction.
3. The existing claim loop dispatches an allowlisted `wazuh.monitoring.collect` operation, using `tool_id=wazuh` and the existing collection job infrastructure. Other API tools are not enabled by a broad policy change.
4. The Wazuh handler revalidates delegation, binding, connector configuration, assets, profile and approved scope. It collects only the frozen targets in bounded batches.
5. Persist the collection attempt, per-target outcomes and immutable source observations. Publish validated canonical evidence, protected artifacts and associations idempotently. An ingestion retry can resume from the attempt's persisted source instead of querying a different latest observation.
6. Record all resulting evidence IDs and failures, then request bounded reevaluation of affected A.8.15/A.8.16 requirements. Human assessment records remain separate and unchanged.

The Wazuh handler must explicitly select monitoring/logging checks. The current bridge loops over logging, monitoring **and clock**; M2 recurring jobs must not invoke that default loop and accidentally schedule A.8.17. Add an explicit monitoring-only entry point/selection while retaining existing clock entry points and their identity logic unchanged.

### Scheduling, leases and retry policy

- Use UTC interval schedules in M2; avoid cron/DST complexity. Persist schedule revision, interval, next due time, approval owner, enabled/paused state and reason. Scheduling is disabled by default.
- Enforce unique `(schedule_id, schedule_revision, scheduled_for)` occurrences. Multiple existing worker instances may tick safely; PostgreSQL decides ownership.
- After downtime, coalesce missed polls into one current collection and record missed occurrences. Never manufacture historical telemetry for missed intervals or enqueue an unbounded catch-up backlog.
- Prevent overlapping Wazuh execution for the same workspace/connector across schedules, scopes and manual requests. Use a database-backed renewable lease with an incrementing fencing token. Bound connector request rate across workspaces as well.
- A worker periodically renews its lease. Only the current token may commit observations, associations, evidence publication or completion. A late worker cannot publish after another worker has recovered its expired lease. Network calls may be repeated after a crash, but durable publication must be idempotent.
- Renew while requests execute; do not hold a database transaction open during HTTP. Check cancellation and authorization between batches and again before publication.
- Retry transient connection/timeouts, throttling and eligible server errors with bounded exponential backoff plus jitter, respecting a capped `Retry-After`. Retry only failed targets/stages; retain successful outputs.
- Authentication/permission failures, TLS verification failure, revoked bindings, changed connector identity and invalid scope/profile context pause or block the affected schedule/target with a safe reason. They are not endless retries.
- Start with three total attempts as a configurable policy. Collection interval, request timeout, lease duration and freshness windows are validated together. No universal production cadence is assumed; excessive delay produces stale coverage, never an automatic freshness extension.
- Persist separate acquisition and ingestion outcomes. A job that queried Wazuh successfully but failed artifact storage is not a successful evidence collection. A successful empty query may complete while its asset remains telemetry-unverified.
- Add a durable partial outcome and target diagnostics. Infrastructure completeness and requirement coverage are distinct. Exhausted attempts remain visible with an explicit audited manual retry action.
- Keep generic CLI collector semantics compatible. Shared claim/completion changes require regression tests; automatic recovery/retry is enabled only for job types with proven idempotent publication. Nuclei stays on its existing worker.
- Bound each scheduling/reevaluation pass so periodic assurance refresh cannot starve collection jobs. Record queue lag, missed polls, last attempt, last success, consecutive failures and safe failure categories in existing operational views.

### Delegated authorization

An administrator authorizes recurring execution for a precise workspace/connector/asset/context set. Each attempt records both the authorizing principal and executing worker identity. Recheck active membership and scope/binding authority at execution and publication, not just at schedule creation. Owner removal, permission revocation or archive/disable stops further collection under that delegation. A worker must not impersonate an administrator or mutate environment identity to bypass checks.

This is a job authorization contract, not a claim that the application's existing header/environment identity model has been hardened. Production recurring execution remains gated on trustworthy authentication and protected worker deployment.

## 4. Collection-health proof for quiet agents

Retain M1's qualifying security-event route. Add a second, explicit route based on evidence that a configured collection path actually transported a source observation from the bound agent to the central system.

Official Wazuh documentation confirms that indexed archives can contain events that do not trigger alerts, provided archiving and indexing are configured. Logcollector statistics can describe local collection activity; those statistics alone do not prove delivery through the complete monitoring path. These source capabilities inform the following proposed design, rather than establishing live compatibility with this installation.

### Proposed first supported health adapter

Use bounded, read-only queries against an administrator-approved archive index and a configured source/channel. Validate exact connector, manager, agent and binding identity, a stable index/document reference, source and receipt timestamps where available, an allowed freshness window and the source/channel contract. Empty results, agent heartbeats, generic manager health and HTTP 200 responses do not create verified health observations.

For quiet agents with no suitable natural events, support a deployment-configured benign canary emitted periodically through an approved log collection channel. Its installation/configuration is a separately reviewed deployment step. SecureScope reads its receipt; it does not run arbitrary endpoint commands, change Wazuh rules, enable broad archiving or install probes automatically. Define a versioned canary format, per-source sequence/event identity, bounded timestamps and replay detection. Record what the canary actually exercises; one canary channel cannot attest to every configured log source or detection rule.

A positive proof means the named collection path was observed working within policy. It does not prove detection effectiveness, incident response or complete ISO conformity. Agents with zero security alerts can meet this narrow collection-health requirement when the approved proof is present. A completely silent agent without such proof remains **Agent active — telemetry unverified**.

Do not invent an all-purpose Wazuh health endpoint. Before enabling an adapter, validate the deployed Wazuh version, permissions, actual index mappings, identity fields and timestamp semantics. If the necessary capabilities are unavailable, expose `health proof unavailable` and retain conservative coverage.

### Observation contract

Retain or reference: workspace, canonical asset, binding, connector identity, manager/agent, source channel, proof type, external event/index ID, source observation time, manager/indexer receipt time when actually supplied, SecureScope collection/ingestion time, policy/configuration revision, adapter/check version, relevant measured facts, artifact pointer/hash and collection/attempt ID.

Missing timestamp fields remain explicitly unavailable; never fabricate them. Freshness policy must reject replayed, malformed and future-dated observations. Receipt of an old source observation must not renew its age. These timestamp checks are monitoring-proof validation and do not modify A.8.17 clock-evidence identity logic.

Use a new versioned health-proof contract alongside the existing M1 security-event validator. Do not globally bump a constant and invalidate all valid M1 evidence. Existing v2 security-event evidence retains its original semantics; unsupported legacy health booleans do not acquire verified status merely because M2 supports a real health adapter.

## 5. Canonical evidence and protected artifacts

Reuse canonical evidence/artifact tables, stable-source deduplication and the M1 observation store.

- Store a bounded source package: selected source event/health document, exact-source references, retrieval provenance and normalization/check version. Label it as a retained source subset, not a complete HTTP capture or full Wazuh log archive. Exclude credentials and authorization headers; document any redaction.
- Encrypt new M2 Wazuh artifacts using the existing protected storage mechanism. Missing/invalid key, storage failure or hash mismatch blocks verified publication. Preserve historical unencrypted artifact read compatibility; no automatic destructive re-encryption is proposed.
- Hash the exact retained plaintext bytes with SHA-256; distinguish that artifact hash from the normalized observation hash. An authenticated connector provides source provenance; a hash alone does not prove authenticity.
- Preserve original event times and source IDs. Retrieval/attempt metadata is appended separately so unchanged facts can deduplicate without losing collection history.
- Use stable observation/evidence keys independent of retry number. Link every attempt to its outputs; allow multiple evidence records from one job. The existing single result-evidence field remains for legacy callers.
- Separate source persistence from evidence publication with a recoverable ingestion state. After a crash, retry publication from the exact stored observation/artifact. Avoid rerunning the bridge against whichever observation happens to be newest.
- Stage artifact bytes atomically, then attach metadata and canonical evidence in a fenced transaction. An interrupted write may leave a quarantined orphan, but cannot expose a canonical record pointing to missing bytes. Reconciliation is reference-aware and never deletes referenced evidence.
- Verify workspace authorization and expected SHA-256 before serving downloads/exports. Preserve all historical observations, artifacts, evidence, associations and audit events; no automatic evidence purge in M2. Backup/restore must include both database and encryption keys/artifacts.
- Serialize audit-chain append per workspace, including the empty-chain case, so concurrent scheduler/collector events cannot fork it. This is an M2 concurrency requirement, not a claimed M1 guarantee.

Application write-once behavior, encryption and access checks do not constitute privileged-admin-proof WORM storage. Formal immutable archival retention is a separate production/storage decision.

## 6. Scope, freshness and ISO coverage

Each schedule target pins `(workspace, engagement, scope, approved_scope_version, profile, requirement, asset, binding)` and a reviewed connector/health policy. Validate ownership using canonical IDs and composite foreign keys, never IP/name guesses. Empty target lists mean no targets. A binding grants source identity, not ISMS membership.

A canonical observation may support more than one approved context only through separate explicit, validated associations. Store association provenance per profile/requirement/context. In M2 jobs, limit links to the approved schedule target set; do not let the existing broad asset-membership search fan evidence out to unrelated contexts. Preserve the existing validated Nuclei association path and its M1 newest-profile rule.

Recheck the approved scope pointer and latest scoped profile immediately before publication. A mid-run change blocks the affected association and pauses that target. Already acquired facts may remain in the workspace's source history without granting requirement coverage. Existing historical links are retained; they do not silently count as current after a scope/profile replacement. Reevaluation uses current explicit membership, exact evidence association and current policy.

Calculate effective freshness from the earliest applicable deadline: authenticated agent heartbeat, successful relevant collection observation, source proof timestamp, source-specific policy and requirement-specific maximum age. Rereading, retrying or remapping evidence never resets source timestamps. Policy revisions are recorded; historical evaluation snapshots remain reproducible. A read can show stale evidence even if the worker is down.

Keep acquisition status per proof stream, so a health-query failure does not masquerade as an empty alert result or erase an independently valid security-event fact. Require the sources needed for the particular requirement to be current and available; do not silently relax failure semantics. A valid alternative source can support only a requirement whose reviewed configuration explicitly permits that alternative.

| Evidence | Permitted automated coverage | Must not infer |
|---|---|---|
| Current relevant security event with exact binding | Existing A.8.15 log-source and A.8.16 monitoring requirements, within their defined scope | Overall implementation/effectiveness or incident handling |
| Valid collection-path health/canary proof | Narrow A.8.16 collection-health/monitoring requirement that explicitly accepts it | A.8.15 logging coverage or detection-rule effectiveness |
| Qualifying natural archived security log | A.8.15 only if the approved requirement/check explicitly recognizes that source; otherwise health-only | All sources logged or retention sufficient |
| Active heartbeat, empty alert query or manager health alone | Informational state; telemetry remains unverified | Monitoring absent, monitoring verified or control compliant |
| Expired, invalid, ambiguous or unavailable proof | Stale/unknown/unverified with a reason | A new human assessment decision |

Coverage denominators include all explicitly required assets, including unbound or unverifiable ones. An empty denominator is not 100% coverage. Retain PASS/PARTIAL/NO EVIDENCE/UNKNOWN distinctions at requirement level. Automated collection and reevaluation must never write human approvals, assessment conclusions, SoA applicability, risk acceptance or policy/scope approval fields.

## 7. Proposed additive database changes

Names/numbers below are proposed against the inspected tree, whose latest migration is 017. Confirm no intervening migrations before implementation. Do not edit migrations 001–017.

| Proposed migration | Changes |
|---|---|
| `018_evidence_collection_scheduling.sql` | Add versioned `securescope_evidence_schedules` and explicit `securescope_evidence_schedule_targets`. Extend canonical jobs with schedule occurrence/revision, operation, lease token/expiry, execution deadline and diagnostic outcome fields. Add `securescope_evidence_job_attempts`, per-target attempt outcomes, multi-evidence job result links and a workspace/connector execution-lease table. Extend job outcome constraints additively where necessary. |
| `019_wazuh_health_evidence_provenance.sql` | Add immutable health-policy revisions and normalized proof metadata/links to existing observation rows and canonical artifacts. Add an evidence-association provenance table referencing existing engagement/scope links, exact approved scope version, profile, requirement and asset. Link monitoring runs to job attempts. Preserve existing observation JSON, source keys and clock tables. |

Every relation carries `client_id`. Use composite ownership foreign keys through job, attempt, binding, asset, scope/engagement, scope version, profile and evidence/artifact. Add minimal composite unique keys to referenced tables where required. For requirement IDs currently inside profile JSON, reference the immutable profile and validate the requirement there transactionally rather than inventing a nonexistent requirement-table FK.

Enforce uniqueness for schedule occurrences, attempt number per job, result associations and observation/proof identities. Index due schedules, available jobs, expiring leases and current asset/proof reads. Historical attempt outcomes are retained; lease/heartbeat state is operational and mutable. Schedules use optimistic revision checks; revision snapshots and approval audit events remain immutable.

No new assessment tables, profile numbering scheme, dedicated Wazuh job queue, destructive backfill or clock identity migration is proposed. Existing evidence rows are not rewritten to claim M2 provenance.

## 8. Affected files after approval

Paths below are relative to `src/securescope/` unless otherwise stated.

| File/module | Planned change |
|---|---|
| `evidence/evidence_worker.py` | Bounded schedule tick, typed API dispatch, leases, safe failure handling and reevaluation orchestration. |
| New `evidence/collection_scheduler.py` | Due-occurrence creation and bounded recovery, called by the existing worker. |
| New `persistence/evidence_schedule_repository.py` | Schedule/target approval, occurrence uniqueness, attempts and execution leases; keep scheduling SQL separate from canonical evidence SQL. |
| `persistence/evidence_repository.py` | Fenced publication/result links, typed enqueue/claim handling, scoped M2 associations and serialized audit append. Preserve Nuclei source validation/idempotency. |
| `integrations/wazuh_collection.py` | Frozen target lists, per-stream/asset outcomes, bounded collection and recoverable ingestion. |
| `integrations/wazuh_service.py`; new `integrations/wazuh_collection_health.py` | Read-only archive/health adapter and capability validation. Pin a separate health-policy identity so adding health configuration does not unnecessarily invalidate M1 bindings. |
| `integrations/wazuh_monitoring.py` | Versioned proof validation and explicit health/source freshness semantics. |
| `persistence/db_wazuh_service.py` | Link runs/observations to attempts and artifact/proof records; preserve immutable M1 history. |
| `evidence/wazuh_bridge.py` | Explicit monitoring/logging-only job path, exact-run source ingestion and protected artifact attachment. Clock identity branches unchanged. |
| `evidence/storage.py`; `evidence/evidence_service.py` where needed | Required protection for M2 artifacts, verified retrieval and recoverable publication using existing storage APIs. |
| `evidence/automated_checks.py`, `evidence/freshness.py`, `grc/assurance_requirements.py` | Conservative versioned health checks and source-aware freshness/coverage. |
| `persistence/assurance_workspace_repository.py`, `evidence/continuous_assurance.py` | Exact scoped context selection, current association eligibility and bounded automatic evaluation snapshots. |
| `api/app.py`, `ui/wazuh_monitoring_ui.py`, `ui/evidence_hub_ui.py` | Minimal schedule enable/pause/run/status/history controls through shared authorization. No ATLAS redesign. |
| `database/migrations/018_*.sql`, `019_*.sql`; tests; operational docs | Additive schema, reproducible migrations/concurrency tests, deployment and restore runbook. |

No changes are planned to Nmap/Nuclei executors, risk workflow, profile version allocation or clock-specific collectors/scripts. Shared evidence/worker changes require their existing regressions to remain green.

## 9. Test plan and acceptance criteria

All following results are future gates, not tests already run for M2.

| Test group | Required acceptance evidence |
|---|---|
| Scheduling | Two real worker processes create one occurrence; simultaneous manual/scheduled requests do not overlap for the same workspace/connector. Missed polls coalesce with recorded history. Pause/resume/cancel/revision behavior is deterministic. |
| Lease recovery | Kill a worker before/after observation persistence, artifact write and evidence commit. Another worker recovers within policy; the old token cannot publish; retries create no duplicate canonical evidence or links. |
| Failure tracking | Timeouts/429/eligible 5xx retry within policy. 401/403/TLS/context errors block safely. Partial asset success survives. Storage/ingestion failure is distinguishable from acquisition failure. Logs contain no credentials or raw sensitive responses. |
| Quiet-agent health | An active bound agent with zero alerts and valid configured health/canary proof meets only its eligible A.8.16 requirement. Active/no-proof, empty archive, missing capability, replay, wrong agent/manager/channel, stale and future timestamps do not verify. Health-only proof does not satisfy A.8.15. |
| Context isolation | Cross-workspace IDs, overlapping IPs, wrong engagement, draft/obsolete scope, empty assets and unscoped fallback are rejected. Test two scopes of the same control, latest disabled/invalid profile and mid-run revocation/profile change. |
| Integrity/history | Actual protected bytes round-trip with SHA-256; wrong workspace, wrong key, missing file and tampering are rejected. Repeated delivery retains one canonical identity. Historical sources, links and assessments remain retrievable. Audit chains remain linear under concurrent first writes. |
| Freshness | Exact expiry boundaries, worker downtime, source outage, clock-skew inputs and independent proof streams behave conservatively. Polling old events never refreshes their source time. Missing assets stay in the coverage denominator. |
| Regression | Nuclei successful zero-finding ingestion still creates canonical evidence and its empty JSONL artifact; repeat delivery deduplicates. Failed/cancelled scans do not become coverage. Preserve existing Nmap, ISO/SoA/policy, risk and frontend tests. |
| Human decisions | Snapshot assessment/approval/audit records before collection, retries, expiry and failures. Assert decisions are unchanged; only source records, allowed associations and automated evaluation/audit snapshots append. |
| A.8.17 exclusion | Assert scheduled dispatch requests monitoring/logging only. Clock-specific code/identity behavior and existing records remain unchanged; no claim of completed clock identity verification. |
| PostgreSQL upgrade | Run 001–019 through the real migration runner/ledger on isolated native PostgreSQL with seeded M1 history; reapply safely. Exercise concurrent workers, transaction rollbacks and ownership constraints. PGlite remains supplemental only. |
| Live release gate | Verify the actual Wazuh version/mappings, permissions, TLS, quiet-agent proof, outages and retry behavior. Demonstrate artifact+database+key backup/restore and hardened authentication before production. |

Recommended implementation order after approval:

1. Schedule/authorization contracts, additive queue schema and native concurrency fixtures.
2. Integrate typed Wazuh jobs, leases, bounded retries and exact-run recovery into the existing worker.
3. Add the narrowly defined archive/health adapter and evidence protection/provenance.
4. Add context-aware associations and conservative freshness/coverage; rerun Nuclei and human-decision preservation tests.
5. Add minimal operational controls, documentation, full regressions and a separate development acceptance report listing production gates.

Development acceptance can distinguish synthetic/embedded evidence from unavailable live checks, as M1 did. Production deployment requires native PostgreSQL, live Wazuh and authentication hardening to pass; none is waived by approving this plan.

## 10. Decisions proposed for approval

Approve the existing-worker architecture, interval scheduling with explicit delegated targets, bounded retries/leases, additive migrations, strict scoped profile selection and the first collection-health adapter described above. Accept a reviewed deployment-configured benign canary as the fallback for truly quiet sources; automatic probe installation and broad archive configuration are excluded.

Deployment-specific inputs needed before live validation: Wazuh version, approved archive/index mappings and read permissions, permitted source/channel or canary, binding list, freshness/cadence policy, encryption-key/backup arrangements and trusted authenticated execution identity. These do not prevent development planning, but they prevent claiming live proof before validation.

**No application implementation begins until the user approves this M2 plan.**

## Source references

Local source findings refer to commit `88bee60a89b7117de3dafd9b94b49d9465f386aa`, especially the functions and paths named above, `database/migrations/001_v6_exposure_grc.sql`, `004_v5_3_7_iso_evidence_platform.sql`, `005_grc_engagement_context_scope.sql`, `017_verified_wazuh_monitoring.sql`, and `docs/milestones/M1_FINAL_VERIFICATION.md`.

External technical references checked for planning; these document available Wazuh capabilities, not this deployment's configuration:

- Wazuh event logging and archives: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- Wazuh logcollector statistics: https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html

All health-proof eligibility and ISO requirement mappings in this document are proposed SecureScope rules requiring implementation tests and human-governed requirement configuration; they are not a certification judgment.
