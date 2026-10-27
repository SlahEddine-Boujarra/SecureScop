# SecureScope — source audit and development plan for approval

Date: 15 October 2026. Status: M0 review completed within the available environment; implementation not started.

## 1. Reviewed baseline and limits

The application was extracted from `SecureScope_UI_UX_Consistency.zip` into:

`/workspace/scratch/25c192b77c6e/development/SecureScope_Control_Implementation_Development`

The separate development handoff was extracted into `/workspace/scratch/25c192b77c6e/handoff`. It contains `AGENTS.md`, all seven specifications in `docs/codex-handoff/`, installation/start instructions, and the ATLAS v10 archive. These were read, including the v9/v10 implementation handoffs inside the ATLAS archive. The application README, START_HERE, architecture/development guidance, remediation specifications and relevant later checkpoint notes were also inspected.

The application identifies itself as **5.4.9.dev0, evaluation/remediation in progress**. The ZIP contains 804 files and no Git checkout metadata. No repository URL or authenticated checkout was supplied. Therefore this is an audit of the uploaded source, not a verification of the private GitHub branch, its latest commits, hosted CI, or deployed database. The handoff remains separate; it has not been overlaid onto application code.

Byte comparison against every original application ZIP entry found **zero modified application files**. No application server, worker, scanner, migration, backfill or live connector was started. No production credentials or database were accessed.

Archive SHA-256 values:

- Application: `0d3e88e274454ba77fefc4bc90f1fe3797eebede5cbf3a04c2ee307d15d7541c`
- Handoff: `1c67ce525f4365d5b51eb453d99e1977c16bb6264832817fd5b24b9694733a13`

All source paths below are relative to the application root. “Present” means implementation was found in source; it does not mean the live integration passed.

## 2. Actual architecture

SecureScope is a Python modular monolith with Streamlit presentation, Components v2, PostgreSQL repositories and persistent workers. `src/securescope/app.py` still owns substantial UI orchestration. FastAPI provides a service/control-plane surface in `src/securescope/api/app.py`.

- Nmap has its own custom builder and execution/parsing path. The custom builder executes a subprocess from its UI flow; the README's general worker diagram should not be read as meaning every scanner runs through a worker.
- Nuclei has a persistent job/attempt lifecycle and a separate worker, including finalization and canonical evidence ingestion.
- The general Evidence Worker claims defensive collector jobs and periodically re-evaluates assurance profiles.
- Wazuh uses an API integration and a bridge from persisted observations. There is no dedicated Wazuh worker. Current collection is initiated by UI actions, not a verified recurring Wazuh collection schedule.
- Raw artifact storage, normalized evidence, control mappings, scope associations and human assessments are separate mechanisms. Some legacy Wazuh paths violate the intended separation.
- The source includes legacy OpenVAS integration. Preserve it alongside Nmap, Nuclei and Wazuh.

## 3. Verified inventory

| Capability | Status in source | Evidence and remaining work |
|---|---|---|
| Nmap discovery/custom builder | Present; live behavior untested | `src/securescope/ui/nmap_custom_ui.py`; `src/securescope/scanners/nmap/nmap_profile_builder.py`. Presets, ports/timing, NSE/options, authorization checkbox, argument-list command execution, XML parsing and CSV path exist. Preserve these; do not equate the checkbox with a complete server-side authorization review. |
| Nuclei automated evidence | Substantial implementation present | `src/securescope/scanners/nuclei/nuclei_worker_service.py::_finalize_job`; `src/securescope/evidence/evidence_service.py::ingest_nuclei_scan_output`. Successful zero-finding output is retained and ingested. Finalization waits for evidence persistence. |
| Nuclei identity/dedup/backfill | Present; DB guarantees untested here | `src/securescope/persistence/evidence_repository.py::create_evidence_record`; `database/migrations/015_trusted_nuclei_evidence.sql`; `src/securescope/cli/backfill_nuclei_evidence.py`. Job/attempt source keys, advisory locks, unique index, deferred artifact creation and repeatable repair paths already exist. |
| Evidence Register and raw artifacts | Present, with source-specific gaps | `src/securescope/ui/evidence_hub_ui.py`; `src/securescope/evidence/storage.py`; `src/securescope/persistence/evidence_repository.py`. SHA-256, workspace paths, review states, mappings and audit events exist. Wazuh bridge does not currently supply a protected raw artifact. Encryption remains optional in artifact storage. |
| Wazuh agent collection | Present but insufficiently truthful | `src/securescope/integrations/wazuh_service.py`; `src/securescope/app.py::render_siem_wazuh_page`. Agent API access exists; active status is incorrectly equated with monitored status. |
| Wazuh canonical evidence | Partial and unsafe as monitoring proof | `src/securescope/evidence/wazuh_bridge.py`. Independent logging/monitoring/clock checks exist, but monitoring support is inferred from active-agent status. Source identity/history and provenance need repair. |
| Clock synchronization | Explicit observation path present | `src/securescope/integrations/ntp_audit_service.py::collect_wazuh_ntp_evidence`; `src/securescope/persistence/clock_evidence_persistence.py`; `integrations/wazuh/`. Endpoint command observations are supported. Preserve this separate proof; a heartbeat is not clock evidence. |
| Scope and human assurance | Present, with association gaps | `src/securescope/grc/assurance_requirements.py`; `src/securescope/persistence/assurance_workspace_repository.py`; `src/securescope/persistence/evidence_repository.py`. Requirements/freshness and current human assessment checks exist. Automated scope linking does not itself enforce an approved scope version. |
| Risk Management | Existing workflow to preserve | `src/securescope/ui/risk_workspace.py`; `src/securescope/grc/risk_lifecycle.py`; `src/securescope/persistence/risk_register_repository.py`. Registers, treatment/residual fields, revision checks and transactional writes exist. Preserve both inherent/residual matrix experiences and approval semantics. |
| Policies, SoA and ISO foundation | Present; full lifecycle completeness not established | `src/securescope/policies/repository.py`; `src/securescope/ui/components_v2/policy_editor.py`; `src/securescope/persistence/grc_workspace_repository.py`; migrations 005–016. Versioned scope/policy, SoA, context, party requirements and objectives are existing work, not modules to recreate. Broader audit/review/corrective-action completeness needs a separate lifecycle review. |
| ATLAS integration | Reference and partial UI work | Existing Components v2 and styling are real application code. ATLAS is an offline prototype with fictional records. Use its visual direction incrementally; never import its demo data or localStorage as business state. |

## 4. Priority findings

### F1 — Agent presence incorrectly becomes monitoring and ISO status

`wazuh_service.py::monitoring_status` returns `Not monitored` for no agent and `Monitored` for any active agent. `iso_monitoring_evidence` returns `Implemented` when all inventory rows are counted as monitored. The bridge's `normalized_source(..., "monitoring")` also emits positive A.8.16 support from active status, with heartbeat or collection time as its timestamp.

These are separate defects: changing a label alone would leave misleading trusted evidence feeding requirement evaluation. The generic assurance evaluator has human-review safeguards; that does not make this legacy summary or the input evidence valid.

### F2 — Requested alert retrieval is missing

`app.py::render_siem_wazuh_page` calls `WazuhClient.search_last_alert_for_agent`, but that method is absent from the supplied class and no implementation was found in the source search. The per-row exception handler stores an error and continues. Thus collection can finish with agent rows and monitoring evidence despite failure to retrieve events.

The separate NTP Indexer query is implemented; it is not a replacement for general monitoring or logging evidence.

### F3 — Identity matching and connector ownership are insufficient

`match_agents_to_assets` uses dictionaries keyed by IP/name, silently retaining the last duplicate, then permits substring hostname matching. There is no verified workspace/manager/agent binding in this matcher. The UI fetches up to 500 agents from host-configured credentials and includes unmatched agents in the receiving workspace's snapshot. SQL client filters alone cannot establish that a shared-manager observation belongs to that client, particularly where private IP ranges overlap.

Use workspace-owned connector identity plus stable agent ID and canonical asset ID. Exact IP/hostname can be constrained candidates; ambiguity must never become proof. No matching path may infer ISMS scope.

### F4 — Wazuh persistence undermines history and idempotency

`db_wazuh_service.py::save_wazuh_snapshot` deletes the workspace's previous asset-status rows before inserting replacements. Canonical Wazuh keys include that transient row ID (`evidence_repository.py::create_evidence_record`). Re-ingesting the same retained row is deduplicated, but recollecting unchanged source facts creates new row IDs and can produce new evidence identities. Prior evidence's source-row reference can cease to resolve.

`wazuh_bridge.py` does not pass an artifact or artifact factory. A hashed audit event is not a retained, hash-verifiable raw source observation. Add durable observations and source-event identity, while preserving a latest-status view for current consumers.

### F5 — Freshness, errors and repeated collection need explicit semantics

The current monitoring label ignores observation age. The connection indicator is a session/configuration signature rather than a recent source-health observation. Source failures are not represented as a durable per-run lifecycle. General evidence expiry exists, with a configurable default of 90 days, but this is not a suitable substitute for explicitly configured monitoring freshness.

The existing Evidence Worker periodically evaluates assurance and may refresh inventory evidence. It does not currently perform recurring Wazuh API collection. Collection scheduling, bounded retry/backoff and no-overlap execution belong in that existing infrastructure in M2.

### F6 — Scope association must be tightened

`evidence_repository.py::asset_scope_memberships` reads asset selections from control-profile configurations. `_link_system_evidence` can also associate evidence from an originating requirement whose asset list is empty. Its scope query checks client/engagement and non-archived state, but not an approved scope version.

Preserve explicit draft associations if needed for preparation, label them accordingly, and prevent them from qualifying as verified approved-scope coverage. Missing independent asset/scope membership must remain unassigned.

### F7 — Authorization exists, but authenticated identity remains a release blocker

`api/app.py::workspace_context` checks membership using caller-supplied workspace/user headers without a signed-token or authenticated-session check in that dependency. `ui/grc_workspace/context.py::current_actor` uses a local setup-code proof or process environment identity. This is not sufficient to claim independently verified human approvers in a deployed multi-user system.

The supplied source includes a working local launch-code access path, as later checkpoint notes explain; it must not be accidentally removed. A verified login/API identity design and service-account authorization remain required before live unattended multi-client collection or production assurance claims. M1 can implement and test deterministic monitoring behavior in isolation without pretending that broader authentication remediation is finished.

### F8 — Nuclei mapping is conservative in part, but has a broad fallback

`automated_checks.py::classify_nuclei` supports exact template mappings and CVE identifiers, but also maps unknown templates through tags such as `cve` and `default-login`. This is broader than the handoff's intended semantic allowlist. Review and narrow that fallback in M2/M3; do not rebuild the successful-scan ingestion path.

### F9 — Some tests encode the old behavior

`tests/test_correction_pass_20261005.py::test_agent_presence_proves_neither_logging_nor_clock` correctly rejects logging/clock inference but explicitly expects an active agent to satisfy monitoring. The M1 test updates must change this assertion and add telemetry verification cases. Passing the old suite alone would not prove the new requirements.

## 5. Verification performed

| Check | Result |
|---|---|
| Extract and compare all application archive files | 804 files; zero original files modified |
| Git status/branch | Unavailable: extracted ZIP is not a Git repository |
| Python runtime | 3.12.14; Python 3.11 execution not verified |
| `python -m compileall -q src tests scripts` | Passed, exit 0; bytecode cache redirected outside application root |
| `python -m pytest -q` | Could not start, exit 1: `No module named pytest` |
| Dedicated PostgreSQL test database | Not configured; migrations, SQL transactions and DB isolation not executed |
| Wazuh/Nmap/Nuclei live integration and browser UI | Not executed |

A dependency-free diagnostic executed the unchanged pure Wazuh functions extracted from their AST, with synthetic documentation-range IPs. It reproduced: no agent → `Not monitored`; active agent without telemetry → `Monitored`; duplicate-IP candidates → agent `002` silently selected; fuzzy hostname → `Monitored`; resulting ISO summary → `Implemented`. Static class inspection confirmed the missing alert method. This was a focused diagnostic, not a substitute for the full regression suite.

Archived test logs are historical, not results of this review. The old remediation brief's coverage requirement is superseded by later checkpoint guidance and the current CI configuration, which measures coverage with a temporary zero floor. Current CI also already includes lint/security tooling and dependency audit steps. Do not reapply stale instructions as if those changes were absent.

## 6. Proposed M1 — verified SIEM asset monitoring

**Approval boundary:** one bounded monitoring-correctness milestone, including the evidence safety fixes needed to prevent its UI and requirement evaluator from disagreeing. No broad rewrite, scanner replacement, authentication-platform rollout or ATLAS redesign.

### Behavior and data contract

1. Establish deterministic identity using the workspace/connector/manager/agent tuple and canonical asset ID. Reject duplicate/missing/conflicting identifiers. Keep unmatched candidates available only within authorized connector scope. Add pagination so a partial agent list is not presented as complete inventory coverage.
2. Represent independent dimensions: registration/agent state, telemetry state, source health, observation timestamps, match confidence/reason, and approved-scope membership. Render `Monitoring verified`, `Agent active — telemetry unverified`, `Monitoring stale`, `Agent disconnected`, or `Monitoring not verified`, with a visible reason. Source unavailable is an explicit error/health state, not proof of a monitoring gap.
3. Repair the missing read-only telemetry lookup using exact source/agent identity. A recent authenticated relevant event or supported collection-health observation can establish telemetry evidence. An API-only heartbeat remains unverified. Zero security alerts must not itself imply failure; where collection health is unavailable, say that verification is incomplete.
4. Apply explicit, configurable heartbeat/telemetry freshness policy using source timestamps. Retain last-known evidence on failure, while marking its current verification unavailable or stale. Do not invent production thresholds or silently refresh observation timestamps on reads.
5. Add durable monitoring observations and collection-run/error records through an additive migration. Keep existing read contracts or a compatibility projection; stop destroying source records that evidence references. Include stable collection and source identities.
6. Replace legacy A.8.16 implementation summaries with factual coverage. Update the canonical bridge at the same time. Historical active-only system evidence must stop qualifying as verified telemetry, using version/provenance eligibility rules and an auditable transition. Preserve the records and all human decisions; flag affected assessments for review rather than rewriting approved conclusions.
7. Surface this in the existing SIEM table, asset status presentation, dashboard counts and exports. Unknown/unmatched states must not continue appearing as “unmonitored” elsewhere. No new dedicated Wazuh worker.

### Expected file impact

| File | Intended M1 change |
|---|---|
| `src/securescope/integrations/wazuh_service.py` | Deterministic matching, factual status derivation, paginated retrieval, exact telemetry/health lookup and typed source outcomes |
| `src/securescope/persistence/db_wazuh_service.py` | Durable collection/observation writes, scoped identity validation, latest-state loading and history preservation |
| `database/migrations/017_verified_wazuh_monitoring.sql` — proposed | Additive connector/agent/asset bindings and run/observation fields or tables; confirm next version against actual checkout before creating |
| `src/securescope/evidence/wazuh_bridge.py` | Require verified telemetry for monitoring support; keep logging and clock semantics independent |
| `src/securescope/persistence/evidence_repository.py` | Stable source resolution, binding validation and safe scope linking for affected paths |
| `src/securescope/evidence/automated_checks.py` and `src/securescope/grc/assurance_requirements.py` | Reject legacy active-only Wazuh proof where needed; preserve the human final-assessment boundary |
| `src/securescope/app.py` | Collection orchestration, SIEM table, dashboard/export consumers and failure presentation |
| `src/securescope/ui/exposure_management_ui.py` | Reconcile affected asset/coverage consumers; retain raw agent availability for existing remediation guardrails |
| `tests/test_wazuh_monitoring.py` — proposed | State/identity/freshness/telemetry tests |
| `tests/test_wazuh_monitoring_persistence.py` — proposed | Stable history, tenant/connector isolation, repeat collection and failure tests; real DB cases gated by a dedicated test DB |
| `tests/test_correction_pass_20261005.py` | Replace assertions that treat active-agent status as monitoring proof |
| Relevant existing Wazuh configuration, API, evidence-scope and UI tests | Regression coverage for consumers and unchanged permissions |

This is the intended change set, not a promise that every listed consumer requires an edit. Confirm call sites and the current Git branch before implementation; report any material expansion before proceeding.

### M1 acceptance gate

- No agent, ambiguous IP/name, missing agent ID and foreign connector/tenant never produce verified monitoring.
- Active heartbeat without telemetry remains unverified; explicit current telemetry can verify; old telemetry becomes stale.
- Disconnected, never-connected, pending, unknown, future/invalid timestamps and timezone handling remain distinct and explainable.
- API/Indexer failure, missing Indexer configuration and an empty alert result do not become false success or false “not monitored” conclusions.
- Duplicate IPs across tenants/managers and changing IPs cannot transfer evidence ownership.
- Repeat collection and retry preserve stable evidence identity and source history.
- Unassigned/draft scope does not count as verified approved-scope coverage.
- Legacy active-only evidence cannot satisfy the new monitoring check. Approved human outcomes are preserved and review needs are visible.
- No automated path writes a final ISO implementation/effectiveness approval.
- Existing Nmap, Nuclei, clock observations, Evidence Register, policies, risk registers and inherent/residual matrices retain behavior.
- Run focused tests, full regression suite and dedicated PostgreSQL tests; show exact results and desktop/mobile screenshots when the runtime is available. Clearly report blocked checks.

Rollback: use a working branch from the confirmed Git baseline and a consistent DB/artifact backup before applying migrations. Keep new schema additive and old records intact. Do not roll back data by deleting evidence or disabling approval rules.

## 7. Subsequent milestones, each separately reviewed

| Milestone | Deliverable |
|---|---|
| M2 — automated verifiable collection | Schedule Wazuh through the existing evidence/job infrastructure; bounded retries, no-overlap execution, service authorization, immutable raw snapshots, SHA-256, stable external IDs, schema/check versions, protected retention and source freshness. Harden Nuclei's existing zero-finding/idempotency/backfill paths and tag mapping. |
| M3 — requirement-level assurance | Tighten approved-scope association and evidence eligibility. Keep vulnerability assessment, triage and remediation verification distinct for A.8.8. Map A.8.15/A.8.16/A.8.17 only from their own facts. Preserve customized profiles, human approvals and justified SoA decisions. |
| M4 — incremental ATLAS UI | SIEM → Evidence Register → assessments → assets/classification → scanners → Policy Builder → Risk Management → governance/audit. Use existing services and real data with feature-parity checks. |
| M5 — remaining ISO lifecycle | Trace stored records, review transitions and exports for monitoring/measurement, internal audit, management review, corrective action, competence/awareness, communications, change and document control. Implement only demonstrated gaps. |
| M6 — release validation | Complete authenticated identity and applicable security gates, encrypted sensitive evidence, tenant isolation, backup/restore and artifact reconciliation. Demonstrate the authorized end-to-end evidence-to-human-assessment flow. |

Authentication is a prerequisite to live unattended multi-client collection and release, not an issue to postpone operationally until M6. Select/confirm the login integration in a separate scoped decision; do not invent an identity provider or replace a newer working authentication branch.

## 8. Requested approval

Approve **M1 only**, as described above. Implementation will stop at its acceptance review before M2. The current request and `AGENTS.md` require that approval; no application code has been changed.

Before live validation, the actual Git repository URL/branch (or confirmation that this ZIP is the intended baseline), a dedicated test PostgreSQL database, and authorized Wazuh test connector/agent scope will be needed. Production credentials should stay in secure configuration, not in chat or source files. Missing live services do not prevent writing and reviewing isolated M1 logic, but they prevent claiming an end-to-end validated integration.
