# SecureScope M3 — Automated ISO/IEC 27001:2022 Control Assurance

**Planning proposal — 19 October 2026**  
**Status:** Ready for architectural review; **implementation not authorized by this document**.  
**Basis:** Inspected `SecureScope_M2_Development_Acceptance.zip`, M2 development acceptance, the independent M2 review and applicable code/handoff files.  
**M2 source commit identified by delivery manifest:** `fc011fc604ff7d7fa6017b662c9cb1644b50a0aa` (archive metadata; not independently matched to a live Git remote).  
**M1 ancestor identified by delivery manifest:** `88bee60a89b7117de3dafd9b94b49d9465f386aa`.

## 0. Decision and explicit boundaries

M2 is **accepted for continued development only**. Native PostgreSQL, live Wazuh and authenticated worker execution remain **open production-release gates**. M3 must not reinterpret prior M1/M2 evidence or test logs as production certification. Keep ATLAS redesign for the final UI phase. No implementation, migration, deployment, database write, or live scan was performed during this M3 planning exercise.

**Mission:** convert current, explicitly eligible Nuclei and Wazuh observations into *conservative, transparent requirement-level technical check results and actions*, without converting them into automatically approved ISO conformity, control effectiveness, SoA applicability or risk acceptance.

Preserve existing Python/Streamlit + Components v2 UI, FastAPI control plane, PostgreSQL repositories, existing Nuclei worker, existing Evidence Worker scheduling, protected evidence/artifacts, approvals, risks, policies, Nmap and reporting. Do not build a parallel assurance engine or dedicated collector.

### Source-verification note

The root `DELIVERY_MANIFEST.json` matches **875/875** packaged file SHA-256 digests in the extracted M2 archive. The older application-local `FILE_MANIFEST.sha256` does **not** match 21 files in this delivery; treat it as a potentially stale internal manifest until reconciled. The current M2 delivery manifest, not that stale file, is the reproducible package identity. This check does not verify the commit against a remote repository.

## 1. Inspected functionality — reuse first

| Existing component | Verified source behavior | M3 consequence |
|---|---|---|
| `grc/requirement_templates.py` | `TEMPLATE_VERSION = 2`; ISO-referenced **SecureScope-authored** criteria; specialized A.8.8, A.8.15 and A.8.16; generic manual criteria plus technical criteria for A.8.9/A.8.24/A.8.5. `merge_baseline` preserves existing/custom criteria. | Extend in-place using version-aware, non-destructive template amendments; do not overwrite edited criteria. |
| `evidence/automated_checks.py` | Deterministic Nuclei check catalogue: completed scan for A.8.8; selected web config, TLS/crypto, default auth and CVE findings. Classification priority: exact template ID, CVE ID pattern, family prefixes, **then tags**. | Tighten positive-findings mapping to explicit reviewed ID/predicate sets. Tags may assist discovery but must not by themselves authorize a requirement gap. |
| `evidence/evidence_service.py` | Successful identified Nuclei scans create canonical JSONL-backed evidence and `nuclei.scan.completed`, including zero-findings scans. Mappings are attached to canonical evidence. | Preserve zero-finding coverage and stored artifacts; never infer clean configuration from empty JSONL. |
| `persistence/evidence_repository.py` | `asset_scope_memberships` uses latest scoped profile and current approved scope pointer. `_link_system_evidence` adds deterministic control/scope links; the general path does not itself guarantee a uniquely pinned **requirement/profile-version** association for every Nuclei-derived check. | Make current requirement eligibility explicit without destroying legacy evidence/mappings; validate asset and profile at read/publication. |
| `grc/assurance_requirements.py` | `validate_requirements`, `evaluate_requirement`, `evaluate_technical_requirement`, `evaluate_assurance` already exist. There are separate applicability, implementation, evidence-status and assurance fields; current check results support PASS/PARTIAL/FAIL/NO EVIDENCE/UNKNOWN. | Extend these functions; ensure statuses are labeled as **technical check** versus **human conclusion** and never implicitly promote a finding to final compliance. |
| `persistence/assurance_workspace_repository.py` | Loads scope-linked evidence, evaluates requirements, stores encrypted audit snapshots, and selects latest scoped profile for automation. `_evidence` joins by workspace, engagement, scope and control and applies current Wazuh checks. | Strengthen provenance eligibility of each individual criterion, not only evidence scope-link existence. |
| `persistence/evidence_schedule_repository.py`, `persistence/wazuh_evidence_repository.py` | M2 scheduled Wazuh targets pin connector/binding/asset/engagement/current approved scope version/latest scoped profile/requirement. `annotate_currency` rechecks target/source recency and records eligible requirement IDs without mutating history. | Reuse this current-eligibility model; preserve A.8.15/A.8.16 behavior and quiet-agent health proof. |
| `evidence/freshness.py`, `evidence/continuous_assurance.py` | Centralized currency logic; bounded reevaluation through existing service. | Add deterministic source-/rule-specific eligibility, not a separate scheduler. Reevaluation must not re-date original observations. |
| `persistence/assurance_workspace_repository.py::record_evaluation` | Compares latest encrypted audit snapshot and appends a new result snapshot when changed. | Preserve original human decisions, signed/approved versions and historical reevaluation audit trails. |
| `grc/gap_dashboard.py` | Summarizes assessment statuses across the ISO catalogue. | Avoid presenting technical finding counts as approved conformity scores. |

### Focused code risks to investigate before changes

1. **Tag-fallback classification**: `classify_nuclei()` can match tags after ID checks. A broad or misleading tag could label a finding as an A.8.x technical gap; tighten source-identity and semantics, including `default-login-` family and the crypto category.
2. **Requirement/profile-version attribution**: canonical control and scope links are not equivalent to an approved *current requirement instance*. Record, recompute or validate exact `(workspace, control, engagement, scope, approved scope version, scoped profile version, requirement, asset, source)` eligibility.
3. **Scope pointer consistency**: `load_workspace()` and `assurance_overview()` read `securescope_scope_versions ... ORDER BY version_number DESC LIMIT 1`, whereas M2 target validation uses `current_approved_version_id`. A newer draft must not prematurely invalidate or replace the current approved version during M3 coverage evaluation. Verify contextual display and evaluation separately before modifying.
4. **Unassigned-assets edge case**: `evaluate_technical_requirement()` may return FAIL when a mapped gap exists but the criterion has no configured assets. Require explicit authorized assets for the criterion's formal technical result; keep unassigned observations as *candidate findings requiring mapping*.
5. **Mixed scan epochs**: the existing technical evaluation conservatively keeps current negative findings, but does not define a full policy for a newer valid targeted retest superseding a previous observation. Add transparent supersession rules *without deleting or hiding* historical findings or human judgments.
6. **Coverage vs technical PASS ambiguity**: technical checks may return PASS when each asset has explicit positive test facts. That is only the evaluated **criterion**, not an “Implemented” or “Effective” decision for the whole Annex A control.
7. **Bounded read**: `_evidence()` loads up to 500 mapped summaries. Define explicit “incomplete evidence window” behavior for larger populations, rather than silently implying complete coverage from the first page.

These are inspection-led risks and review items, **not all reproduced defects**. Verify with focused fixtures and database tests first.

## 2. Assurance contract: five separate layers

| Layer | Question | Example allowed output | What it must NOT claim |
|---|---|---|---|
| 1. Technical observation | What did a trusted tool actually observe? | `Nuclei template X matched on asset 42 at T`, `Wazuh collection path verified` | Compliance or control effectiveness |
| 2. Evidence eligibility/coverage | Is evidence current, owned, in approved context and covering configured assets? | `3/5 eligible assets; 2 missing`, `Stale`, `Unmapped` | Tested assets not actually targeted; an empty denominator = 100% |
| 3. Requirement-check result | Does the exact authored criterion meet its deterministic test? | PASS/PARTIAL/FAIL/NO EVIDENCE/UNKNOWN + reason, evaluated set, fact IDs | A scanner pass automatically approving an Annex A control |
| 4. Implementation status | What is the current **derived/advisory** implementation view across criteria? | `Partially Implemented (advisory)`, `Insufficient Evidence` | Overwriting recorded human implementation assessment |
| 5. Human-approved assurance | What did an authorized reviewer approve, and when? | Persisted review/decision, approval evidence, `Needs Review` on changed facts | Automatic approval, SoA change, risk acceptance or policy sign-off |

Every machine-produced requirement result must expose: authored criterion ID/version, latest scoped Control Profile ID/version, scope/version/engagement, expected assets, tested and missing assets, check ID/version, exact evidence and source IDs, source and acquisition timestamps, effective freshness, reason, negative/positive facts, conflicts, and a recommended next action. The source can support a **criterion-level** PASS only after the configured narrow test actually ran and proved the stated property.

Use a **versioned rule registry inside existing modules**. The registry defines supported provider, acceptable source contract, exact templates and predicates, target/asset expectations, coverage semantics, freshness ceiling, and whether only a gap (not a PASS) may be inferred. Never let plain descriptions, arbitrary user JSON or LLM-generated text assign an official status.

## 3. Conservative M3 control mappings

| Control / authored requirement | Eligible source observation | Permissible result | Explicitly excluded inference |
|---|---|---|---|
| **A.8.8 — Current vulnerability assessment** | Successful Nuclei run, authenticated worker origin, exact approved asset/requirement, retained zero-or-more-findings JSONL, required target/scan completeness and freshness | PASS/PARTIAL/NO EVIDENCE for **scan coverage only**; identified CVEs separately generate prioritized technical gaps | No findings = vulnerabilities absent; scan coverage = remediation complete; CVE observation alone = overall control failed |
| **A.8.8 — Triage / remediation verification** | Assigned owner/triage and validated follow-up testing, when those facts exist | Human/documentary review required; scan can link corroborating facts | A newly empty scan automatically closes a ticket or approves remediation |
| **A.8.9 — Secure configuration subcriterion** | Versioned allowlisted Nuclei configuration test with exact ID, approved tested host/service and observed misconfiguration | A positive supported finding = specific **technical gap**; PASS only if a complete, explicitly bounded configuration check and approved expected baseline prove the stated negative property | Clean generic scan = secure configuration management; a missing header always violates an organizational baseline without review |
| **A.8.24 — Transport encryption subcriterion** | Explicit Nuclei certificate, TLS or relevant crypto predicate with protocol, endpoint and test details | Confirmed outdated/weak setting = scoped potential gap; exceptions and trust model can require review | Self-signed certificate universally noncompliant; no reported TLS issue = appropriate crypto governance or key management |
| **A.8.5 — No default credentials on specified service** | Approved exact Nuclei authentication template and validated observed condition, on an approved authorized target | Supported positive default-credential detection = serious technical gap; explicit negative test coverage may support only the narrow configured check | General secure authentication, MFA, privileged access or IAM effectiveness proved from the absence of default-login findings |
| **A.8.15 — Logging** | Existing verified eligible M2 logging/security-event path | **UNCHANGED** M2 requirement-specific logging coverage | Quiet-agent canary implies log retention or security review |
| **A.8.16 — Monitoring** | Existing verified eligible M2 monitoring or explicitly allowed source-backed health/canary observation | **UNCHANGED** M2 narrow monitoring coverage | Active-only Wazuh agent or zero-alert query = verified monitoring/effective detection |
| **A.8.17 — Clock** | Existing dedicated clock path | **UNCHANGED, deferred** | M3 identity or timestamp work applied to clock evidence |

Tag-only classification is *discovery metadata*, not a validated ISO association. The default rule for unsupported templates, missing target identity, unverifiable scan completion, absent explicit test execution or uncertain expectation is **UNKNOWN/NO EVIDENCE**, never PASS. A positive confirmed weakness may be reported as a mapped observation or gap even when the overall authored control needs human judgment.

## 4. Exact eligibility pipeline

Use the existing canonical ID and repository architecture. For each candidate association, require **all** applicable gates:

1. **Workspace authorization:** canonical workspace ID and authorized principal/worker; no tenant mixing.
2. **Source authenticity:** allowed provider/collector method, trusted validator identity, stable scanner execution/job ID, verified artifact/observation hash, source identity/contract and no replay/tampering; distinguish a trusted source from a true assertion.
3. **Canonical asset:** explicit authorized asset identity; no IP/hostname guesses or multiple-tenant fan-out.
4. **Engagement and approved ISMS Scope:** exact engagement, scope and `current_approved_version_id` selected by canonical scope record; latest *draft* does not supersede the still-approved scope.
5. **Control Profile:** latest scoped profile for `(workspace, control, scope)`, exact profile version and requirement stable ID; a newer disabled/review-pending profile cannot silently fall back to an old one.
6. **Requirement mapping:** criterion uses an approved authored version and compatible exact check definition; narrow expected property and coverage denominator must be known.
7. **Freshness:** earlier applicable expiry from source observation, source-specific collection policy, artifact validity and requirement max age; a retry/reread/new audit snapshot never refreshes original observation time.
8. **Current eligibility:** check revocation, connector/binding status and changed profile/scope at evaluation and publication; preserve the original evidence even if the current association becomes ineligible.

Where M2 existing association provenance is sufficient, reuse it. If Nuclei's current structure cannot pin exact profile/criterion/check version safely, propose a **minimal additive migration 020** only after tests demonstrate the gap; include workspace-scoped ownership keys, uniqueness, explicit provenance and indexes. Do not rewrite the 001–019 migration chain or bulk-upgrade historical evidence to verified status. Existing historical records without adequate identifiers remain readable but unverified for newly tightened checks.

### Event / history semantics

- Treat a later scan as a **new immutable observation**. Recompute current eligibility from its actual time and target identity; do not overwrite prior findings, source artifacts or recorded reviewer decisions.
- A retest may supersede the *current technical state* of the identical tested property **only** when the newer scan explicitly repeated the same test on the same approved target and produced a verified negative result; otherwise keep the earlier unresolved gap visible.
- Contradictory eligible positive/negative observations without defensible supersession block a technical PASS and present `Conflicting evidence — review required`.
- New findings or stale evidence may set an advisory `Needs Review` flag. They must not change stored approved assessment text, approvals, SoA applicability, risk acceptance, or past evaluation snapshots.
- Requirement/profile/scope changes produce new evaluation context, not a mutation of an earlier context's output.

## 5. Deterministic gap and recommended-action rules

| Condition | Displayed technical result | Next action suggestion (no auto-execution) |
|---|---|---|
| Confirmed eligible Nuclei finding | Specific observed technical gap; scoped severity and source | Assign owner; validate exploitability/context; triage; record plan; verify remediation by scoped retest |
| Completed eligible Nuclei scan with zero findings | A.8.8 scan coverage; other untested subcriteria remain UNKNOWN | Maintain scheduled assessment; review untested services and separate triage/remediation criteria |
| Partial configured-asset coverage | PARTIAL + exact missing IDs | Correct approved target assignments, permissions or source binding; rerun authorized collector |
| No evidence / unmapped asset | NO EVIDENCE or UNKNOWN | Select canonical asset and approved requirement; obtain source evidence or manual review |
| Expired or future/invalid timestamp | Stale/UNKNOWN; no current eligibility | Acquire fresh source-backed proof; retain historical observation |
| Newest profile disabled, or scope version changed | Ineligible for new current criterion | Reviewer rebinds/reapproves the new profile or current approved scope; no fallback |
| Valid monitoring proof absent but Wazuh active | `Agent active — telemetry unverified` | Establish authorized event or configured collection-health evidence; do not assume monitoring failure |
| Human/documentary criterion not fulfilled | Manual review required | Request a dated procedure, configuration approval, review record, interview or authorized judgment |
| Contradictory eligible facts | UNKNOWN/review-required, retain both | Investigate test scopes and timestamps; decide whether authenticated retest validly supersedes older fact |

Priorities may use existing validated technical severity and configured asset criticality, but **must not** fabricate CVSS, exploitability, risk acceptance, remediation status or approval. Reuse the existing `securescope_improvement_actions`/risk registers for *reviewer-authorized* actions, and ensure a recommendation is not an automatic risk or policy update.

## 6. What may be automatically checked across ISO controls?

The existing catalogue has ISO 27001 clauses 4–10 and Annex A. Only **explicitly configured, provider-supported and versioned subcriteria** get automatic results. First M3 implementation coverage is intentionally limited to A.8.8, A.8.9, A.8.24 and A.8.5, with preservation tests for A.8.15/A.8.16. A.5.9 discovery and A.5.12 classification are existing limited evidence-support features and remain unchanged unless regression fixes require otherwise. A.8.17 remains deferred.

For every other authored requirement use one of three capabilities:

- **Technically verifiable subcriterion:** demonstrable narrow test with the defined provider, asset, threshold and source contract (no generic all-controls automation).
- **Partially technically supported:** scanner logs or records inform one fact, but interpretation of procedures, governance, risk, key management, responses and effectiveness still requires a reviewer.
- **Human/documentary assessment:** policies, approvals, competence, awareness, physical/organizational controls, management review, internal audit, risk acceptance and effectiveness determinations require accountable human examination.

A future applicability matrix should record `control_id`, `criterion_id`, `capability`, `source_contract`, `why_automatable`, `human_review_required`, `unsupported_claims` and reviewer approval/version. Do not prepopulate all 93 Annex A controls as scanned or tested.

## 7. Implementation phases and affected files — after plan approval

| Phase | Implementation intent | Primary existing paths | Gate |
|---|---|---|---|
| **M3-P0** Regression baseline and fixture audit | Freeze M2 output, document current data contracts, prove Nuclei zero-scan and M2 Wazuh behavior unchanged | `tests/test_nuclei_evidence_pipeline.py`, `tests/test_m2_*`, `tests/test_assurance_requirements.py` | No regressions, tests environment documented |
| **M3-P1** Conservative Nuclei check classification | Rule IDs/versions, reviewed exact template selectors, per-observation source conditions; reject tag-only ISO authorization | `evidence/automated_checks.py`, `evidence/evidence_service.py`, `reporting/nuclei_report.py` | Positive, ambiguous and zero findings classified as intended |
| **M3-P2** Evidence/requirement eligibility | Exact scoped profile/approved scope/requirement and asset identity, provenance, freshness; optional small migration only if needed | `persistence/evidence_repository.py`, `persistence/assurance_workspace_repository.py`, `evidence/freshness.py`, existing M2 provenance helpers | Latest profile/approved scope, cross-tenant and immutable history tests |
| **M3-P3** Requirement checks + traceable next actions | Separate observation, coverage, check outcome, advisory status and human conclusion; gap and supersession rules | `grc/assurance_requirements.py`, `grc/requirement_templates.py`, `grc/gap_dashboard.py`, `persistence/assurance_workspace_repository.py` | Reproducible explanations; zero auto-approved assessments |
| **M3-P4** Minimal existing UI/report exposure | Show `why`, source, age, affected assets, current vs historical and recommended action; no new ATLAS | Existing assurance workspace/workbench components, reporting/auditor package | Reviewer can trace each check to facts and unchanged decisions |
| **M3-P5** Validation and acceptance dossier | Unit, database, provenance, isolation, compatibility and artifact/restore gates | Existing tests, `validation/m3/`, milestone docs | Development acceptance evidence + production gates remain explicit |

**Migration posture:** do not create migration `020` merely to signal progress. Plan a narrow `020_requirement_check_attribution.sql` only if the inspected existing tables cannot persist or derive required exact provenance with strong DB constraints. Backfill only verified identities, keep every original evidence record and approval, and provide repeatability/rollback analysis.

## 8. Mandatory regression and negative tests

| ID | Fixture / transition | Expected invariant |
|---|---|---|
| T01 | Exact allowlisted Nuclei config, TLS and default-auth positive findings on approved assets | Only corresponding narrow check produces technical gap; no overall ISO compliance write |
| T02 | Unknown template with `default-login`, `cve` or security tags | No auto-authorized A.8.5/A.8.9/A.8.24 mapping based on broad tags |
| T03 | Nuclei successful zero-finding JSONL, full target set | A.8.8 scan coverage valid; no A.8.5/A.8.9/A.8.24 clean PASS inferred |
| T04 | Incomplete/failed Nuclei scan, malformed JSONL or corrupt artifact | No completed-scan coverage; explicit reason and retained acquisition history |
| T05 | Current source but omitted/mismatched asset, uncertain identity, no configured requirement assets | Not counted; candidate gap stays unmapped; denominator not silently reduced |
| T06 | No evidence and partially covered required asset set | NO EVIDENCE/PARTIAL with affected IDs and next action |
| T07 | Expired, future-dated, mismatched timestamp or reread/retry | Does not regain current eligibility; historical observation preserved |
| T08 | New eligible negative retest vs prior positive finding; incomplete retest; contradictory evidence | Only same check+asset explicitly retested can supersede current technical result; history retained |
| T09 | Newer disabled/changed Control Profile; older enabled profile exists | No fall-back to old profile or older requirement schema |
| T10 | New *draft* ISMS scope version but existing approved pointer remains current | Current approved scope stays eligible; replacing approved pointer invalidates old association |
| T11 | Cross-tenant / cross-engagement / cross-scope / asset substitution | Zero unauthorized coverage and zero cross-link writes |
| T12 | Wazuh active agent, zero alerts, no verified health; then verified approved health | `telemetry unverified` first; narrow A.8.16 support only after valid proof; A.8.15 unchanged |
| T13 | Existing A.8.15 valid security log and A.8.16 event-backed monitoring | Exact M2 outcomes and source contracts preserved |
| T14 | A.8.17 clock evidence | Identity, source requirements and results unchanged |
| T15 | New Nuclei findings / evidence expiry after authorized approved human assessment | Human assessment, risk acceptance, approved SoA, approved policies and prior audit snapshots byte-for-byte unchanged; current advisory review flag allowed |
| T16 | Tampered hash, wrong worker origin, forged `technical_checks` / source JSON | Evidence rejected from automatic eligibility even with familiar check ID |
| T17 | >500 relevant evidence rows / pagination or job retries and restarts | No optimistic full coverage from bounded incomplete read; idempotent processing; no duplicate actions/snapshots |
| T18 | Migration upgrade from real M2 database with historical custom baseline profiles | No loss or silent retcon; migrations repeatable and ownership constraints enforced |

Testing tiers: deterministic unit tests; PGlite compatibility where feasible; **native PostgreSQL** concurrency/migration/restore and isolation; authorized Wazuh source integration; Nuclei source/canonical-artifact regression; protected artifact integrity and download authorization; existing FastAPI/Streamlit workbench smoke tests. Execute on the supported Python 3.11/3.12 environment and retain original full regression logs. M2 production tests are **not** automatically green because M3 tests pass.

## 9. Development acceptance conditions

To request **M3 development acceptance** supply:

1. Source audit/diff referencing original M2 source, working Git baseline, affected files and exact migrations.
2. Approved mapping catalogue/version; controls/criteria with verification class, rule semantics, examples of permissible/forbidden claims and reason codes.
3. Evidence eligibility truth table showing denied workspace, asset, engagement, approved scope, profile, requirement, freshness and source scenarios.
4. Runnable reproducible regression suite with actual results, test environment, failures/skips and baseline comparison.
5. End-to-end traced examples: Nuclei positive/zero/incomplete; A.8.9/A.8.24/A.8.5; current/stale/quiet Wazuh; profile and scope revisions; retained human decision.
6. Screens/reports from **real application only if executed**; archived/static reference screenshots labeled separately.
7. Data preservation statement, migration verification, no new infrastructure, no ATLAS changes, and explicit list of residual issues.

**Still-open independent production gates inherited from M2:** native PostgreSQL migrations + multiprocess concurrency/recovery + full regressions; live authorized Wazuh API/indexer and quiet-agent proof; strong authenticated worker identity and tenant authorization; backup/restore of database plus protected artifacts/keys; real Streamlit/UI acceptance. Do not bypass production hard-disable by labeling a production host as `development`.

## 10. Recommended next action

Approve this **M3 plan**, then ask the developer to execute **M3-P0 only** first: establish a Git-tracked M2 baseline, reproduce focused existing tests in a supported environment, prepare exact fixture inventories and acceptance contracts, and submit findings **before code edits**. Then implement P1–P5 in bounded reviews. Continue to defer ATLAS and A.8.17 identity.

---

**Not claimed here:** no code implementation; no new schema migration; no native PostgreSQL or live Wazuh execution; no production approval; no ISO certification or compliance conclusion. The source code was inspected from a hash-verified delivery archive, not a live running deployment.
