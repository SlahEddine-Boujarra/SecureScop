# M3 development acceptance submission

20 October 2026. Submitted for review; this is **not production approval**.

Implementation follows the M3 plan dated 19 October and subsequent user authorization to start M3. The archived plan retains its original planning-only wording. Baseline: `fc011fc604ff7d7fa6017b662c9cb1644b50a0aa`; branch: `m3-control-assurance`. No remote repository identity or deployment was verified.

## Delivered behavior

M3 adds conservative Nuclei requirement checks for **A.8.8, A.8.9, A.8.24 and A.8.5**, as specified in the plan. A.8.4 is not added by this milestone. These are authored technical subcriteria, not ISO conformity decisions.

1. Exact supported template identities replace tag/prefix authorization. A CVE identifier remains a vulnerability observation, not an overall control failure.
2. The existing Nuclei queue captures the approved profile/requirement/scope-version/asset targets. Supplied target snapshots are replaced by server-derived targets. Completion must still match those targets; replay cannot expand them.
3. First canonical ingestion retains immutable source facts and exact criterion attribution in two small additive tables. Artifact bytes are read through existing protected storage and checked against SHA-256. Source and collection timestamps remain distinct when supplied by the scanner.
4. Evaluation rechecks source bytes, canonical completed job, exact ownership, current approved scope pointer, latest scoped profile, requirement hash and freshness. Newer drafts do not replace the approved scope. A new disabled/changed profile cannot fall back to an older profile.
5. Empty successful scans support A.8.8 **scan coverage only**. Supported positive findings can establish a narrow reviewed configuration, transport-security or default-credential gap. Missing, ambiguous, expired and unassigned facts cannot establish a technical PASS. A bounded read exceeding 500 rows cannot claim complete automated coverage.
6. Existing UI drawers show reason codes, missing/affected assets, source/check identities and next actions. An authorized Control Profile read can export the current technical trace as JSON. Advisory implementation and the persisted human decision are shown separately. New or unresolved technical facts flag review without rewriting the human decision.

The existing Evidence Worker, Nuclei worker, PostgreSQL queue and Wazuh scheduling remain in place. No new broker, dedicated Wazuh worker, ATLAS redesign, live scan or deployment was introduced. A.8.17 identity logic remains deferred and unchanged.

## Executed verification

| Suite | Actual result | Evidence |
|---|---:|---|
| Full Python regression, Python 3.12 | **882 passed, 47 skipped**, one existing Starlette/httpx deprecation warning | `validation/m3/python-regression.log` |
| Focused M3 rule tests | **32 passed** | `validation/m3/focused-rules.log` |
| Actual SQL/repository/artifact integration on PGlite PostgreSQL 18.3 | **38 passed, 4 skipped** | `validation/m3/postgresql-compatibility.log` |
| Frontend DOM/component regression | **51 passed** | `validation/m3/frontend-regression.log` |
| Black/isort on changed Python files | Passed | `validation/m3/style-check.log` |
| Pylint E/F and unused imports, two new application modules | Passed | `validation/m3/pylint-new-modules.log` |
| Migration history preservation | All **21 published files representing 001–019**, including aliases, byte-identical to M2 | `validation/m3/migrations-001-019-preserved.json` |

The 38 database passes are a second execution tier for tests skipped without a database; do not add them to the test count as new test definitions. Four native multiprocessing tests explicitly reject the embedded engine. Five older persistence tests (four ISMS-project tests and one SoA migration test) remain unverified against a native server; they are not reported as passed. The new full SQL checks include the real Control Assurance read, encrypted audit snapshot, replay deduplication, corrupt artifact rejection, changed scope/profile eligibility, 501-row bound and M2-to-M3 upgrade.

Native PostgreSQL executables, a native test DSN, Docker and Podman were unavailable. PGlite validates serial PostgreSQL SQL compatibility; it does **not** establish native lock behavior, multiprocessing concurrency, process-death recovery or production restore. Live Wazuh, a live Nuclei execution and the real Streamlit UI were not exercised. Frontend results are DOM tests, not a browser acceptance claim.

### Corrections made during development

- Canonicalized source fact timestamps to UTC so a database session timezone change cannot invalidate an unchanged artifact; added an equivalent-offset regression.

- Added the missing composite asset-owner uniqueness key required by the new foreign key; reran the database tests successfully.
- Corrected existing test fixtures to use their actual approved requirement ID and explicit source annotations. Tag-only/default-prefix authorization and unassigned-asset formal FAIL expectations were deliberately replaced by the new conservative contract.
- Removed historical normalized-payload rewriting from Nuclei repair. M3 repair/replay preserves attribution; legacy repair can retain/add deterministic control mapping but cannot create new M3 eligibility or scope association.
- Restricted initial Nuclei scope links to actual captured requirement attributions, preventing origin-scope fan-out.
- Removed a transient Python datetime from the JSON audit payload while retaining canonical job/source timestamps in their typed fields.
- Fixed the scope-change test to perform the real Under review → Reviewed → Approved transition; the existing database correctly rejected bypassing that workflow.
- Used JSON-stable asset-result keys so encrypted snapshot comparison remains idempotent. The final real audit test confirms that unchanged reevaluation does not append another snapshot.

## Migration 020

`database/migrations/020_requirement_check_attribution.sql` adds:

- `securescope_nuclei_requirement_sources`: tenant/evidence primary key; artifact, source key, canonical asset, original timestamp, artifact SHA-256, immutable derived facts and facts SHA-256, rule version 3.
- `securescope_requirement_check_attributions`: unique tenant/evidence/profile/requirement/asset association, exact engagement/scope/approved-version, requirement digest and rule version.
- Composite owner foreign keys, a context lookup index, and insert guards for source identity, scope/profile/asset ownership, review state and current profile. Update/delete triggers preserve both histories. Requirement digest equality is revalidated by application reads.

No data is backfilled or deleted; no assessment or approval is changed. Existing evidence without adequate M3 attribution remains readable but does not become eligible for newly tightened checks. Queue a new approved scan to obtain M3 evidence. Jobs queued before M3 may be associated only with an already existing compatible profile created before that job, after the same current approved-context checks; new jobs always carry exact snapshots.

The real migration runner was tested against a seeded M2 001–019 ledger: only 020 applies, the next run is empty, and direct repetition of 020 SQL is safe. Historical custom profile, evidence and assessment rows remain identical. A destructive down migration is intentionally absent. Prefer a forward correction; any production rollback requires a tested database/artifact/key backup and must retain these histories. Production backup/restore remains unverified.

## Acceptance checklist

- [x] Existing application architecture and workers retained.
- [x] Positive, zero-finding, foreign-target, future/stale and forged-fact unit contracts exercised.
- [x] Exact queue-to-source-to-criterion association; immutable history and repeat-delivery deduplication exercised.
- [x] Workspace/scope isolation and current profile/scope-version eligibility exercised; no origin-scope fan-out.
- [x] Serial migration repeatability, ownership constraints and historical-row preservation exercised.
- [x] Human assessment and earlier encrypted audit snapshots preserved in seeded integration tests.
- [x] Existing SoA, policy, risk, Nmap and approval implementations left intact; general regressions passed. These were not separately seeded with every production workflow in the new M3 SQL fixture.
- [x] M2 Wazuh active-only/quiet-agent/source-health and recovery fixtures passed; production recurring gate unchanged.
- [x] A.8.17 identity behavior left unchanged; its deferred validation is not declared complete.
- [x] Explanation and JSON export added within the existing UI; DOM regression passed.
- [ ] Native PostgreSQL concurrency/recovery and full native persistence/restore gates verified.
- [ ] Live authorized Wazuh and live Nuclei source execution verified.
- [ ] Authenticated worker identity/tenant authorization hardened and independently accepted.
- [ ] Real Streamlit/UI acceptance completed.
- [ ] User approves completed M3 development acceptance.

## Remaining functional limits

- **Negative-test execution proof and automatic supersession are unsupported.** Existing Nuclei JSONL records positive matches, not a trustworthy manifest proving each negative test ran. Empty or forged clean results never create a configuration/TLS/authentication PASS or close an earlier gap. The plan's T08 is satisfied only for conservative non-supersession/history preservation; positive-to-verified-negative supersession is not implemented or claimed tested.
- Supported template IDs describe a narrow approved predicate. Their emitted identity is checked; live template execution, template-file digests, scanner completeness beyond the existing canonical Completed job contract, exploitability and organization-wide effectiveness are not independently established here.
- Self-signed/mismatched certificate findings require context review and do not automatically FAIL. Hostname/IP ambiguity is rejected; no DNS inference is introduced.
- Historical M1/M2 Nuclei records are not silently upgraded. Custom criteria remain intact and require explicit predicate review for M3. Assets without current approved criteria retain canonical evidence without automatic scope attribution.
- Source rereads verify bytes each time. Reads are bounded at 500 summaries and 25 MiB per artifact; large-deployment throughput and end-to-end latency were not benchmarked. Incomplete windows return conservative results.
- Artifact encryption remains the existing Nuclei configuration-dependent behavior. Tests used encrypted artifacts. M2 Wazuh mandatory protected-artifact behavior is unchanged; key custody, authenticated download paths and restore are deployment gates.

Production recurring collection remains hard-disabled outside the explicit development gate. Do not label a production host as development to bypass it. **Stop at M3 acceptance; M4 and ATLAS are not authorized by this delivery.**
