# Nuclei evidence integration and workflow corrections

Implementation date: 2026-10-04.

**Status: implemented and locally regression-tested; live acceptance remains pending.**
No real PostgreSQL migration, authorized Nuclei scan, or live browser download is claimed by this report.

## Changes

### Evidence pipeline and provenance

The existing Nuclei worker passes the raw `findings.jsonl` into the existing evidence persistence path before completing report finalization. PDF generation remains unchanged; PDFs are not parsed as evidence. A completed zero-finding scan retains an empty JSONL artifact. Failed scans, missing artifacts and malformed JSONL cannot become verified evidence.

One scan attempt produces one Evidence record containing individual observations. The repository locks and validates the canonical job, attempt, client and asset. The stable source identity is `nuclei:<job UUID>:attempt:<number>`; repeated finalization returns the existing Evidence ID. Database insertion of evidence, mappings and scope links is transactional.

Trusted records use `verification_origin = System collector`, `validation_status = Validated`, validator `system:nuclei-worker`, and mapping origin `Automated check`. They do not receive consultant approval or human approval metadata. Generic collectors, manual submissions and imports retain human review. Generic collector requests now carry engagement and scope through queue, worker and service into canonical persistence.

### Automated checks and scope

`automated_checks.py` holds the deterministic catalogue. Classification checks exact template IDs first, then explicit template families and allowlisted tags. Unknown observations stay unmapped. No free-text guessing or blanket control mapping is used.

| Check | Control | Meaning |
|---|---|---|
| Successful scan completion | A.8.8 | Supports the Recent vulnerability scan requirement |
| Known security-header / CSP failures | A.8.9 | Detected gap |
| Known certificate / cipher failures | A.8.24 | Detected gap |
| Default-login checks | A.8.5 | Detected gap |
| Explicit CVE identifiers or CVE tag | A.8.8 | Detected gap |

Scope links derive from the scanned canonical asset and the latest existing control requirement configuration for each scope. Links must belong to the same client and valid engagement/scope; applicable approved SoA exclusions are respected. One Evidence record may link to multiple matching scopes. No matching configured scope leaves evidence unassigned rather than guessing from UI context.

### Coverage and assurance

The evaluator unions distinct applicable assets with current usable scan evidence. Duplicate scans do not inflate coverage, unrelated assets do not count, and stale evidence is excluded. Coverage is 0/3 with no evidence, Partial at 1/3 or 2/3, and Pass at 3/3 for the configured scan requirement. Gap findings cannot become positive requirement support.

Control Profile evidence exposes system provenance, asset, checks, detected observations and the reason for linking. Requirements show asset coverage and missing assets. Assess Control can use the verified evidence through the existing scope-aware reader. Completing collection coverage does not automatically make the control implemented or effective; final assurance remains a human decision.

### Worker configuration and polling

The worker uses the canonical `ENV_FILE` and `PROJECT_ROOT` and contains exactly:

```python
load_dotenv(dotenv_path=ENV_FILE, override=False)
```

It runs startup migrations once, then claims queued jobs with `schema_initialized=True`. This removes migration checks from every empty polling iteration while retaining safe initialization for standalone callers. Other existing repository migration guards remain intact.

### Control Profile interface

List and selected detail rendering are mutually exclusive. The list filters, count and table are absent in detail; returning restores list state. The requirement confirmation action belongs in the Requirements section, rather than above the detail workspace. Existing configuration, evidence and assessment paths remain canonical.

### Policy downloads

The existing Word/PDF generators produce the same document formats. Export returns a serializable filename, MIME type and base64 payload to the component. JavaScript creates a Blob and starts the browser download immediately, once per response nonce. It removes the temporary anchor, revokes the object URL, resets busy state and displays generation/delivery errors. The redundant second Streamlit download button is removed only for policy exports. Filenames are sanitized; exporting does not change policy versions.

## Database migration

New migration: `database/migrations/015_trusted_nuclei_evidence.sql`.

- Adds nullable `securescope_evidence_records.source_key`.
- Adds `verification_origin`, default `Human review`, constrained to Human review or System collector.
- Adds a partial unique index on `(client_id, tool_id, source_key)` when source_key is non-null.
- Extends existing mapping-origin constraint with `Automated check`.
- Extends existing engagement-link-origin constraint with `Automated collection`.

No historical records are deleted or assigned guessed scopes. No second evidence, scope, treatment or control model is created. Apply using the existing migration runner, first against a disposable database and a backed-up staging copy. This migration has not been executed against PostgreSQL in this environment.

## Exact implementation and test files

- `database/migrations/015_trusted_nuclei_evidence.sql`
- `src/securescope/evidence/automated_checks.py`
- `src/securescope/evidence/evidence_service.py`
- `src/securescope/evidence/evidence_worker.py`
- `src/securescope/evidence/storage.py`
- `src/securescope/grc/assurance_requirements.py`
- `src/securescope/grc/control_implementation.py`
- `src/securescope/persistence/assurance_workspace_repository.py`
- `src/securescope/persistence/control_implementation_repository.py`
- `src/securescope/persistence/evidence_repository.py`
- `src/securescope/reporting/nuclei_report.py`
- `src/securescope/scanners/nuclei/nuclei_worker_service.py`
- `src/securescope/ui/assurance_workbench.py`
- `src/securescope/ui/components_v2/assurance_workbench.js`
- `src/securescope/ui/control_assessment_ui.py`
- `src/securescope/ui/control_profiles_workbench.py`
- `src/securescope/ui/control_workspace.py`
- `src/securescope/ui/evidence_hub_ui.py`
- `src/securescope/ui/exposure_management_ui.py`
- `tests/frontend/assurance_workbench.test.mjs`
- `tests/test_nuclei_evidence_pipeline.py`

Documentation: this report and `CHANGELOG.md`. Verification logs: `validation/nuclei_pipeline/`. `validation/SOURCE_REVISION.txt` identifies the packaged source commit.

## Verification performed

- Full Python suite: **695 passed, 4 skipped, 78 warnings**, 20.50 seconds.
- New focused pipeline suite: **29 passed**; zero findings, observations, deterministic mapping, retry identity, configured scope associations, stale/duplicate/unrelated assets, trust boundary, generic worker context, dotenv, worker initialization, finalization failure, list/detail restoration, and actual DOCX/PDF generator bytes.
- Frontend workbench interactions: passed, including Blob payload/MIME, repeated nonce suppression, URL cleanup and error recovery.
- Existing risk/control frontend suite: **17 passed**.
- Black, isort and flake8: passed for all 18 changed/new Python files.
- `git diff --check`: passed.

Tests include real parsers, evaluators, document generators and Streamlit AppTest rendering, but database reads/writes and scanner execution are mocked in the new pipeline tests. Four existing PostgreSQL tests were skipped because `SECURESCOPE_TEST_DATABASE_URL` was not configured. Logs preserve warnings rather than suppressing them.

## Limitations and remaining acceptance

The available PostgreSQL setup could not be initialized under this runtime's permissions. The cached browser process exited on launch. Consequently, there are no new live-database or desktop-browser screenshots for this pass. Unit/AppTest/JSDOM results are not substitutes for that acceptance.

The catalogue is deliberately narrow: unsupported Nuclei findings remain visible but unmapped. Evidence without matching configured assets remains unassigned. This pass does not retrospectively scan or backfill historical evidence. Artifact storage precedes database persistence, so an interrupted or repeated ingestion can leave an unreferenced stored artifact even when Evidence row identity is preserved; artifact retention/cleanup needs operational review.

Existing legacy evidence count paths outside the canonical assurance evaluator have not all been demonstrated against live data. Verify each consuming surface below before release. The previous navigation/animation corrections remain in the source; this pass does not claim a new live animation diagnosis.

## Manual end-to-end acceptance checklist

Use an explicitly authorized scan target and a disposable PostgreSQL database first.

1. Run all migrations fresh, including 015. Repeat startup to confirm the migration runner skips already-applied migrations. Repeat against a backed-up pre-015 database and confirm historical evidence remains accessible.
2. Create a client, engagement, ISMS scope and A.8.8 Recent vulnerability scan requirement covering three canonical assets. Create a different scope with unrelated assets.
3. Run one successful Nuclei scan through the real worker. Confirm raw JSONL storage, one Evidence row, individual observations, trusted provenance, automatic mapping, and only deterministic matching scope links.
4. Check Evidence Register, Evidence Overview, Control Profiles, Gap Dashboard and Assess Control under the same context. Confirm the evidence is visible and collection coverage is 1/3. Scan the other two assets and confirm 2/3 then 3/3. Confirm final assurance still needs a human decision.
5. Test zero findings, unknown template, known gap, failed scan, malformed JSONL, stale scan and duplicate finalization. Verify failed inputs never gain verified support, gaps never count as positive support, and repeated finalization does not duplicate Evidence/mapping/link rows.
6. Verify a scan asset configured in two valid scopes produces two associations to the same Evidence ID. Verify an unconfigured asset remains unassigned and cross-client or unrelated-scope data is excluded.
7. Submit manual evidence and generic collector evidence in a selected scope. Confirm Pending review, visible scoped records and persistent submission feedback. Approve through Consultant Review and inspect all downstream surfaces.
8. Open Control Profiles at 1440px and 1280px. Capture list, selected detail, Requirements, Evidence and return-to-list. Confirm filters/count/table do not overlay detail and selected list state is retained. Check that navigation bars/indicators do not accumulate during repeated reruns.
9. Download a policy as Word and PDF from the real menu. Confirm one immediate browser download per click, correct filename/MIME, readable documents, no second button and no replay after rerender. Test a generation error and recovery.
10. Capture screenshots and computed styles for any remaining sidebar/navigation regression and record actual database IDs/counts for the evidence chain. Only then mark live acceptance complete.
