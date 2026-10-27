# SecureScope correction pass — 6 October 2026

Status: implementation and automated regression checks completed; live acceptance remains pending. Base revision: de45eb1545f3c7372b39a2f8f56d1e0fd2f88519. The packaged revision is recorded in validation/SOURCE_REVISION.txt.

## Preserved scope

PART I — SURGICAL UI REMOVALS is excluded at the user's request. Programme Attention, Exposure Actionable Risk Triggers, Coverage Gaps and CVSS remain. The canonical Programme Foundation, Risk Management, Policies and Control Assurance ownership boundaries remain. No second evidence, risk, scope, treatment or SoA model was introduced. Removal of the Control Assurance Related Risk Treatments top-level tab belongs to the separately authorized Part F; canonical risk treatments remain intact.

## Changes and principal files

| Area | Change | Principal files under src/securescope unless specified |
| --- | --- | --- |
| A: Nuclei evidence | Canonical evidence retries repair mappings and scope links without creating another evidence record or raw artifact. Persisted collection origin and existing configured-asset memberships determine scope. Unknown relationships remain unassigned. | persistence/evidence_repository.py; persistence/nuclei_persistence.py; evidence/evidence_service.py |
| A: requirements | Version 2 baselines retain the three manual requirements and add technical requirements for A.8.9, A.8.24, A.8.5 and A.8.17. Seed supersession preserves custom requirement identity. Per-asset Pass, Gap and Not Collected results are visible. | grc/requirement_templates.py; grc/assurance_requirements.py; persistence/assurance_workspace_repository.py |
| A: collection | Collect New and Link Existing are separate actions. Provider routes retain client, engagement, scope, control, requirement and configured assets; returning to the originating control is explicit. Generic ingestion rechecks workspace membership. | ui/evidence_collection_context.py; ui/control_workspace.py; ui/evidence_hub_ui.py; ui/dual_engine_ui.py; ui/components_v2/assurance_workbench.js |
| A: repair | Idempotent client-specific CLI repairs historical trusted Nuclei mappings and scope associations; missing records require retained source artifacts. | cli/backfill_nuclei_evidence.py |
| A: freshness | Shared timestamp-based currency, conservative unknown/expired handling, source expiry default 90 days and stricter associated requirement windows. | evidence/freshness.py; persistence/evidence_repository.py; grc/control_implementation.py; grc/assurance_requirements.py |
| B: Wazuh | Bridge existing stored snapshots into canonical evidence. Separate logging, monitoring and clock proof; current workspace authorization and scope context; existing encrypted configuration with Test Connection and Collect actions. | evidence/wazuh_bridge.py; evidence/automated_checks.py; app.py; ui/wazuh_settings_ui.py |
| C: SoA | Justified draft exclusions need not already be approved. Approved SoA exclusions remain strictly guarded. Aggregate validation, upload dialog and approved-SoA-only applicability metrics. | database/migrations/016_soa_draft_justified_exclusions.sql; persistence/grc_repository.py; ui/exposure_management_ui.py; ui/assurance_dashboard.py |
| D–F: assurance | Plan in One Pass is exclusive with Back. Assessment retains one bottom Save Draft and Complete Assessment with existing validation. Human Assessment uses the existing canonical display helper. | ui/gap_dashboard_ui.py; ui/control_assessment_ui.py; ui/assurance_dashboard.py; ui/exposure_management_ui.py |
| G: Audit Scope | Read/edit presentation, sections and persistent save feedback; same fields and persistence. | ui/exposure_management_ui.py |
| H: sidebar | Remove conflicting legacy geometry; sidebar.css owns sizing, 20px icons, full-width links and inset active styling. Stray-caret diagnosis still requires live DOM inspection. | ui/styles/legacy.css; ui/styles/sidebar.css |
| Windows encoding | Launcher sets PYTHONUTF8 before Python starts; component and assessment stylesheet reads explicitly use UTF-8. | start_securescope.ps1; ui/components_v2/{assurance_pages,assurance_plan,assurance_workbench,policy_editor}.py; ui/control_assessment_ui.py |

## Evidence semantics

One canonical evidence record may have multiple proven scope associations. Collection origin is validated against the current persisted requirement and configured assets; existing memberships are resolved from the latest control profiles for each scope. Neither free-text scope names nor an arbitrary default scope are used to guess historical ownership. Excluded controls do not cause associated evidence to disappear.

Exact technical mappings include missing-x-frame-options and cookies-without-httponly to A.8.9, and ssh-weak-algo to A.8.24. TLS-version observations and generic exposed-panel SSL/TLS tags are not automatically treated as equivalent proof. Retained source observations support deterministic reclassification during repair. A clean scanner output alone does not establish every technical requirement as passing. Missing asset configuration produces an actionable message.

Automated technical verification remains distinct from consultant approval. Passing technical evidence does not create a completed human assessment or independently turn final assurance into Implemented. Existing manual/request review paths remain; this pass does not replace request acceptance or grant automatic human approval.

Freshness is computed consistently for requirements, control implementation, Evidence Register/Overview and assessment choices. The strictest relevant recorded age limit is used. Unrelated scopes' criteria do not alter a record's currency in the wider view. Explicit unknown or expired states remain conservative.

Wazuh logging requires an actual alert observation, monitoring uses explicit agent state, and clock proof requires the existing endpoint-command provenance and a known synchronization result. Agent presence alone proves neither logging nor clock synchronization. Stored observations are independent evidence records with trusted technical provenance, not human-approved mappings. Clock evidence can require running the existing clock collection action first. Existing encrypted connection settings are reused.

## Migration and repair

Migration 016 removes the old combined justification/approval check and separates draft justification from approved-version approval requirements. New constraints preserve legacy rows (including historically invalid whitespace-only justification) while enforcing new/changed records. Deferred triggers protect approved SoA items and version transitions. No historical records are copied or deleted. This SQL has not been executed against a live database in this environment.

Back up the target database before deployment. From the project root, using the actual client name:

```powershell
.\.venv\Scripts\python.exe -m securescope.cli.run_migrations
.\.venv\Scripts\python.exe -m securescope.cli.backfill_nuclei_evidence --client "Default Client" --dry-run
.\.venv\Scripts\python.exe -m securescope.cli.backfill_nuclei_evidence --client "Default Client"
```

Dry run does not migrate or write. Repeat execution should create zero additional evidence records. Errors are reported per job and produce a nonzero exit code. Records lacking provable source/scope relationships remain preserved and unassigned; repair does not invent links. Deferred artifact creation avoids an extra raw artifact on a successful idempotent retry, but does not claim cross-filesystem/database atomicity for every failure mode.

## Verification

- Python regression suite: **730 passed, 5 skipped, 78 warnings**. Log: validation/correction_pass_20261005/pytest.txt.
- The five skips require an explicit disposable PostgreSQL test URL; they are not successful database checks.
- Workbench jsdom frontend tests passed, including selection, escaping, navigation, failed-save handling, read-only behavior and policy downloads. Log: frontend.txt.
- Changed Python lint, compilation and whitespace checks passed. Logs: lint.txt and final-checks.txt.
- Regression coverage includes precise mappings, preserved manual baselines, requirement upgrades, per-asset technical results, conservative freshness, independent Wazuh checks, scope associations, idempotent repair, SoA draft/approval semantics, collection context and UTF-8 reads.

Run the real database verification against an explicitly empty disposable database, never a production database:

```powershell
$env:SECURESCOPE_TEST_DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/EMPTY_TEST_DB"
.\.venv\Scripts\python.exe scripts/verify_evidence_scope_postgres.py
.\.venv\Scripts\python.exe -m pytest tests/test_soa_draft_migration_postgres.py
```

The verification script runs migrations fresh and exercises manual evidence isolation plus recorded Nuclei and Wazuh fixtures through actual persistence. scripts/verify_automated_evidence_postgres.py supplies the automated-source checks, four-asset coverage progression, scope isolation and repeated backfill assertions. These scripts were syntax/lint checked but **not executed here**. Recorded fixtures are not a live Wazuh or scanner test.

## Pending live acceptance

No authorized test PostgreSQL URL or live Wazuh endpoint was available. The available Chromium executable exited with signal 11 (exit 139), preventing fresh real-app screenshots, animation inspection and computed-style checks. Prior screenshots are not evidence for this release. No actual Windows launch was performed.

On the real application, verify:

1. Submit manual evidence; confirm persistent success feedback, Current Scope and All Client Evidence visibility, Consultant Review and approved evidence summaries. Confirm approval does not impersonate a completed control assessment.
2. Collect Nuclei evidence from a scoped requirement; inspect origin, numeric asset and all mapped controls, unrelated-scope exclusion and an intentionally shared multi-scope asset. With four configured assets, check coverage after each qualifying asset result; clean output must not pass unsupported checks.
3. Run backfill twice; confirm same canonical IDs and no duplicate artifacts on retry. Unprovable legacy associations must stay unassigned.
4. Test the saved Wazuh connection, collect logging/monitoring, then collect clock evidence. Confirm each proof independently and verify the source timestamp/freshness.
5. Save a justified unapproved SoA exclusion in Draft; reject unjustified exclusions and unapproved exclusions in an Approved version. Verify approved-area metrics and legacy access.
6. Check Plan in One Pass/Back, assessment Save Draft/Complete, upload dialog, Audit Scope read/edit and operation-specific feedback.
7. Inspect sidebar button color AND -webkit-text-fill-color, checkbox/radio/expander/code text, collapsed controls and actual navigation DOM. Check for duplicate bars before diagnosing animation. The stray-caret/animation issue is **not signed off**.
8. Launch using start_securescope.ps1 on Windows without manually setting PYTHONUTF8; revisit Control workspace.

This package is ready for those live acceptance checks, not a claim that every requested live check passed.
