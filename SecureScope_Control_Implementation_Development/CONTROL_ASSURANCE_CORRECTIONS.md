# Control Assurance correction pass

This update extends the existing Control Profile, assessment, evidence and
canonical risk services. It introduces no parallel persistence model and no
new database migration.

## Requirements and assessment

- All 123 catalog entries have editable SecureScope-authored starter criteria:
  30 management-system entries and 93 Annex A controls.
- A.5.1, A.5.9, A.5.12, A.8.8, A.8.15 and A.8.16 have tailored checks. Other
  entries use contextualized defined-approach, implementation and operating-review
  checks. These are starter assurance criteria, not verbatim ISO requirements or
  an exhaustive interpretation of the standard.
- Baselines are previewed on read and persisted once when an authorized
  Consultant or Administrator opens a scoped Control Workspace/assessment.
  Auditors do not trigger baseline writes. Stable IDs and a template version
  prevent repeated insertion; custom wording and intentional removals survive.
- Review the starter set for the organization and scope, add relevant obligations,
  then confirm it. Configuration and requirement edits use focused dialogs.
- Assessments reuse the configured criteria, stable identities, supporting
  references and saved overrides. A positive conclusion requires completed
  mandatory results, supporting references, rationale and existing authorization
  gates. Save Draft remains separate from Complete Assessment.
- Missing evidence remains distinct from failed implementation. Human conclusions,
  evidence sufficiency and assurance remain separate dimensions.
- Provider verification requires explicit machine-verifiability plus existing
  freshness, scope, validation and source-capability checks. An unreviewed baseline
  cannot enable automatic assurance.

## Workflow and presentation

- Requirements use compact rows with readable states and focused detail actions.
- Control configuration keeps assessment methods, measurement model and evidence
  expectations under Advanced Settings.
- The scoped assurance dashboard uses canonical results, attention filters,
  direct Control Workspace navigation and area summaries. Unassessed/unknown
  states do not imply zero conformity or zero gaps.
- Evidence Register defaults to the selected scope; wider client visibility is
  explicit. Settings and source setup have their own tab and are hidden from the
  auditor tab list. Raw scanner payloads are excluded from metadata list reads.
- Control-to-Evidence navigation retains the control filter and resets the view
  to the current scope. Policy creation opens canonical Policies.
- Risk scope selection is compact. Empty scoped views expose unassigned risks;
  new scenarios preselect the current scope without assigning historical risks.
- Missing SoA justifications are visible beside the editable rows. Applicability
  remains a human decision.
- Audit Scope opens in read mode; Edit Audit Scope and Use Current ISMS Scope
  prefill the separate audit boundary without changing formal Scope records.
- Project-plan summaries expose owner, dates, progress and status while retaining
  existing scheduling and export behavior.
- The unsupported populated-toolkit download action is removed. Other existing
  workbook exports remain available without requiring LibreOffice for this pass.
- Formal Risk Acceptance and configurable Methodology remain Coming Soon.

## Persistence and compatibility

Previous profiles, assessments, policies, evidence, scope versions and risks are
retained. A newly versioned profile may require a new target/assessment review;
historical assessments are not silently copied into another scope. Legacy
unassigned assessments cannot certify the selected scope's assurance result.

Baseline changes create versions through the existing profile service and its
optimistic concurrency guard. Future template upgrades must use an explicit
reviewed upgrade path; this pass deliberately does not overwrite seeded versions.

## Validation

- Python suite: 611 passed, 4 skipped.
- Frontend DOM suite: 38 passed.
- Changed Python code passes flake8 and Black checks.
- Focused coverage includes seeding/idempotence, custom edits, deletion preservation,
  machine-verification opt-in, stable assessment references, authorized manual
  results, scope isolation, risk defaults, modal saving, dashboard empty states,
  evidence filtering and audit-scope copying.
- Four PostgreSQL integration tests require SECURESCOPE_TEST_DATABASE_URL and were
  skipped. No live PostgreSQL migration/persistence or visual browser validation
  was performed for this pass. This remains a development/evaluation build.

The validation directory includes test logs. SOURCE_REVISION.txt identifies the
source commit used for this package.
