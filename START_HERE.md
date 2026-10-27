# SecureScope v5.4.9.dev0 — Remediation work in progress

Latest update: [Control Assurance corrections](CONTROL_ASSURANCE_CORRECTIONS.md)
— seeded criteria, scoped evidence, assessment and UX fixes, with validation limits.

Latest continuation: see [the checkpoint report](docs/remediation/CONTINUATION_CHECKPOINT.md).
The build/security gates and new risk-methodology/SoA/nonconformity UI remain unfinished.

This source release adds the ISO assurance workspace, guided control assessment,
audit scheduling, risk registers, toolkit previews/guarded export and UI hardening
to the v5.4.2 Streamlit application.

## Start on Windows

1. Extract the ZIP into a **new folder**.
2. Copy your existing `.env` into that folder. For a fresh installation, copy
   `.env.example` to `.env` and configure PostgreSQL and your engines.
3. Keep the previous installation as your rollback copy. Do **not** copy its
   `.venv`: Windows virtual environments contain paths to their original folder.
4. Open PowerShell in the new extracted folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start_securescope.ps1
```

The launcher uses Python 3.11, creates a fresh virtual environment, installs
`requirements.txt`, sets the package import path, applies pending migrations
and starts the configured workers and Streamlit. Open `http://localhost:8501`.
Use this launcher to avoid a stale `streamlit.exe` pointing to an old folder
or `No module named securescope` from an unconfigured source checkout.

Migration **007_isms_project_plan.sql** adds project tasks and change history.
Existing scanner, evidence and assessment tables are retained. There is no
new runtime dependency; charts use Streamlit's native Vega-Lite support.
Migrations 008 and 009 add the client-scoped audit/risk and working-register
storage used by the new screens. They are normal `.sql` migrations; files
ending in `.disabled` are ignored. Their SQL contents are unchanged from the
previous staged files. No migration was exercised against a live database here.
Preserve your usual database backup before upgrading.

## Open the dashboard

Open the existing **Control Assurance** workspace (the Gap Assessment menu in
installations retaining that sidebar label). **Gap dashboard** is its default
tab, with an 11-area summary, weighted totals, four indicators, radar, count
bars, percentage bars, area/result filters, assessment drilldown and CSV exports.

Counts use the existing catalog: **30 clause entries + 93 Annex A controls =
123 units**. Your spreadsheet uses 47 clause checklist items and 140 total
units. Its detailed checklist was not supplied, so those items are not invented.

Only a validated **Implemented and effective** assessment with current validated
evidence counts as met. Unknown entries remain in scope. Approved, justified
Annex A exclusions are taken from the latest approved SoA. Clauses 4–10 remain
in scope. Partial results, achieved targets and accepted risk remain distinct.
This is an internal assessment metric, not a certification decision.

## Use the project plan

1. Select **Project plan** to see all 30 tasks and the requested columns.
2. Use **Plan the project in one pass**: choose one start date and select
   **Suggest all dates**, keeping existing dates if desired.
3. Review owners, durations and dates together; save changed tasks in one action.
4. Use the individual task editor for detailed changes.
5. Export the plan or inspect its recent changes when needed.

Start date counts as day one. Weekends are skipped; public holidays are not
subtracted. Unplanned tasks have no end date or percentage. Task 15 is a
read-only summary of tasks 16–20, excluded from total effort to avoid counting
work twice. Overall progress is weighted by planned work days; unscheduled tasks
are displayed separately. Date suggestions use task dependencies and editable
estimates; public holidays and team capacity are not modelled.

Changes are saved in PostgreSQL per client. A revision check prevents a stale
browser form overwriting a newer saved version. **Reload saved task** loads the
latest version after a conflict. Drafts and filters are isolated per client.

## Connection settings and toolkit handoff

The Wazuh editor requires an Administrator in the active workspace and a host
identity allowed by `SECURESCOPE_CONNECTOR_ADMINS`. Configure
`SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY` before saving. API and Indexer TLS
verification default on and have independent settings.

If upgrading an installation that already uses encrypted connection settings,
carry `data/wazuh_connection.enc` into the new installation and retain its
matching encryption key. Existing plaintext host configuration is not deleted
automatically; saved passwords are never prefilled into browser fields.

Toolkit uploads can be previewed, but applying them is disabled until your live
schema is reviewed. Follow [the mapping proposal](docs/releases/TOOLKIT_MAPPING_PROPOSAL.md)
to produce a read-only `toolkit_schema.json` report. It also contains the
opportunity-table and reference-storage decisions awaiting approval.

Original-template downloads require a working LibreOffice binary and successful
formula, chart and pivot validation. `SECURESCOPE_SOFFICE_PATH` chooses the
binary. No end-to-end faithful populated workbook was verified here; a host
conversion that drops objects or leaves stale caches is rejected.

## Validation

Validation results belong to the current remediation report and CI run.
No passing test count from an earlier build establishes this build’s readiness.

The cloud browser cannot access the local preview, so visual verification was
not completed. No live Windows/scanner/database upgrade was exercised against
your environment.

## Development

Install `requirements-dev.txt` in a virtual environment, then run:

```powershell
python -m pytest -q
python -m compileall -q src tests
python -m pip check
python -m sphinx -b html docs/api build/docs
```

For database tests, set `SECURESCOPE_TEST_DATABASE_URL` to a dedicated PostgreSQL
test database. Tests create and remove a uniquely named schema; do not use a
production database. See [feature documentation](docs/features/ISO_GAP_DASHBOARD.md).
