# SecureScope v5.4.3 — UI hardening and ISO assurance

## Changes

- Fixed the eleven reported UI/security defects at source: sidebar/context
  layout, scanner output, Wazuh TLS and credential handling, enrichment states,
  radar margins, table reading and Foundation progress alignment.
- Added shared CSS tokens and escaped card/heading/empty/status/table primitives.
  Existing screen styling migrates incrementally.
- Continued guided control assessment, editable profiles/evidence workflows,
  batch project-date planning, audit scope/schedule and risk registers.
- Replaced unsupported ButtonColumn scan-report actions with direct per-asset
  PDF download icons.
- Added toolkit parsing/preview, formula-injection protection and original XLSX
  input-cell population with strict preservation/recalculation checks.

## Persistence and limits

- Migrations 008/009 are ordinary .sql migrations. Disabled files are ignored.
  SQL contents are unchanged from their previously staged versions.
- Database import application stays disabled pending live-schema verification.
- Scenario/opportunity JSON worksheets are drafts. No new dedicated opportunity
  migration was created. The mapping proposal requests schema/storage decisions.
- Live database/browser/scanner acceptance and faithful native workbook
  recalculation remain unverified. Failed export validation blocks the download.
- Original template risk thresholds differ from the application; the UI explains
  this rather than silently changing template formulas or live Gap scoring.

## Verification

289 tests passed; four explicit PostgreSQL integration tests were skipped.
See validation/VALIDATION_V5_4_3.md for scope and limitations, and
SECURESCOPE_UI_HARDENING_AUDIT.md for bug locations and the frontend tradeoff.
